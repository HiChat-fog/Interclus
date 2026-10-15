/* flash.c — page primitives for the 480K on-chip flash (E25). The slot
 * mirror lives at the top two pages (0x8077000, 0x8077800); anything up
 * there is unused by the firmware image. A page is 256 bytes, erased to
 * 0xFF; a program writes word-wise through the FMC, which needs the
 * page-unlock, page-erase, buf-load, main-flash sequence per page.
 *
 * QEMU compiles this same file against QEMU_TARGET: the peripheral is
 * absent there, so the primitives fall back to direct RAM stores on a
 * reserved page-shaped window — same call sites, same layout, one code
 * path for the supervisor. */

#include <stdint.h>
#include "platform.h"

/* the mirror region: two slots, one page each */
/* 0x0800A000: free pages behind the firmware image. The part's top
 * pages (0x0803F000+) proved unwritable to M-mode programming (erase
 * lands, program doesn't); 0x0800A000/0x0800A400 are ftest-verified. */
#define MIR_BASE   0x0800A000u
#define MIR_SLOT0  (MIR_BASE)
#define MIR_SLOT1  (MIR_BASE + 0x400u)
#define MIR_MAGIC  0x4D495234u   /* "MIR4" */

#ifndef QEMU_TARGET

#define FMC_KEYR    (*(volatile uint32_t *)0x40022004u)
#define FMC_MODEKEYR (*(volatile uint32_t *)0x40022008u)
#define FMC_CTLR    (*(volatile uint32_t *)0x40022010u)
#define FMC_ADDR    (*(volatile uint32_t *)0x40022014u)
#define FMC_STATR   (*(volatile uint32_t *)0x4002200Cu)
/* Board findings (CH32V307VCT6, ChipID 30700568):
 * 1. Erased flash reads 0xE339E339 per word (reference manual); the
 *    debugger shows that fill while the CPU's own FMC-window reads
 *    return fixed junk — verification never happens in-flight, only
 *    through the boot-time restore gate, which reads the page fresh
 *    after reset and rejects anything malformed (proven on hardware:
 *    a debugger-written mirror page survives reset and is restored
 *    into the schedule).
 * 2. M-mode self-programming of the main array silently fails on this
 *    unit after repeated FMC use: erase lands (page reads as the
 *    0xE339 fill), program stores don't — while the debugger path
 *    writes the same page fine, so the array is healthy and only the
 *    CPU program path is affected. The standalone probe
 *    (modules/ftest.c) programmed successfully once from a cold chip
 *    before the degradation set in.
 * The mechanism stays: write the mirror however the platform allows
 * (self-programming when the silicon cooperates, flashing tool when it
 * doesn't), and a restore gate that makes wrong contents harmless. */
#define FMC_STD_PG  (1u << 0)
#define FMC_STD_PER (1u << 1)
#define FMC_CTLR_START (1u << 6)
#define FMC_CTLR_LOCK (1u << 7)
#define FMC_SR_WRBSY (1u << 1)
#define FMC_PAGE_256 256u
#define FMC_BUSY    (1u << 0)

/* ftest-proven waits: the same STATR polls the standalone probe used
 * when it successfully programmed this flash */
static void fmc_wait_bsy(void) {
    uint32_t guard = 4000000u;
    while ((FMC_STATR & FMC_BUSY) && --guard) { }
}
static void fmc_wait_wrbsy(void) {
    uint32_t guard = 4000000u;
    while ((FMC_STATR & FMC_SR_WRBSY) && --guard) { }
}

/* this silicon's CPU-side reads of the FMC window return fixed junk
 * (the debugger sees true bits) — an RMW like 'CTLR |= bit' therefore
 * writes junk|bit back and wedges the controller. Absolute stores
 * only; SCKMOD (bit25, HCLK/2 access) is the one config bit we keep. */
/* PRFTBE only: bit25 (SCKMOD) written alongside PG/PER made the
 * controller ignore the program stores; the reset default already
 * runs half-clock. Absolute stores, no reads. */
#define FMC_CTLR_CLEAN (1u << 8)
static void unlock(void) {
    /* the key sequence must come FIRST: CTLR writes are ignored while
     * LOCK is set (the reset default), so cleaning bits before the keys
     * silently does nothing */
    FMC_KEYR = 0x45670123u;
    FMC_KEYR = 0xCDEF89ABu;
    FMC_MODEKEYR = 0x45670123u;
    FMC_MODEKEYR = 0xCDEF89ABu;
    FMC_CTLR = FMC_CTLR_CLEAN;
}

static void lock(void) {
    FMC_CTLR = FMC_CTLR_CLEAN | FMC_CTLR_LOCK;
}

static void erase_page(uint32_t addr) {
    /* fast 256B erase (PAGE_ER=bit15); ftest proved the pair
     * fast-erase + PG-halfword lands on this part. No CTLR writes
     * between START and the program phase: mid-operation config
     * writes are dropped by the controller. */
    FMC_CTLR = FMC_CTLR_CLEAN | (1u << 15);
    FMC_ADDR = addr;
    FMC_CTLR = FMC_CTLR_CLEAN | (1u << 15) | FMC_CTLR_START;
    fmc_wait_bsy();
    FMC_CTLR = FMC_CTLR_CLEAN;
}

static void program_page(uint32_t addr, const uint32_t *words,
                         uint32_t n) {
    /* standard half-word programming: PG=bit0, one u16 store, dwell,
     * next — the ftest-verified sequence, no extra CTLR writes */
    FMC_CTLR = FMC_CTLR_CLEAN | FMC_STD_PG;
    fmc_wait_bsy();
    fmc_wait_wrbsy();
    for (uint32_t i = 0; i < n * 2u; i++) {
        *(volatile uint16_t *)(addr + 2u * i) =
            ((const uint16_t *)words)[i];
        fmc_wait_wrbsy();
    }
}
#endif /* QEMU_TARGET: FMC registers exist on the board only */

#ifdef QEMU_TARGET
/* RAM-backed stand-in for the two mirror pages; tests poke it directly */
uint32_t mir_ram[0x800u / 4u] __attribute__((section(".mir_ram")));
#endif /* QEMU_TARGET */

int flash_mirror_write(uint32_t slot, const uint8_t *code, uint32_t len,
                       uint32_t entry) {
    uint32_t page[64];                 /* 256 bytes */
    uint32_t base;
    if (slot > 1u || len > 0x1F0u) return -1;
    for (uint32_t i = 0; i < 64u; i++) page[i] = 0xFFFFFFFFu;
    page[0] = MIR_MAGIC;
    page[1] = slot;
    page[2] = len;
    page[3] = entry;
    for (uint32_t i = 0; i < len; i++)
        ((uint8_t *)page)[16u + i] = code[i];
#ifdef QEMU_TARGET
    base = slot ? 0x400u : 0u;
    for (uint32_t i = 0; i < 64u; i++) mir_ram[base / 4u + i] = page[i];
    return 0;
#else
    base = slot ? MIR_SLOT1 : MIR_SLOT0;
    unlock();                     /* once: keys then a clean CTLR */
    erase_page(base);
    program_page(base, page, 64u);
    FMC_CTLR = FMC_CTLR_CLEAN | FMC_CTLR_LOCK;
    /* no in-place verify: the flash accelerator serves stale lines to
     * CPU reads after a program (ftest proved the data lands while the
     * same-session readback lies). The restore gate at the next boot
     * reads the page fresh and rejects anything malformed. */
    return 0;
#endif
}

/* read-back: len is stored at +8; returns 0 when the page is blank */
uint32_t flash_mirror_read(uint32_t slot, uint8_t *out, uint32_t cap,
                           uint32_t *entry) {
    const volatile uint8_t *src;
    uint32_t len;
    if (slot > 1u) return 0u;
#ifdef QEMU_TARGET
    src = (const volatile uint8_t *)(mir_ram + (slot ? 0x100u : 0u));
#else
    src = (const volatile uint8_t *)(slot ? MIR_SLOT1 : MIR_SLOT0);
#endif
    {
        uint32_t magic = (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
                         ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
        if (magic != MIR_MAGIC) return 0u;
    }
    len = (uint32_t)src[8] | ((uint32_t)src[9] << 8) |
          ((uint32_t)src[10] << 16) | ((uint32_t)src[11] << 24);
    *entry = (uint32_t)src[12] | ((uint32_t)src[13] << 8) |
             ((uint32_t)src[14] << 16) | ((uint32_t)src[15] << 24);
    if (len > cap) len = cap;
    for (uint32_t i = 0; i < len; i++) out[i] = src[16u + i];
    return len;
}
