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
#define MIR_BASE   (FLASH_TOP - 0x800u)  /* slot0 @ -0x800, slot1 @ -0x400 */
#define MIR_SLOT0  (MIR_BASE)
#define MIR_SLOT1  (MIR_BASE + 0x400u)
#define MIR_MAGIC  0x4D495234u   /* "MIR4" */

#ifndef QEMU_TARGET

#define FMC_KEYR    (*(volatile uint32_t *)0x40022004u)
#define FMC_MODEKEYR (*(volatile uint32_t *)0x40022008u)
#define FMC_CTLR    (*(volatile uint32_t *)0x40022010u)
#define FMC_ADDR    (*(volatile uint32_t *)0x40022014u)
#define FMC_STATR   (*(volatile uint32_t *)0x4002200Cu)
#define FMC_PAGE_PG (1u << 3)   /* 256-byte page program, CH32V307 FMC */
#define FMC_BUF_LOAD (1u << 4)  /* buffer load */
#define FMC_WPE     (1u << 15)
#define FMC_BUSY    (1u << 0)
#define FMC_WR_ERR  (1u << 2)
#define FMC_EOP     (1u << 5)
#define FMC_CTLR_PER (1u << 1)
#define FMC_CTLR_MER (1u << 2)
#define FMC_CTLR_START (1u << 6)
#define FMC_CTLR_LOCK (1u << 7)
#define FMC_PAGE_256 256u

static int fmc_wait(void) {
    uint32_t guard = 2000000u;
    while ((FMC_STATR & FMC_BUSY) && --guard) { }
    return guard ? 0 : -1;
}

static void unlock(void) {
    if (!(FMC_CTLR & FMC_CTLR_LOCK)) return;
    FMC_KEYR = 0x45670123u;
    FMC_KEYR = 0xCDEF89ABu;
    FMC_MODEKEYR = 0x45670123u;
    FMC_MODEKEYR = 0xCDEF89ABu;
}

static void lock(void) {
    FMC_CTLR |= FMC_CTLR_LOCK;
}

static int erase_page(uint32_t addr) {
    unlock();
    FMC_CTLR |= FMC_CTLR_PER;
    FMC_ADDR = addr;
    FMC_CTLR |= FMC_CTLR_START;
    {
        int rc = fmc_wait();
        FMC_CTLR &= ~FMC_CTLR_PER;
        lock();
        return rc;
    }
}

static int program_page(uint32_t addr, const uint32_t *words, uint32_t n) {
    unlock();
    /* page mode: load 64 words into the buffer, then one start writes
     * the whole 256-byte page */
    FMC_CTLR |= FMC_PAGE_PG;
    FMC_ADDR = addr;
    for (uint32_t i = 0; i < n; i++) {
        *(volatile uint32_t *)(addr + 4u * i) = words[i];
        FMC_CTLR |= FMC_BUF_LOAD;
    }
    FMC_CTLR |= FMC_CTLR_START;
    {
        int rc = fmc_wait();
        FMC_CTLR &= ~(FMC_PAGE_PG | FMC_BUF_LOAD);
        lock();
        return rc;
    }
}

#else

/* RAM-backed stand-in for the two mirror pages; tests poke it directly */
uint32_t mir_ram[0x800u / 4u] __attribute__((section(".mir_ram")));

#endif

/* header of one mirror page: magic, slot index, len, entry, then code */
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
    if (erase_page(base)) return -2;
    if (program_page(base, page, 64u)) return -3;
    {   /* verify through the CPU view: the controller may lie */
        const volatile uint32_t *v = (const volatile uint32_t *)base;
        for (uint32_t i = 0; i < 4u; i++)
            if (v[i] != page[i]) return -4;
    }
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
