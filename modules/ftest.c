/* ftest — minimal board-side FMC ground-truth probe (E25 diagnosis).
 * Standalone firmware: unlock, fast-erase one 256B page at 0x0800A000,
 * fast-program a known pattern, markers into the STATUS window at every
 * stage. No CPU-side verification: the debugger reads back the page.
 * Stage codes in STATUS[100]: 1=entered, 2=unlocked, 3=erased,
 * 4=programmed, 0xEE=stuck (also mirrors the first two STATR reads to
 * STATUS[101..102] so the debugger sees them even if a poll hangs). */

#include <stdint.h>

#define FMC_STATR   (*(volatile uint32_t *)0x4002200Cu)
#define FMC_CTLR    (*(volatile uint32_t *)0x40022010u)
#define FMC_ADDR    (*(volatile uint32_t *)0x40022014u)
#define FMC_KEYR    (*(volatile uint32_t *)0x40022004u)
#define FMC_MODEKEYR (*(volatile uint32_t *)0x40022008u)
#define FMC_PAGE_ER  (1u << 15)
#define FMC_PAGE_PG  (1u << 16)
#define FMC_PG_STRT  (1u << 21)
#define SR_BSY       (1u << 0)
#define SR_WR_BSY    (1u << 1)

#define STATUS      ((volatile uint32_t *)0x20000100u)
#define TEST_PAGE   0x0800A000u

#define STAGE   ((volatile uint32_t *)0x20000290u)
#define STATR1  ((volatile uint32_t *)0x20000294u)
#define STATR2  ((volatile uint32_t *)0x20000298u)
/* fixed RAM slots above .bss; no startup zeroing needed — the firmware
 * writes them before reading anything back */

static void poll_bsy(void) {
    uint32_t guard = 4000000u;
    while ((FMC_STATR & SR_BSY) && --guard) { }
    if (!guard) *STAGE = 0xEE;
}

__attribute__((section(".init")))
void ftest_main(void) {
    volatile uint32_t buf[64];
    *STAGE = 1;
    for (uint32_t i = 0; i < 64u; i++)
        buf[i] = 0xA5A50000u | i;

    FMC_KEYR = 0x45670123u;
    FMC_KEYR = 0xCDEF89ABu;
    FMC_MODEKEYR = 0x45670123u;
    FMC_MODEKEYR = 0xCDEF89ABu;
    FMC_CTLR = 0x12345678u;    /* freshness probe: dbg must see this */
    *STAGE = 2;

    /* fast erase: PAGE_ER, ADDR, STRT, poll BSY */
    *STATR1 = FMC_STATR;
    FMC_CTLR |= FMC_PAGE_ER;
    FMC_ADDR = TEST_PAGE;
    FMC_CTLR |= (1u << 6);
    poll_bsy();
    if (*STAGE == 0xEE) for (;;) { }
    FMC_CTLR &= ~FMC_PAGE_ER;
    *STAGE = 3;

    /* standard half-word programming: PG=bit0, one u16 store per poll */
    *STATR2 = FMC_STATR;
    FMC_CTLR |= 1u;
    for (uint32_t i = 0; i < 128u; i++) {
        *(volatile uint16_t *)(TEST_PAGE + 2u * i) = (uint16_t)i;
        poll_bsy();          /* official: wait EOP after EVERY halfword */
        while (FMC_STATR & SR_WR_BSY) { }
    }
    if (*STAGE == 0xEE) for (;;) { }
    FMC_CTLR &= ~1u;
    *STAGE = 4;

    for (;;) { }
}

__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, 0x20004\n"
    "  addi sp, sp, -256\n"
    "  j    ftest_main\n"
);
