/* measure.c: standalone cycle-cost firmware (dual target). Measures the
 * PMP re-arm vs armed-skip cost, the full time-slice switch (same- and
 * cross-compartment), the fault-eviction round trip, and the
 * ic_program_check preflight slope. Shares trap.S/compartment.c/loader.c/
 * uart.c with the production image; UART printout plus a pinned result
 * array for wlink dump read-back. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/contract.h"
#include "../core/compartment.h"
#include "../core/loader.h"
#include "../core/ebpf_asm.h"

void uart_init(void);
void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void uart_puthex(uint32_t v);

extern void trap_entry(void);
extern uint32_t trap_sp0_top[];      /* scratch end (linker symbol) */

/* trap.S contract: fault forensics + the two supervisor resume points */
volatile uint32_t g_ri_index;
volatile uint32_t g_ri_cause[8];
volatile uint32_t g_ri_addr[8];

enum {
    R_OVH, R_ARMF0, R_ARMS0, R_ARMF1, R_ARMS1,
    R_CHK8, R_CHK16, R_CHK32, R_CHK64,
    R_SL_SAME, R_SL_CROSS, R_SL_EVICT,
    R_SAN_RD, R_SAN_MC, R_SAN_STK, R_CNT
};
static const char *const names[R_CNT] = {
    "cyc_overhead", "pmp_arm_full_0", "pmp_arm_skip_0",
    "pmp_arm_full_1", "pmp_arm_skip_1",
    "check_n8", "check_n16", "check_n32", "check_n64",
    "slice_same", "slice_cross", "slice_evict",
    "sanity_rdcycle50k", "sanity_mcycle50k", "sanity_stk50k",
};

__attribute__((section(".meas_res"), used))
static volatile uint32_t res[R_CNT];

/* counter source, picked at boot: 0 rdcycle, 1 csrr mcycle, 2 TIMER_NOW.
 * QingKe cores have been seen with a dead rdcycle mapping; the sanity
 * chain below falls through until one of the three actually ticks. */
static uint32_t cmode;

static inline uint32_t cyc(void) {
    uint32_t t;
    switch (cmode) {
    case 2:  t = TIMER_NOW(); break;
    case 1:  __asm__ volatile ("csrr %0, 0xB00" : "=r"(t)); break;
    default: __asm__ volatile ("rdcycle %0" : "=r"(t)); break;
    }
    return t;
}

static void dump(void) {
    uart_puts("\n== measure (cycles) ==\n");
    for (unsigned i = 0; i < R_CNT; i++) {
        uart_puts(names[i]);
        uart_puts("=");
        uart_putdec(res[i]);
        uart_puts("\n");
    }
}

static void park(void) {
#ifdef QEMU_TARGET
    *(volatile uint32_t *)0x100000u = 0x5555u;   /* virt test device: pass */
#endif
    for (;;) __asm__ volatile ("wfi");
}

static uint32_t t_enter;
static unsigned g_step;
static unsigned nxt;                 /* compartment scheduled for the slice */
static const ic_compartment_spec spec0 = { NAT_TEXT, 4096u, NAT_SRAM, 4096u };

/* Slice protocol (both comps share identical specs, so a cross switch
 * pays exactly the cross-compartment re-arm cost; enter() arms):
 *   s1  0->0 ecall module, armed-skip      s2  0->1 ecall module, full re-arm
 *   s3  0   fault module  -> first fault evicts, resume at supervisor_fault */
void supervisor_resume(void) {
    uint32_t back = cyc();
    if (g_step == 1) res[R_SL_SAME] = back - t_enter;
    if (g_step == 2) res[R_SL_CROSS] = back - t_enter;
    g_step++;
    if (g_step == 2) nxt = 1u;
    if (g_step >= 3) {
        volatile uint32_t *m = (volatile uint32_t *)NAT_TEXT;
        m[0] = 0x00000297u;      /* auipc t0, 0 */
        m[1] = 0x10028067u;      /* jalr x0, 0x1000(t0) -> NAT_SRAM (no X) */
        compartment_set(0u, &spec0, 0u);   /* fresh lifetime for the fault */
        nxt = 0u;
    }
    t_enter = cyc();
    compartment_enter(nxt);
}

void supervisor_fault(uint32_t yuanyin, uint32_t zhi) {
    (void)yuanyin; (void)zhi;
    res[R_SL_EVICT] = cyc() - t_enter;
    compartment_evict(cur_comp);
    dump();
    park();
}

void boot_main(void) {
    res[R_OVH] = 0xDEADBEEFu;       /* reach marker: survives if we hang */
    TIMER_INIT();

    /* sanity: 50k no-op rounds per counter source; pick one that ticks */
    uint32_t a;
    cmode = 0; a = cyc();
    for (volatile unsigned i = 0; i < 50000u; i++) { }
    res[R_SAN_RD] = cyc() - a;
    cmode = 1; a = cyc();
    for (volatile unsigned i = 0; i < 50000u; i++) { }
    res[R_SAN_MC] = cyc() - a;
    cmode = 2; a = cyc();
    for (volatile unsigned i = 0; i < 50000u; i++) { }
    res[R_SAN_STK] = cyc() - a;
    cmode = (res[R_SAN_RD] >= 30000u) ? 0u
          : (res[R_SAN_MC] >= 30000u) ? 1u : 2u;

    uart_init();
    __asm__ volatile ("csrw mtvec, %0" :: "r" (trap_entry));
    __asm__ volatile ("csrw mscratch, %0" :: "r" (trap_sp0_top));
    uint32_t t0, t1;
    t0 = cyc(); t1 = cyc();
    res[R_OVH] = t1 - t0;

    static const ic_compartment_spec spec1 = spec0;
    *(volatile uint32_t *)NAT_TEXT = 0x00000073u;   /* the module: ecall */
    compartment_set(0u, &spec0, 0u);
    compartment_set(1u, &spec1, 0u);
    t0 = cyc(); compartment_arm(0); t1 = cyc(); res[R_ARMF0] = t1 - t0;
    t0 = cyc(); compartment_arm(0); t1 = cyc(); res[R_ARMS0] = t1 - t0;
    t0 = cyc(); compartment_arm(1); t1 = cyc(); res[R_ARMF1] = t1 - t0;
    t0 = cyc(); compartment_arm(1); t1 = cyc(); res[R_ARMS1] = t1 - t0;

    static uint64_t prog[64];
    static const uint32_t sizes[4] = { 8, 16, 32, 64 };
    for (unsigned s = 0; s < 4; s++) {
        uint32_t n = sizes[s];
        for (uint32_t i = 0; i + 1 < n; i++)
            prog[i] = MOV64I(1u + (i % 10u), i);
        prog[n - 1] = EXIT();
        (void)ic_program_check(prog, n);            /* prime */
        t0 = cyc(); (void)ic_program_check(prog, n); t1 = cyc();
        res[R_CHK8 + s] = t1 - t0;
    }

    uart_puts("== measure ==\n");
    compartment_arm(0);             /* untimed; s1's enter() then skips */
    g_step = 1;
    nxt = 0u;
    t_enter = cyc();
    compartment_enter(nxt);
}

#ifdef QEMU_TARGET
__asm__(
    ".section .text.startup\n"      /* QEMU -bios none jumps to 0x80000000 */
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot_main\n"
);
#endif
