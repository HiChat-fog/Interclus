/* compartment.c: time-multiplexed PMP compartments. One NAPOT pair
 * (entry0 = SRAM, entry1 = text) is re-armed per switch; entry3 stays the
 * static deny-all filler. Re-arming the same compartment is skipped. */

#include <stdint.h>
#include "compartment.h"
#include "platform.h"

#define COMP_COUNT 4u

struct compartment {
    ic_compartment_spec spec;
    uint32_t entry;
    uint32_t armed;
    uint32_t tcb[32];
};

static struct compartment comps[COMP_COUNT]
    __attribute__((section(".comp_state"), aligned(8), used));

volatile uint32_t cur_tcb;      /* TCB of the running compartment, for ecall */
volatile uint32_t cur_comp;     /* forensics attribution */

static void csr_set(unsigned csr, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n" (csr), "r" (v) : "memory");
}

void compartment_set(unsigned i, const ic_compartment_spec *spec,
                     uint32_t entry) {
    if (i >= COMP_COUNT) return;
    comps[i].spec = *spec;
    comps[i].entry = entry;
}

void compartment_arm(unsigned i) {
    if (i >= COMP_COUNT || comps[i].armed) return;
    uint32_t cfgw = 0x1Bu | (0x1Du << 8) | (0x00u << 16) | (0x18u << 24);
    csr_set(0x3a0, 0u);
    csr_set(0x3b0, NAPOT(comps[i].spec.sram_base, comps[i].spec.sram_size));
    csr_set(0x3b1, NAPOT(comps[i].spec.text_base, comps[i].spec.text_size));
    csr_set(0x3b2, 0u);
    csr_set(0x3b3, PMP_DENY);
    csr_set(0x3a0, cfgw);
    for (unsigned j = 0; j < COMP_COUNT; j++) comps[j].armed = 0u;
    comps[i].armed = 1u;
}

/* Enter compartment i: restore its TCB into the register file (zeros on
 * first entry — the register-cleanup convention), arm its PMP pair, and
 * mret into text_base+entry. Never returns; the caller's C state is
 * abandoned exactly as it was with the previous enter. */
__attribute__((noreturn))
void compartment_enter(unsigned i) {
    compartment_arm(i);
    cur_comp = i;
    register uint32_t tcb asm("t0") = (uint32_t)&comps[i].tcb;
    register uint32_t target asm("a1") =
        comps[i].spec.text_base + comps[i].entry;
    __asm__ volatile (
        "csrw mepc, %1\n"
        "csrr t1, mstatus\n"
        "li   t2, 0x21800\n"          /* MPP | MPRV */
        "not  t2, t2\n"
        "and  t1, t1, t2\n"
        "csrw mstatus, t1\n"
        "lw   ra, 4(t0)\n"
        "lw   gp, 12(t0)\n"
        "lw   tp, 16(t0)\n"
        "lw   t1, 24(t0)\n"
        "lw   t2, 28(t0)\n"
        "lw   sp, 8(t0)\n"            /* 0 on first entry; entry code sets it */
        "lw   s0, 32(t0)\n"
        "lw   s1, 36(t0)\n"
        "lw   a0, 40(t0)\n"
        "lw   a1, 44(t0)\n"
        "lw   a2, 48(t0)\n"
        "lw   a3, 52(t0)\n"
        "lw   a4, 56(t0)\n"
        "lw   a5, 60(t0)\n"
        "lw   a6, 64(t0)\n"
        "lw   a7, 68(t0)\n"
        "lw   s2, 72(t0)\n"
        "lw   s3, 76(t0)\n"
        "lw   s4, 80(t0)\n"
        "lw   s5, 84(t0)\n"
        "lw   s6, 88(t0)\n"
        "lw   s7, 92(t0)\n"
        "lw   s8, 96(t0)\n"
        "lw   s9, 100(t0)\n"
        "lw   s10, 104(t0)\n"
        "lw   s11, 108(t0)\n"
        "lw   t3, 112(t0)\n"
        "lw   t4, 116(t0)\n"
        "lw   t5, 120(t0)\n"
        "lw   t6, 124(t0)\n"
        "lw   t0, 20(t0)\n"
        "mret\n"
        :: "r" (tcb), "r" (target) : "memory");
    __builtin_unreachable();
}
