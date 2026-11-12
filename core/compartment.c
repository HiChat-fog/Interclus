/* compartment.c: time-multiplexed PMP compartments driven by the VRT
 * engine (core/pmp/). Each compartment owns one icp_state whose region
 * table is the authority; the two hot rows are pinned into entry0/1 at
 * arm, entry2 stays the on-demand slot, entry3 stays deny-all. A faulting
 * compartment is evicted: the trap path saves its frame into the TCB and
 * wipes the register file, the supervisor marks it dead here, and the
 * schedule moves on without it (Tock-style, no collateral). */

#include <stdint.h>
#include "compartment.h"
#include "pmp/icp.h"

#define COMP_COUNT 4u

struct compartment {
    ic_compartment_spec spec;
    uint32_t entry;
    uint32_t armed;
    uint32_t evicted;
    uint32_t tcb[32];
};

/* the drills and the trap path hand-compute these offsets; a field move
 * must break the build, not the evidence */
_Static_assert(sizeof(struct compartment) == 156u, "compartment layout drifted");
_Static_assert(sizeof(struct compartment) == sizeof(ic_compartment_spec)
               + 3u * 4u + 32u * 4u, "tcb sits at word 7");

static struct compartment comps[COMP_COUNT]
    __attribute__((section(".comp_state"), aligned(8), used));

static icp_state dom[IC_DOM_MAX]
    __attribute__((section(".pmp_state"), aligned(8), used));

volatile uint32_t cur_tcb;      /* TCB of the running compartment, for ecall */
volatile uint32_t cur_comp;     /* forensics attribution */

void compartment_set(unsigned i, const ic_compartment_spec *spec,
                     uint32_t entry) {
    icp_state *d;
    if (i >= COMP_COUNT) return;
    d = &dom[i];
    icp_init(d);
    icp_mount(d, spec->sram_base, spec->sram_size, ICP_R | ICP_W);
    icp_mount(d, spec->text_base, spec->text_size, ICP_R | ICP_X);
    comps[i].spec = *spec;
    comps[i].entry = entry;
    comps[i].armed = 0u;        /* instantiation invalidates prior arming */
    comps[i].evicted = 0u;
    for (unsigned j = 0; j < 32u; j++) comps[i].tcb[j] = 0u;
}

/* extra VRT rows between set and arm: the region lands as an overflow row
 * and the fill path swaps it in on first use */
void compartment_extend(unsigned i, uint32_t base, uint32_t size,
                        uint32_t perms) {
    if (i >= COMP_COUNT) return;
    icp_mount(&dom[i], base, size, perms);
}

void compartment_set_arg(unsigned i, uint32_t sp, uint32_t a0) {
    if (i >= COMP_COUNT) return;
    comps[i].tcb[2] = sp;
    comps[i].tcb[10] = a0;
}

void compartment_arm(unsigned i) {
    if (i >= COMP_COUNT || comps[i].armed) return;
    icp_lock(&dom[i]);
    icp_arm(&dom[i]);
    for (unsigned j = 0; j < COMP_COUNT; j++) comps[j].armed = 0u;
    comps[i].armed = 1u;
}

/* Terminate the running lifetime: keep the TCB frame the trap path saved
 * (it is the evidence), mark the slot dead, and drop every armed bit —
 * nothing about this compartment may look live afterwards. */
void compartment_evict(unsigned i) {
    if (i >= COMP_COUNT) return;
    comps[i].evicted = 1u;
    comps[i].armed = 0u;
}

unsigned compartment_evicted(unsigned i) {
    return (i < COMP_COUNT) ? comps[i].evicted : 1u;
}

unsigned compartment_swaps(unsigned i) {
    return (i < COMP_COUNT) ? dom[i].swaps : 0u;
}

/* Enter compartment i: restore its TCB into the register file (zeros on
 * first entry — the register-cleanup convention), arm its PMP pair, and
 * mret into text_base+entry. Never returns; the caller's C state is
 * abandoned exactly as it was with the previous enter. Entering an
 * evicted compartment parks the core: the supervisor must not do it. */
__attribute__((noreturn))
void compartment_enter(unsigned i) {
    while (comps[i].evicted) { __asm__ volatile ("wfi"); }
    compartment_arm(i);
    cur_comp = i;
    cur_tcb = (uint32_t)&comps[i].tcb;
    register uint32_t tcb asm("t0") = (uint32_t)&comps[i].tcb;
    register uint32_t target asm("a1") =
        comps[i].spec.text_base + comps[i].entry;
    __asm__ volatile (
        "csrw mepc, %1\n"
        "csrr t1, mstatus\n"
        "li   t2, 0x21800\n"          /* MPP | MPRV */
        "not  t2, t2\n"
        "and  t1, t1, t2\n"
        "ori  t1, t1, 0x80\n"         /* MPIE: budget IRQ live in U-mode */
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
