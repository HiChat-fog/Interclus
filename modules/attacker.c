/* Attacker probe (U-mode), contract v1.1: one vector per lifetime. A
 * vector either yields (ecall) or dies on its first fault (evicted);
 * the supervisor schedules the next lifetime either way. -O0 matches
 * the shipped image. Vector targets come from the unit context. */

#include <stdint.h>
#include "../core/unit.h"

/* one stub per lifetime: the host already installed sp and the context
 * pointer; the vector runs from a0. The stubs emit into .text ahead of
 * the vec functions (file order), so attacker_entry sits at the region
 * start — entry_offset 0, same convention as the native demo blob. */
#define VEC(sym, fn) \
    asm(".section .text\n" \
        ".globl " #sym "\n" \
        ".align 2\n" \
        #sym ":\n" \
        "  lui  t0, %hi(" #fn ")\n" \
        "  addi t0, t0, %lo(" #fn ")\n" \
        "  jalr t0\n" \
        "1: wfi\n" \
        "  j 1b\n")

void vec_own(const ic_unit_ctx *c);
void vec_st_res(const ic_unit_ctx *c);
void vec_st_in(const ic_unit_ctx *c);
void vec_ld_res(const ic_unit_ctx *c);
void vec_spv(const ic_unit_ctx *c);
void vec_jmp(const ic_unit_ctx *c);
void vec_proof(const ic_unit_ctx *c);

VEC(attacker_entry, vec_own);
VEC(attacker_v1, vec_st_res);
VEC(attacker_v2, vec_st_in);
VEC(attacker_v3, vec_ld_res);
VEC(attacker_v4, vec_spv);
VEC(attacker_v5, vec_jmp);
VEC(attacker_v6, vec_proof);

void vec_own(const ic_unit_ctx *c) {
    *c->own = 0xBEEF5EEDu;       /* own region: grant must let it land */
    ic_unit_yield();
}

void vec_st_res(const ic_unit_ctx *c) {
    *(volatile uint32_t *)c->mon_results = 0x77777777u;  /* OOB store */
}

void vec_st_in(const ic_unit_ctx *c) {
    *(volatile uint32_t *)c->mon_input = 0x88888888u;    /* OOB store */
}

void vec_ld_res(const ic_unit_ctx *c) {
    volatile uint32_t v = *(volatile uint32_t *)c->mon_results;  /* OOB load */
    (void)v;
}

/* sp-vector: poison sp at the screening verdict slots, mark the live
 * registers, then fault. This lifetime ends at the fault. */
void vec_spv(const ic_unit_ctx *c) {
    register uint32_t poison = c->sp_poison;
    register uint32_t bad = c->mon_flash;
    __asm__ volatile (
        ".option push\n.option norvc\n"
        "li   a0, 0xDEADBEEF\n"
        "li   a1, 0xC0DE0001\n"
        "li   t0, 0xC0DE0002\n"
        "li   t1, 0xC0DE0003\n"
        "li   t2, 0xC0DE0004\n"
        "li   t3, 0xC0DE0005\n"
        "li   t4, 0xC0DE0006\n"
        "li   t5, 0xC0DE0007\n"
        "li   t6, 0xC0DE0008\n"
        "mv   sp, %0\n"
        "lw   t0, 0(%1)\n"          /* OOB load -> cause 5 */
        ".option pop\n"
        :: "r"(poison), "r"(bad)
        : "a0", "a1", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "memory");
}

void vec_jmp(const ic_unit_ctx *c) {
    __asm__ volatile (              /* OOB fetch -> cause 1, evicted */
        ".option push\n.option norvc\n"
        "jalr x0, 0(%0)\n"
        ".option pop\n" :: "r" (c->mon_flash) : "memory");
}

void vec_proof(const ic_unit_ctx *c) {
    *c->proof = 0x5EEDC0DEu;     /* the box still works after five evictions */
    ic_unit_yield();
}
