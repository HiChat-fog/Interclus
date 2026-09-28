/* Attacker probe (U-mode), contract v1.1: one vector per lifetime. A
 * vector either yields (ecall) or dies on its first fault (evicted);
 * the supervisor schedules the next lifetime either way. -O0 matches
 * the shipped image. */

#include <stdint.h>

#include "../core/platform.h"

#define MON_RESULTS  ((volatile uint32_t *)(MON_BOX + 0x200u))
#define MON_INPUT_W  ((volatile uint32_t *)(MON_BOX + 0x80u))
#define MON_FLASH    MON_TEXT

/* one stub per lifetime: fresh sp, then the vector. The stubs emit into
 * .text ahead of the vec functions (file order), so attacker_entry sits
 * at the region start — entry_offset 0 in the shipped description, same
 * convention as the native demo blob. */
#define VEC(sym, fn) \
    asm(".section .text\n" \
        ".globl " #sym "\n" \
        ".align 2\n" \
        #sym ":\n" \
        "  lui  sp, %hi(_atk_stack_top)\n" \
        "  addi sp, sp, %lo(_atk_stack_top)\n" \
        "  lui  t0, %hi(" #fn ")\n" \
        "  addi t0, t0, %lo(" #fn ")\n" \
        "  jalr t0\n" \
        "1: wfi\n" \
        "  j 1b\n")

VEC(attacker_entry, vec_own);
VEC(attacker_v1, vec_st_res);
VEC(attacker_v2, vec_st_in);
VEC(attacker_v3, vec_ld_res);
VEC(attacker_v4, vec_spv);
VEC(attacker_v5, vec_jmp);
VEC(attacker_v6, vec_proof);

void vec_own(void) {
    *ATK_OWN = 0xBEEF5EEDu;      /* own region: grant must let it land */
    __asm__ volatile ("ecall");
}

void vec_st_res(void) {
    *MON_RESULTS = 0x77777777u;  /* OOB store -> cause 7, evicted */
}

void vec_st_in(void) {
    *MON_INPUT_W = 0x88888888u;  /* OOB store -> cause 7, evicted */
}

void vec_ld_res(void) {
    volatile uint32_t v = *MON_RESULTS;   /* OOB load -> cause 5, evicted */
    (void)v;
}

/* sp-vector: poison sp at the screening verdict slots, mark the live
 * registers, then fault. The handler never stores through the poisoned
 * sp (mscratch swap since the fix); under v1.1 this lifetime simply ends
 * at the fault — eviction, not skip-and-continue. */
void vec_spv(void) {
    register uint32_t poison = (uint32_t)(STATUS + 76u);  /* verdicts+48 */
    register uint32_t bad = MON_FLASH;
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

void vec_jmp(void) {
    __asm__ volatile (              /* OOB fetch -> cause 1, evicted */
        ".option push\n.option norvc\n"
        "jalr x0, 0(%0)\n"
        ".option pop\n" :: "r" (MON_FLASH) : "memory");
}

void vec_proof(void) {
    *ATK_PROOF = 0x5EEDC0DEu;    /* the box still works after five evictions */
    __asm__ volatile ("ecall");
}
