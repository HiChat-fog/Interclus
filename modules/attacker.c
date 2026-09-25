/* Attacker probe (U-mode). Built -O0 to match the shipped image. */

#include <stdint.h>

#include "../core/platform.h"

#define MON_RESULTS  ((volatile uint32_t *)(MON_BOX + 0x200u))
#define MON_INPUT_W  ((volatile uint32_t *)(MON_BOX + 0x80u))
#define MON_FLASH    MON_TEXT

void attacker_main(void) {
    *ATK_OWN = 0xBEEF5EEDu;      /* own region: grant must let it land */
    *MON_RESULTS = 0x77777777u;  /* OOB store -> cause 7, mtval=0x20004200 */
    *MON_INPUT_W = 0x88888888u;    /* OOB store -> cause 7, mtval=0x20004080 */
    {
        volatile uint32_t v = *MON_RESULTS;  /* OOB load -> cause 5 */
        (void)v;
    }
    /* step 6: vector the trap handler through our own sp. sp is aimed so a
     * handler saving at sp-48 would land on the screening verdict slots,
     * and the registers carry markers. Recovery is self-contained: the
     * handler skips the faulting load, returns here, and sp comes back
     * from s1, which the handler never touches. */
    {
        register uint32_t poison = (uint32_t)(STATUS + 76u);  /* verdicts+48 */
        register uint32_t bad = MON_FLASH;
        __asm__ volatile (
            ".option push\n.option norvc\n"
            "mv   s1, sp\n"
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
            "mv   sp, s1\n"             /* resume here: sp was never trusted */
            ".option pop\n"
            :: "r"(poison), "r"(bad)
            : "a0", "a1", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "s1",
              "memory");
    }
    /* OOB fetch -> cause 1; the supervisor redirects mepc to attacker_recover */
    __asm__ volatile (
        ".option push\n.option norvc\n"
        "jalr x0, 0(%0)\n"
        ".option pop\n" :: "r" (MON_FLASH) : "memory");
    for (;;) { __asm__ volatile ("wfi"); }   /* unreachable */
}

void attacker_recover(void) {
    *ATK_PROOF = 0x5EEDC0DEu;    /* recovery proof */
    __asm__ volatile ("ecall");  /* yield back */
    for (;;) { __asm__ volatile ("wfi"); }
}

asm(
    ".section .attacker.text\n"
    ".globl attacker_entry\n"
    ".align 2\n"
    "attacker_entry:\n"
    "  lui  sp, %hi(_atk_stack_top)\n"
    "  addi sp, sp, %lo(_atk_stack_top)\n"
    "  lui  t0, %hi(attacker_main)\n"
    "  addi t0, t0, %lo(attacker_main)\n"
    "  jalr t0\n"
    "1: wfi\n"
    "  j 1b\n"
);
