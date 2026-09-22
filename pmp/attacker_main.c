/* Attacker probe (U-mode). Built -O0 to match the shipped image. */

#include <stdint.h>

#include "platform.h"

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
