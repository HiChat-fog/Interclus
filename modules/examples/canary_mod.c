/* canary_mod.c: E37 boundary-audit module. Each schedule round it
 * records the register file the supervisor restored into it, then parks
 * 31 distinct canaries (plus the stack pointer) into every live
 * register and ecalls. The host-side drill then verifies three things:
 * the TCB holds the complete evidence set, no canary leaked anywhere in
 * M-mode RAM outside the TCB, and the restored registers are exactly
 * this compartment's own parked values — never another lifetime's. */

#include <stdint.h>

#ifndef NAT_SRAM_BASE
#define NAT_SRAM_BASE 0x2000B000
#endif
#define BOX       ((volatile uint32_t *)NAT_SRAM_BASE)
#define BOXREC    (NAT_SRAM_BASE + 16u)
#define CANARY_TOP (NAT_SRAM_BASE + 0x1000u)

#define STR2(x) #x
#define STR(x) STR2(x)

/* canary_i(reg i, round) = 0xE3700000 + (round << 8) + i */
uint32_t canary_round(void) {
    uint32_t round = BOX[0];
    if (round >= 64u) round = 0u;        /* fuzzed box: restart the ladder */
    uint32_t base = 0xE3700000u | (round << 8);
    BOX[1] = base;
    BOX[0] = round + 1u;
    return base;
}

__asm__ (
    ".section .text\n"
    ".globl canary_entry\n"
    ".align 2\n"
    "canary_entry:\n"
    "  lui  sp, %hi(" STR(CANARY_TOP) ")\n"
    "  addi sp, sp, %lo(" STR(CANARY_TOP) ")\n"
    /* snapshot the restored s0..s11: the host compares these against the
     * canaries this compartment parked in the previous round */
    "  lui  t0, %hi(" STR(BOXREC) ")\n"
    "  addi t0, t0, %lo(" STR(BOXREC) ")\n"
    "  sw   s0, 0(t0)\n"
    "  sw   s1, 4(t0)\n"
    "  sw   s2, 8(t0)\n"
    "  sw   s3, 12(t0)\n"
    "  sw   s4, 16(t0)\n"
    "  sw   s5, 20(t0)\n"
    "  sw   s6, 24(t0)\n"
    "  sw   s7, 28(t0)\n"
    "  sw   s8, 32(t0)\n"
    "  sw   s9, 36(t0)\n"
    "  sw   s10, 40(t0)\n"
    "  sw   s11, 44(t0)\n"
    "  call canary_round\n"
    /* park: every live register gets its own canary; the trap path then
     * copies the whole file into the TCB and zeroes it */
    "  addi x1,  a0, 1\n"
    "  addi x3,  a0, 3\n"
    "  addi x4,  a0, 4\n"
    "  addi x5,  a0, 5\n"
    "  addi x6,  a0, 6\n"
    "  addi x7,  a0, 7\n"
    "  addi x8,  a0, 8\n"
    "  addi x9,  a0, 9\n"
    "  addi x11, a0, 11\n"
    "  addi x12, a0, 12\n"
    "  addi x13, a0, 13\n"
    "  addi x14, a0, 14\n"
    "  addi x15, a0, 15\n"
    "  addi x16, a0, 16\n"
    "  addi x17, a0, 17\n"
    "  addi x18, a0, 18\n"
    "  addi x19, a0, 19\n"
    "  addi x20, a0, 20\n"
    "  addi x21, a0, 21\n"
    "  addi x22, a0, 22\n"
    "  addi x23, a0, 23\n"
    "  addi x24, a0, 24\n"
    "  addi x25, a0, 25\n"
    "  addi x26, a0, 26\n"
    "  addi x27, a0, 27\n"
    "  addi x28, a0, 28\n"
    "  addi x29, a0, 29\n"
    "  addi x30, a0, 30\n"
    "  addi x31, a0, 31\n"
    "  addi sp,  a0, 2\n"
    "  addi x10, a0, 10\n"
    "  ecall\n"
    "1: j 1b\n"
    ".globl canary_stack_top\n"
    "canary_stack_top:\n"
);
