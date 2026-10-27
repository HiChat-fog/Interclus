/* native_chaos.c: the PMP boundary under random fire. Each iteration
 * derives a fresh address from the seed staged in the slot's SRAM and
 * does a load then a store there. Odd steps probe the module's own
 * window (legal, must pass); even steps hit a uniform address in the
 * 64K RAM map or the 64K flash map — anything outside the module's two
 * windows must trap and evict. Surviving all 64 rounds means every
 * probe landed inside; the proof word says so. Linked per slot base
 * with modules/native.ld; its digest is pinned like any module. */

#include <stdint.h>

#ifndef NAT_SRAM_BASE
#define NAT_SRAM_BASE 0x2000B000
#endif
#define NAT_STACK_TOP (NAT_SRAM_BASE + 0x1000)
#define CHAOS_PROOF   0xC0DE00C5u

#define STR2(x) #x
#define STR(x) STR2(x)

__asm__ (
    ".globl native_entry\n"
    "native_entry:\n"
    "  li   sp, " STR(NAT_STACK_TOP) "\n"
    "  lui  a0, %hi(" STR(NAT_SRAM_BASE) ")\n"
    "  lw   a0, %lo(" STR(NAT_SRAM_BASE) ")(a0)\n"
    "  li   a1, 64\n"
    "chaos_loop:\n"
    "  beqz a1, chaos_done\n"
    "  addi a1, a1, -1\n"
    "  slli t0, a0, 13\n"
    "  xor  a0, a0, t0\n"
    "  srli t0, a0, 17\n"
    "  xor  a0, a0, t0\n"
    "  slli t0, a0, 5\n"
    "  xor  a0, a0, t0\n"
    "  andi t1, a0, 1\n"
    "  bnez t1, chaos_own\n"
    "  srli t2, a0, 16\n"
    "  andi t2, t2, 1\n"
    "  beqz t2, chaos_ram\n"
    "  lui  a2, 0x08000\n"
    "  j    chaos_probe\n"
    "chaos_ram:\n"
    "  lui  a2, 0x20000\n"
    "chaos_probe:\n"
    "  li   t3, 0xFFFF\n"
    "  and  t4, a0, t3\n"
    "  or   a2, a2, t4\n"
    "  lw   a3, 0(a2)\n"
    "  sw   a3, 0(a2)\n"
    "  j    chaos_loop\n"
    "chaos_own:\n"
    "  lui  a2, %hi(" STR(NAT_SRAM_BASE) ")\n"
    "  srli t4, a0, 8\n"
    "  li   t3, 0xFFF\n"
    "  and  t4, t4, t3\n"
    "  add  a2, a2, t4\n"
    "  lw   a3, 0(a2)\n"
    "  sw   a3, 0(a2)\n"
    "  j    chaos_loop\n"
    "chaos_done:\n"
    "  lui  a2, %hi(" STR(NAT_SRAM_BASE) ")\n"
    "  lui  a3, 0xC0DE0\n"
    "  addi a3, a3, 0xC5\n"
    "  sw   a3, %lo(" STR(NAT_SRAM_BASE) ")(a2)\n"
    "  ecall\n"
    "1: j 1b\n"
);
