/* native_trap.c: a signed-but-hostile module for the E26-era drills —
 * its digest is pinned in the trust list (the operator legitimately
 * signed it), yet the code fetches outside its window, so the PMP
 * stops it at run. This is the trust-vs-safety story: the gate proves
 * identity, the PMP remains the safety guarantee. Built per target
 * with modules/native.ld; slot-agnostic (linked per base). */

#include <stdint.h>

#ifndef NAT_SRAM_BASE
#define NAT_SRAM_BASE 0x2000B000
#endif
#define NAT_STACK_TOP (NAT_SRAM_BASE + 0x1000)

#define STR2(x) #x
#define STR(x) STR2(x)

__asm__ (
    ".globl native_entry\n"
    "native_entry:\n"
    "  li sp, " STR(NAT_STACK_TOP) "\n"
    "  j native_trap\n"
    "1: j 1b\n"
);

/* fetch from +0x1000: inside the SRAM window where X is denied */
void native_trap(void) {
    __asm__ volatile (
        "auipc t0, 1\n"              /* +0x1000: inside the SRAM window */
        "jalr  x0, 0(t0)\n"
    );
    for (;;) { __asm__ volatile ("wfi"); }
}
