/* native_variant.c: second native compartment module for the hot-load
 * drill — identical shape to native_demo, different proof word, so a
 * swap is observable in S_NAT2. Built per target with modules/native.ld
 * at the fixed slot base; never linked into an image, only converted to
 * a raw blob and staged through the hot path. */

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
    "  call native_main\n"
    "1: j 1b\n"
);

void native_main(void) {
    *(volatile uint32_t *)NAT_SRAM_BASE = 0xC0DE0003u;
    __asm__ volatile ("ecall");
    for (;;) { __asm__ volatile ("wfi"); }
}
