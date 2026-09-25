/* native_demo.c: minimal native compartment module. Built per target with
 * modules/native.ld at the fixed slot base (NAT_TEXT); the supervisor
 * copies the blob into the slot, gates it, and schedules it as
 * compartment 2. Self-contained code only: no data sections. */

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
    *(volatile uint32_t *)NAT_SRAM_BASE = 0xC0DE0002u;
    __asm__ volatile ("ecall");
    for (;;) { __asm__ volatile ("wfi"); }
}
