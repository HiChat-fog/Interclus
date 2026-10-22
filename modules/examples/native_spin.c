/* native_spin.c: the budget drill's hostile module — signed (its digest
 * is pinned) but it never yields. Without a time budget the schedule
 * would park on it forever; the machine timer turns the overrun into
 * the same one-strike eviction a fault gets. Linked per slot base with
 * modules/native.ld. */

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
    "1: j 1b\n"
);
