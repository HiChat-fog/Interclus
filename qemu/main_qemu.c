/* QEMU target boot: entry, UART banner, fixture mailbox, then the same
 * supervisor (main_pmp.c) as the board. Run with:
 *   qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic */

#include <stdint.h>
#include "../pmp/platform.h"
#include "fixture.h"           /* const mailbox_init[] in section .mailbox */

void uart_puts(const char *s);
void report(void);
void rukou(void);

__attribute__((section(".text.startup")))
void boot(void) {
    uart_puts("== pmp-ebpf qemu ==\n");
    rukou();                       /* four-phase schedule; report() at the end */
    for (;;) { __asm__ volatile ("wfi"); }
}

__asm__(
    ".section .text.startup\n"    /* QEMU -bios none jumps to 0x80000000 */
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot\n"
);
