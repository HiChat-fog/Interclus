/* QEMU load test: pass_all goes through the boot-time load path and must
 * replace the built-in mavlink policy for the six built-in packets.
 * Run with:
 *   qemu-system-riscv32 -M virt -bios none -kernel build/fw_load.elf -nographic
 * PASS line: == LOAD PASS ==
 * Built with -DPROG_FROM_UART (fw_urx.elf), the program arrives on the
 * console instead: tools/uart_frame.py feeds the frame via stdin. */

#include <stdint.h>
#include "../core/platform.h"
#include "../modules/examples/pass_all.c"

void uart_puts(const char *s);
int report(void);
void rukou(void);
void supervisor_reset(void);
void qemu_exit(int code);

static const uint32_t want[6] = { 1, 1, 0, 1, 1, 1 };

/* the supervisor's last phase jumps here; nothing to sweep, just check */
void sweep_next(void) {
    uint32_t ok = (STATUS[S_LOAD] == 1u);
    for (int i = 0; i < 6; i++)
        if (STATUS[S_CAIJUE + i] != want[i]) ok = 0;
    uart_puts(ok ? "\n== LOAD PASS ==\n" : "\n== LOAD FAIL ==\n");
    qemu_exit(ok ? 0 : 1);
}

__attribute__((section(".text.startup")))
void boot(void) {
#ifndef PROG_FROM_UART
    volatile uint32_t *area = (volatile uint32_t *)PROG_AREA;
    volatile uint64_t *ins = (volatile uint64_t *)(PROG_AREA + 8u);
    area[0] = PROG_MAGIC;
    area[1] = pass_all_cnt;
    for (unsigned i = 0; i < pass_all_cnt; i++)
        ins[i] = pass_all_ins[i];
#endif
    supervisor_reset();
    rukou();
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
