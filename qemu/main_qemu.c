/* QEMU target boot: entry, UART banner, fixture mailbox, then the same
 * supervisor (main_pmp.c) as the board. Run with:
 *   qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic */

#include <stdint.h>
#include "../pmp/platform.h"
#include "fixture.h"           /* per-N fixture arrays (capacity sweep) */

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
int report(void);
extern volatile int g_report_ok;
void rukou(void);
void supervisor_reset(void);
void qemu_exit(int code);

volatile uint8_t mailbox_ram[8 + 42u * 64u] __attribute__((section(".mailbox")));
static volatile unsigned sweep_t;
static volatile unsigned sweep_fails;

#define NFIX (sizeof(sweeps) / sizeof(sweeps[0]))

/* entered via `j sweep_next` from the supervisor's last phase: no caller
 * frame, never returns */
void sweep_next(void) {
    uart_puts("\n");
    if (!g_report_ok) sweep_fails++;
    sweep_t++;
    if (sweep_t >= NFIX) {
        uart_puts(sweep_fails ? "== SWEEP FAILED ==\n" : "== SWEEP 8/8 MATCH ==\n");
        qemu_exit(sweep_fails ? 1 : 0);
    }
    for (unsigned i = 0; i < 8u + 42u * sweeps[sweep_t].n; i++)
        mailbox_ram[i] = sweeps[sweep_t].data[i];
    supervisor_reset();
    rukou();
}

__attribute__((section(".text.startup")))
void boot(void) {
    uart_puts("== pmp-ebpf qemu: capacity sweep ==\n");
    for (unsigned i = 0; i < 8u + 42u * sweeps[0].n; i++)
        mailbox_ram[i] = sweeps[0].data[i];
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
