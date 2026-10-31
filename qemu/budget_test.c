/* QEMU budget acceptance (E28): a signed module that never yields is
 * running in slot 1 when its slice expires. The machine timer fires,
 * the trap path treats the overrun as the slot's one strike, and the
 * schedule remaps to slot 0 — the round ends instead of parking.
 *   == BUDGET PASS == / == BUDGET FAIL ==
 * State 0: round 1 served the built-in demo (proof 0xC0DE0002).
 *          Install native_spin into slot 1 (its digest is pinned).
 * State 1: round 2 entered the spinner, the timer killed it:
 *          S_PREEMPT=1, S_ROLL=1, nat2=0, boundary remapped to slot 0.
 * State 2: round 3 ran the slot-0 demo again — proof returned. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"
#include "trust_stub.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
void qemu_exit(int code);

extern const uint8_t _binary_native_spin_s1_qemu_bin_start[];
extern const uint8_t _binary_native_spin_s1_qemu_bin_end[];

static volatile unsigned state;

static void stage_native(uint32_t addr, const uint8_t *code, uint32_t len,
                         uint32_t entry, uint32_t slot) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint8_t *p = (volatile uint8_t *)(addr + 16u);
    a[0] = len;
    a[1] = PEND_NATIVE;
    a[2] = entry;
    a[3] = slot;
    for (uint32_t i = 0; i < len; i++) p[i] = code[i];
    trust_stamp((volatile uint8_t *)addr, 16u + len);
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;
}

static int verdicts_ok(void) {
    static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };
    for (int i = 0; i < 6; i++)
        if (STATUS[S_CAIJUE + i] != want[i]) return 0;
    return 1;
}

void sweep_next(void) {
    uint32_t ok = 1;
    if (state == 0) {
        state = 1;
        ok = STATUS[S_NAT2] == 0xC0DE0002u && STATUS[S_NSLOT] == 0u &&
             verdicts_ok();
        stage_native(PROG_PEND_ADDR, _binary_native_spin_s1_qemu_bin_start,
                     (uint32_t)(_binary_native_spin_s1_qemu_bin_end
                                - _binary_native_spin_s1_qemu_bin_start),
                     0u, 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u || STATUS[S_NSLOT] != 1u) ok = 0;
    } else if (state == 1) {
        state = 2;
        /* the spinner was killed by the timer, not by a fault */
        ok = STATUS[S_PREEMPT] == 1u && STATUS[S_ROLL] == 1u &&
             STATUS[S_NAT2] == 0u && STATUS[S_NSLOT] == 0u;
    } else {
        ok = STATUS[S_NAT2] == 0xC0DE0002u && STATUS[S_PREEMPT] == 1u &&
             verdicts_ok();
        uart_puts(ok ? "\n== BUDGET PASS ==\n" : "\n== BUDGET FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== BUDGET FAIL ==\n[preempt=");
        uart_putdec(STATUS[S_PREEMPT]);
        uart_puts(" roll=");
        uart_putdec(STATUS[S_ROLL]);
        uart_puts(" nat2=");
        uart_putdec(STATUS[S_NAT2]);
        uart_puts(" nslot=");
        uart_putdec(STATUS[S_NSLOT]);
        uart_puts("]\\n");
        qemu_exit(1);
    }
    hot_round();
}

__attribute__((section(".text.startup")))
void boot(void) {
    supervisor_reset();
    boot_main();
    for (;;) { __asm__ volatile ("wfi"); }
}

__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot\n"
);
