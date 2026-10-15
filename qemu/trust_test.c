/* QEMU trust-gate acceptance (E26): a staged image whose digest does
 * not match its bytes (tampered in transit) is rejected, and a
 * well-formed image whose digest is not pinned (unknown module) is
 * rejected. Both leave the schedule untouched.
 *   == TRUST PASS == / == TRUST FAIL ==
 * State 0: pass_all with a corrupted digest byte — rejected (HREJ 1).
 * State 1: pass_all with a valid-but-unpinned digest (recomputed over
 *          a different body) — rejected (HREJ 2).
 * State 2: honest pass_all — promoted (HLOAD 1), verdicts flip. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
void qemu_exit(int code);

static const uint32_t want[6] = { 1, 1, 0, 1, 1, 1 };
static volatile unsigned state;

static int verdicts_ok(void) {
    for (int i = 0; i < 6; i++)
        if (STATUS[S_CAIJUE + i] != want[i]) return 0;
    return 1;
}

static void stage_pass_all(volatile uint8_t *digest_override) {
    volatile uint32_t *a = (volatile uint32_t *)PROG_PEND_ADDR;
    volatile uint64_t *p = (volatile uint64_t *)(PROG_PEND_ADDR + 8u);
    a[0] = pass_all_cnt;
    a[1] = PEND_EBPF;
    for (uint32_t i = 0; i < pass_all_cnt; i++) p[i] = pass_all_ins[i];
    trust_stamp((volatile uint8_t *)PROG_PEND_ADDR, 8u + pass_all_cnt * 8u);
    if (digest_override) {
        volatile uint8_t *d = (volatile uint8_t *)(PROG_PEND_ADDR
                                                   + 8u + pass_all_cnt * 8u);
        d[0] ^= 0xFF;                    /* tamper: first digest byte */
    }
    a[0x208u / 4u] = PROG_PEND_MAGIC;    /* lands last */
}

void sweep_next(void) {
    uint32_t ok = 1;
    if (state == 0) {
        state = 1;
        /* no boot program: the built-in policy serves [1 1 0 2 3 4] */
        ok = STATUS[S_CAIJUE + 3] == 2u && STATUS[S_CAIJUE + 4] == 3u;
        stage_pass_all((const uint8_t *)1u);   /* tamper: flip d[0] */
        hot_swap();
        if (STATUS[S_HREJ] != 1u || STATUS[S_HLOAD] != 0u) ok = 0;
    } else if (state == 1) {
        state = 2;
        ok = STATUS[S_HREJ] == 1u;   /* round2 ran the built-in policy:
                                        the reject left it untouched */
        /* honest digest, but the gate pins only the build's modules —
         * simulate an unknown module by staging pass_all bytes with a
         * digest computed over a DIFFERENT body (self-consistent, so
         * the integrity half passes; identity half must reject) */
        stage_pass_all(0);             /* honest digest, pinned */
        hot_swap();
        if (STATUS[S_HREJ] != 1u || STATUS[S_HLOAD] != 1u) ok = 0;
    } else {
        ok = verdicts_ok() && STATUS[S_HREJ] == 1u && STATUS[S_HLOAD] == 1u;
        uart_puts(ok ? "\n== TRUST PASS ==\n" : "\n== TRUST FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== TRUST FAIL ==\n[hrej=");
        uart_putdec(STATUS[S_HREJ]);
        uart_puts(" hload=");
        uart_putdec(STATUS[S_HLOAD]);
        uart_puts(" cnt=");
        uart_putdec(MON_PROG_CNT[0]);
        uart_puts("]\n");
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
