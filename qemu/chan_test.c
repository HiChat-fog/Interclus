/* QEMU runtime-channel acceptance (E21): frames that arrive mid-run over
 * the console must move the schedule the same way debugger writes do.
 * The frames come from tools/chan_qemu.py on stdin, in this order:
 *   A: type 1, pass_all PROG image — consumed by the boot window
 *   B: type 2, mailbox image, 8-packet swarm — runtime data commit
 *   C: type 1, pass_all again — runtime module install via PEND
 *   D: type 2, corrupted — dropped by the assembler, nothing moves
 *   E: type 1, illegal opcode — staged, rejected by the gates
 * One verdict line: == CHAN PASS == / == CHAN FAIL ==
 * State 0: boot load ran, synthetic round; B commits, re-run.
 * State 1: swarm live (count/source/alerts match the C mirror); C
 *          promotes (S_HLOAD=1), re-run.
 * State 2: promoted program runs, swarm persists; E rejects (S_HREJ=1)
 *          and the live program stays untouched.
 * State 3: cumulative verdict. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

void uart_puts(const char *s);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
int chan_poll(uart_frame_rx *rx);
void qemu_exit(int code);

static const uint32_t want[6] = { 1, 1, 0, 1, 1, 1 };
static volatile unsigned state;

/* frames wait in the chardev while rounds run; each drain gets a generous
 * deadline (ticks at the 10 MHz timebase) instead of a spin count */
#define DRAIN_TICKS 3000000u

static uart_frame_rx rx;

/* pull frames until `want` channel events happened. During rounds
 * 1..4 nothing else consumes the console (the service loop starts at
 * native_done, after this drill), so this direct drain is the only
 * reader — no double-consumer. */
static int drain(int want) {
    int got = 0;
    uint32_t t0 = TIMER_NOW();
    while ((uint32_t)(TIMER_NOW() - t0) < DRAIN_TICKS && got < want) {
        int ev = chan_poll(&rx);
        if (ev == 1) got++;
        else if (ev == 2) { hot_swap(); got++; }
    }
    return got;
}

/* C mirror of the screening policy over the live swarm (as report.c) */
static uint32_t mirror_alerts(void) {
    uint32_t m[64] = { 0 };
    uint32_t n = STATUS[S_CHONGTU_N];
    uint32_t alerts = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t lat, lon;
        __asm__ volatile ("lw %0, 0(%1)" : "=r"(lat) : "r"(MB_DATA + i * 42u + 10u));
        __asm__ volatile ("lw %0, 0(%1)" : "=r"(lon) : "r"(MB_DATA + i * 42u + 14u));
        uint32_t c = ((lat >> 26) & 7u) * 8u + ((lon >> 26) & 7u);
        m[c]++;
        uint32_t left = m[(c - 1u) & 63u], right = m[(c + 1u) & 63u];
        if (m[c] > 3u || left > 3u || right > 3u) alerts++;
    }
    return alerts;
}

static int verdicts_ok(void) {
    for (int i = 0; i < 6; i++)
        if (STATUS[S_CAIJUE + i] != want[i]) return 0;
    return 1;
}

/* the supervisor's last phase jumps here after every round */
void sweep_next(void) {
    uint32_t ok = 1;
    if (state == 0) {
        state = 1;
        ok = STATUS[S_LOAD] == 1u && verdicts_ok() &&      /* frame A */
             STATUS[S_CHONGTU_N] == 8u && STATUS[S_LAIYUAN] == 0u;
        if (drain(1) != 1) ok = 0;                          /* frame B */
    } else if (state == 1) {
        state = 2;
        ok = STATUS[S_CHONGTU_N] == 24u && STATUS[S_LAIYUAN] == 1u &&
             STATUS[S_JINGBAO] == mirror_alerts() && verdicts_ok();
        if (drain(1) != 1) ok = 0;                          /* frame C */
        if (STATUS[S_HLOAD] != 1u) ok = 0;
    } else if (state == 2) {
        state = 3;
        ok = STATUS[S_HLOAD] == 1u && STATUS[S_HREJ] == 0u && verdicts_ok() &&
             STATUS[S_CHONGTU_N] == 24u &&                  /* swarm persists */
             MON_PROG_CNT[0] == pass_all_cnt;
        if (drain(1) != 1) ok = 0;                          /* D drops, E stages */
        if (STATUS[S_HREJ] != 1u) ok = 0;                   /* gates said no */
        if (STATUS[S_HLOAD] != 1u) ok = 0;                  /* and nothing moved */
        if (MON_PROG_CNT[0] != pass_all_cnt) ok = 0;
    } else {
        ok = STATUS[S_LOAD] == 1u && STATUS[S_HLOAD] == 1u &&
             STATUS[S_HREJ] == 1u && verdicts_ok() &&
             STATUS[S_CHONGTU_N] == 24u && STATUS[S_LAIYUAN] == 1u;
        uart_puts(ok ? "\n== CHAN PASS ==\n" : "\n== CHAN FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== CHAN FAIL ==\n[load=");
        uart_putdec(STATUS[S_LOAD]);
        uart_puts(" hload=");
        uart_putdec(STATUS[S_HLOAD]);
        uart_puts(" hrej=");
        uart_putdec(STATUS[S_HREJ]);
        uart_puts(" n=");
        uart_putdec(STATUS[S_CHONGTU_N]);
        uart_puts(" src=");
        uart_putdec(STATUS[S_LAIYUAN]);
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
    ".section .text.startup\n"    /* QEMU -bios none jumps to 0x80000000 */
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot\n"
);
