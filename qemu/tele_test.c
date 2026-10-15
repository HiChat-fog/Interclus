/* QEMU telemetry acceptance (E24): a native slot fault must emit an
 * evidence frame, and an operator re-arm frame must revive the slot.
 * tools/tele_qemu.py drives stdin/stdout and decodes the binary frames
 * that flow between the report lines. One verdict line:
 *   == TELE PASS == / == TELE FAIL ==
 * State 0: fetch-fault image installed into slot 0; the round evicts it
 *          and the telemetry frame flows (mcause 5, mtval = NAT2_SRAM).
 * State 1: the re-arm frame (already buffered) revives slot 0; the ack
 *          frame answers it. S_REARM=1.
 * State 2: slot 0 runs again, proof returns. Cumulative verdict. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

void uart_puts(const char *s);
void uart_puthex(uint32_t v);
void uart_putdec(uint32_t v);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
int chan_poll(uart_frame_rx *rx);
void qemu_exit(int code);

extern const uint8_t _binary_native_trap_s1_qemu_bin_start[];
extern const uint8_t _binary_native_trap_s1_qemu_bin_end[];
extern const uint8_t _binary_native_trap_qemu_bin_start[];
extern const uint8_t _binary_native_trap_qemu_bin_end[];

static volatile unsigned state;
static uart_frame_rx rx;

static void stage_native(uint32_t addr, const uint8_t *code, uint32_t len,
                         uint32_t entry, uint32_t slot) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint8_t *p = (volatile uint8_t *)(addr + 16u);
    a[0] = len;
    a[1] = PEND_NATIVE;
    a[2] = entry;
    a[3] = slot;
    for (uint32_t i = 0; i < len; i++) p[i] = code[i];
    trust_stamp((volatile uint8_t *)addr,
                (a[1] == PEND_NATIVE) ? 16u + a[0]
                                      : 8u + a[0] * 8u);
    a[0x208u / 4u] = PROG_PEND_MAGIC;
}

static void badnat(uint32_t slot) {
    /* slot0 install carries the slot0-pinned digest; the digest covers
     * the header including the slot word, so image and slot must match */
    stage_native(PROG_PEND_ADDR,
                 _binary_native_trap_qemu_bin_start,
                 (uint32_t)(_binary_native_trap_qemu_bin_end
                            - _binary_native_trap_qemu_bin_start),
                 0u, slot);
}

#define DRAIN_TICKS 3000000u

static int drain(void) {
    uint32_t t0 = TIMER_NOW();
    while ((uint32_t)(TIMER_NOW() - t0) < DRAIN_TICKS) {
        int ev = chan_poll(&rx);
        if (ev) return ev;
    }
    return 0;
}

void sweep_next(void) {
    uint32_t ok = 1;
    if (state == 0) {
        state = 1;
        badnat(0u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u) ok = 0;
    } else if (state == 1) {
        /* the round faulted in slot 0: telemetry left the device, the
         * boundary remapped nowhere (slot 1 empty) so the phase retired */
        state = 2;
        ok = STATUS[S_NAT2] == 0u && STATUS[S_NSLOT] == 0xFFFFFFFFu &&
             STATUS[S_ROLL] == 0u && STATUS[S_INTER] == 5u;
        {
            int ev = drain();
            if (ev != 3 || rx.type != FRAME_REARM) ok = 0;
        }
        if (STATUS[S_REARM] != 1u) ok = 0;
        /* the operator revives a slot they trust: a good image goes in
         * first, the re-arm makes it live — the poisoned image stays
         * dead in the table until overwritten */
        {
            /* the revive installs a GOOD module: native_variant, whose
             * digest is pinned (the trap image stays dead in the table
             * until overwritten) */
            extern const uint8_t _binary_native_variant_qemu_bin_start[];
            extern const uint8_t _binary_native_variant_qemu_bin_end[];
            stage_native(PROG_PEND_ADDR,
                         _binary_native_variant_qemu_bin_start,
                         (uint32_t)(_binary_native_variant_qemu_bin_end
                                    - _binary_native_variant_qemu_bin_start),
                         0u, 0u);
            hot_swap();
        }
    } else {
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_NSLOT] == 0u &&
             STATUS[S_REARM] == 1u;
        uart_puts(ok ? "\n== TELE PASS ==\n" : "\n== TELE FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== TELE FAIL ==\n");
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
