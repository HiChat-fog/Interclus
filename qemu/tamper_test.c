/* E38-style campaign for the trust gate (E26): every bit of a staged
 * eBPF image — header, payload, and pinned digest, 768 bits — is
 * flipped before hot_swap, and the gate must reject each one (HREJ
 * advances, HLOAD never moves, the live program is untouched). A clean
 * install afterwards proves the rejections were bit-specific. The
 * teeth demonstration makes trust_check accept everything; the
 * campaign must then fail with HLOAD running away. */

#include <stdint.h>
#include "../core/platform.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void qemu_exit(int code);

#define NBYTES (pass_all_cnt * 8u)
#define NBITS ((8u + NBYTES + 32u) * 8u)

static uint32_t state, fails, hrej0, hload0, flips;

static void install_pass(void) {
    volatile uint32_t *a = (volatile uint32_t *)PROG_PEND_ADDR;
    volatile uint64_t *p = (volatile uint64_t *)(PROG_PEND_ADDR + 8u);
    a[0] = pass_all_cnt;
    a[1] = PEND_EBPF;
    for (uint32_t i = 0; i < pass_all_cnt; i++) p[i] = pass_all_ins[i];
    trust_stamp((volatile uint8_t *)PROG_PEND_ADDR, 8u + NBYTES);
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;
}

void sweep_next(void) {
    if (state == 0) {
        state = 1;
        hrej0 = STATUS[S_HREJ];
        hload0 = STATUS[S_HLOAD];
        for (uint32_t b = 0; b < NBITS; b++) {
            install_pass();
            ((volatile uint8_t *)PROG_PEND_ADDR)[b >> 3]
                ^= (uint8_t)(1u << (b & 7));
            hot_swap();
            if (STATUS[S_HREJ] != hrej0 + b + 1u
                || STATUS[S_HLOAD] != hload0) {
                fails++;
                if (fails < 4u) {
                    uart_puts("flip accepted at bit ");
                    uart_putdec(b);
                    uart_puts("\n");
                }
            }
        }
        uart_puts("bits done: ");
        uart_putdec(NBITS);
        uart_puts("\n");
        state = 1;
        state = 2;
        install_pass();
        hot_swap();
        if (STATUS[S_HLOAD] != hload0 + 1u
            || STATUS[S_HREJ] != hrej0 + NBITS) {
            fails++;
            uart_puts("control install rejected\n");
        }
        /* the capacity fix's runtime proof: a full-length 64-insn
         * program stages, passes the trust gate, and installs — the
         * digest no longer overlaps the magic word */
        {
            static uint64_t max_ins[64];
            max_ins[0] = 0xb7ull | (0x00ull << 8) | (1ull << 32);   /* mov r0, 1 */
            for (uint32_t i = 0; i < 62u; i++)
                max_ins[1u + i] = 0xb7u | (0x02u << 8) | ((uint64_t)i << 32);
            max_ins[63] = 0x95u;                              /* exit */
            volatile uint32_t *a = (volatile uint32_t *)PROG_PEND_ADDR;
            volatile uint64_t *p = (volatile uint64_t *)(PROG_PEND_ADDR + 8u);
            a[0] = 64u;
            a[1] = PEND_EBPF;
            for (uint32_t i = 0; i < 64u; i++) p[i] = max_ins[i];
            trust_stamp((volatile uint8_t *)PROG_PEND_ADDR, 8u + 64u * 8u);
            a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;
            hot_swap();
            if (STATUS[S_HLOAD] != hload0 + 2u) {
                fails++;
                uart_puts("max-length install rejected: hrej+");
                uart_putdec(STATUS[S_HREJ] - (hrej0 + 768u));
                uart_puts(" site=");
                uart_putdec(STATUS[S_FUZZA]);
                uart_puts(" w0=");
                uart_putdec(STATUS[S_FUZZR]);
                uart_puts(" hload=");
                uart_putdec(STATUS[S_HLOAD] - hload0);
                uart_puts(" load=");
                uart_putdec(STATUS[S_LOAD]);
                uart_puts("\n");
            }
        }
        uart_puts(fails ? "\n== TAMPER FAIL ==\n" : "\n== TAMPER PASS ==\n");
        qemu_exit(fails ? 1 : 0);
    }
    uart_puts("\n== TAMPER FAIL ==\n");
    qemu_exit(1);
}

__attribute__((section(".text.startup")))
void boot(void) {
    volatile uint32_t *a = (volatile uint32_t *)PROG_AREA;
    volatile uint64_t *p = (volatile uint64_t *)(PROG_AREA + 8u);
    a[0] = PROG_MAGIC;
    a[1] = pass_all_cnt;
    for (uint32_t i = 0; i < pass_all_cnt; i++) p[i] = pass_all_ins[i];
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
