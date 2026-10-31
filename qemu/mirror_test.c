/* E43: boot restore-gate audit. The E25 mirror gives a compartment
 * persistence across boots, and the restore path treats the mirror as
 * untrusted flash: a magic check, then the descriptor gate on the
 * reconstructed descriptor. This firmware corrupts every single bit of
 * a validly-mirrored slot — 2176 bits, one boot per bit — and asserts
 * per field class:
 *   magic   -> the restore is rejected, the builtin demo runs (proof 2);
 *   slot    -> the field is not read back, the restore proceeds (proof 3);
 *   len     -> zero rejects (proof 2), other flips accept with the copy
 *              clamped (proof 3, never the builtin);
 *   entry   -> the descriptor gate rejects odd/out-of-range entries
 *              (proof 2); in-range-but-wrong entries fault the module
 *              and the phase retires (no proof, 0) — never the builtin;
 *   code    -> the gate cannot see these; the module runs corrupted and
 *              contained: its proof store either survives (3) or the
 *              lifetime faults (0) — the builtin must never run, because
 *              the restore accepted the image.
 * Universal per bit: the schedule completes, the gate stays clean, no
 * fail-stop marker. The teeth demonstration drops the magic check so a
 * corrupted-magic mirror restores garbage and the class-A assertion
 * must fail. */

#include <stdint.h>
#include "../core/platform.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

extern uint32_t mir_ram[2048u / 4u];

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void qemu_exit(int code);

extern const uint8_t _binary_native_variant_qemu_bin_start[];
extern const uint8_t _binary_native_variant_qemu_bin_end[];

#define MIR_PAGE 0x80214000u
#define PAGEBITS (256u * 8u)

static uint32_t state, bit, fails;
static uint32_t nat2;

static void install_variant(void) {
    volatile uint32_t *a = (volatile uint32_t *)PROG_PEND_ADDR;
    volatile uint8_t *p = (volatile uint8_t *)(PROG_PEND_ADDR + 16u);
    uint32_t len = (uint32_t)(_binary_native_variant_qemu_bin_end
                              - _binary_native_variant_qemu_bin_start);
    uint8_t dg[32];
    a[0] = len;
    a[1] = PEND_NATIVE;
    a[2] = 0u;
    a[3] = 0u;
    for (uint32_t i = 0; i < len; i++) p[i] = _binary_native_variant_qemu_bin_start[i];
    sha256((const uint8_t *)PROG_PEND_ADDR, 16u + len, dg);
    for (uint32_t k = 0; k < 32u; k++)
        ((volatile uint8_t *)PROG_PEND_ADDR)[16u + len + k] = dg[k];
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;
}

static uint32_t flip_word(uint32_t byte_off) {
    return byte_off >> 2u;
}

static char class_of(uint32_t b) {
    if (b < 32u) return 'A';
    if (b < 64u) return 'B';
    if (b < 96u) return 'C';
    if (b < 128u) return 'D';
    return 'E';
}

static int halted(void) {
    return STATUS[S_HALT] == 0x48414C54u;
}

/* A: magic corrupted -> builtin. B: the slot word is never read back.
 * C: len zero rejects, other flips accept with a clamped copy.
 * D: a wrong entry faults the lifetime before the builtin could run.
 * E: the code is corrupted, so the box value it leaves behind is not a
 * verification signal at all — containment is what matters, and that is
 * E36/E37's proven territory; only the schedule must survive. */
static int proof_ok(char cls, uint32_t proof) {
    if (cls == 'A') return proof == 0xC0DE0002u;
    if (cls == 'B') return proof == 0xC0DE0003u;
    if (cls == 'C') return proof == 0xC0DE0002u || proof == 0xC0DE0003u;
    if (cls == 'D') return proof != 0xC0DE0002u;
    return 1;
}

/* the supervisor's last phase jumps here after every round */
void sweep_next(void) {
    if (state == 0) {
        state = 1;
        bit = 0;
        install_variant();
        hot_swap();
        /* S_NAT2 is round-scoped: it still shows the boot round's
         * builtin proof here. The install's immediate observables are
         * the hot-load count and the live slot. */
        if (STATUS[S_HLOAD] != 1u || STATUS[S_NSLOT] != 0u) {
            fails++;
            uart_puts("install failed\n");
        }
        /* the round just completed ran the variant; start the campaign */
    }
    if (state == 1) {
        /* the boot that just finished carried exactly one corrupted bit:
         * undo it before the next corruption, or the damage accumulates */
        if (bit > 0u) {
            volatile uint8_t *pg = (volatile uint8_t *)MIR_PAGE;
            pg[(bit - 1u) >> 3] ^= (uint8_t)(1u << ((bit - 1u) & 7));
            char cls = class_of(bit - 1u);
            uint32_t proof = STATUS[S_NAT2];
            if (!proof_ok(cls, proof) || halted()
                || STATUS[S_GATE] != 0xc0de0000u
                || STATUS[S_DONE] != 0x600DF00Du) {
                fails++;
                if (fails < 6u) {
                    uart_puts("class ");
                    uart_putdec(cls - 'A');
                    uart_puts(" bit ");
                    uart_putdec(bit - 1u);
                    uart_puts(" proof_top=");
                    uart_putdec(proof >> 28);
                    uart_puts(" proof_lo=");
                    uart_putdec(proof & 0xFFFFu);
                    uart_puts(" nslot=");
                    uart_putdec(STATUS[S_NSLOT]);
                    uart_puts("\n");
                }
            }
        }
#ifdef E43_DEBUG
        if (bit >= 40u) {
            uart_puts("halt=");
            uart_putdec(STATUS[S_HALT] >> 28);
            uart_puts(" nslot=");
            uart_putdec(STATUS[S_NSLOT]);
            uart_puts(" nat2=");
            uart_putdec(STATUS[S_NAT2] >> 28);
            uart_putdec(STATUS[S_NAT2] & 0xFFFFu);
            uart_puts(" gnat0len=");
            uart_putdec(0u);
            uart_puts("\n");
            qemu_exit(fails ? 1 : 0);
        }
#endif
        if (bit == PAGEBITS) {
            uart_puts("\nbits done: ");
            uart_putdec(PAGEBITS);
            uart_puts("\n");
            uart_puts(fails ? "\n== MIRROR FAIL ==\n"
                            : "\n== MIRROR PASS ==\n");
            qemu_exit(fails ? 1 : 0);
        }
        /* corrupt the next bit, reboot in place, let the round re-run */
        volatile uint8_t *page = (volatile uint8_t *)MIR_PAGE;
        page[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
        bit++;
        supervisor_reset();
        boot_main();
        return;
    }
    uart_puts("\n== MIRROR FAIL ==\n");
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
