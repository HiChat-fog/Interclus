/* E38: one-strike rollback audit. The rollback path — an interpreter
 * fault in the live program must restore the shadow (or the builtin
 * policy when no shadow exists) within the same schedule round and
 * never let the corrupted image run twice — has only ever been probed
 * with one hand-crafted bad program. This firmware flips every single
 * bit of the live program, one bit per round, 448 rounds, and checks
 * after each round:
 *   - at most one strike: S_ROLL advances by 0 or 1, never more;
 *   - a faulting flip restores the shadow bytes exactly, consumes the
 *     shadow, and clears the fault flag; the faulted round's verdicts
 *     are zeros by design, so a verification round with no new flip
 *     must then produce the restored program's clean verdicts;
 *   - a silent flip (the corrupted image still runs) keeps the flipped
 *     bytes live — the designed behavior — with no spurious rollback;
 *   - the gate stays clean and no fail-stop marker appears.
 * Then the no-shadow case: with the shadow consumed, a fatal flip must
 * roll back to the builtin policy, and the following round must run it
 * with its own clean verdicts. */

#include <stdint.h>
#include "../core/platform.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"
#include "fixture.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
void qemu_exit(int code);

volatile uint8_t mailbox_ram[8 + 42u * 64u]
    __attribute__((section(".mailbox")));

static const uint32_t want_pass[6] = { 1, 1, 0, 1, 1, 1 };
static const uint32_t want_builtin[6] = { 1, 1, 0, 2, 3, 4 };
#define NBITS (pass_all_cnt * 64u)
#define NBYTES (pass_all_cnt * 8u)

static uint32_t state;               /* 0 boot check, 1 bit campaign,
                                        2 shadow consume, 3 no-shadow
                                        round, 4 no-shadow check,
                                        5 verdict */
static uint32_t bit;
static uint32_t roll_base;
static uint32_t fails;
static uint32_t faults;              /* flips that actually faulted */
static uint32_t verify_pending;      /* the next round must prove the
                                        restoration */

static int kmemcmp(const uint8_t *a, const uint8_t *b, uint32_t n) {
    for (uint32_t i = 0; i < n; i++)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

static int verdicts_ok(const uint32_t *want) {
    for (int i = 0; i < 6; i++)
        if (STATUS[S_CAIJUE + i] != want[i]) return 0;
    return 1;
}

static int halted(void) {
    return STATUS[S_HALT] == 0x48414C54u;
}

static void install_pass(void) {
    volatile uint32_t *a = (volatile uint32_t *)PROG_PEND_ADDR;
    volatile uint64_t *p = (volatile uint64_t *)(PROG_PEND_ADDR + 8u);
    a[0] = pass_all_cnt;
    a[1] = PEND_EBPF;
    for (uint32_t i = 0; i < pass_all_cnt; i++) p[i] = pass_all_ins[i];
    trust_stamp((volatile uint8_t *)PROG_PEND_ADDR, 8u + NBYTES);
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;                 /* lands last */
}

/* two installs: the first demotes the current live image into the
 * shadow, the second puts a clean copy live — so both the live image
 * and the shadow hold the unflipped program */
static void install_pass_twice(void) {
    install_pass();
    hot_swap();
    install_pass();
    hot_swap();
}

static void flip_bit(uint32_t word, uint64_t mask) {
    ((volatile uint64_t *)MON_PROG)[word] ^= mask;
}

static void fatal_flip(void) {
    flip_bit(6, 2u);                   /* exit -> mod-by-zero */
}

/* the supervisor's last phase jumps here after every round; the frame
 * is abandoned each time, so all state lives in the globals above */
void sweep_next(void) {
    if (state == 0) {
        state = 1;
        bit = 0;
        if (STATUS[S_ROLL] != 0u || !verdicts_ok(want_pass)) fails++;
        install_pass_twice();
        roll_base = STATUS[S_ROLL];
        flip_bit(bit >> 6, 1ull << (bit & 63));
    } else if (state == 1) {
        uint32_t roll = STATUS[S_ROLL] - roll_base;
        uint32_t advance = 0;
        if (roll > 1u) { fails++; uart_puts("multi-strike\n"); }
        if (verify_pending) {
            /* the round ran the restored program with no new flip:
             * its verdicts are the restoration proof */
            verify_pending = 0;
            if (!verdicts_ok(want_pass) ||
                kmemcmp((const uint8_t *)MON_PROG,
                        (const uint8_t *)pass_all_ins, NBYTES) != 0) {
                fails++;
                uart_puts("verdicts not restored\n");
            }
            advance = 1;
        } else {
            uint8_t live[NBYTES];
            for (uint32_t i = 0; i < NBYTES; i++)
                live[i] = ((const volatile uint8_t *)MON_PROG)[i];
            if (roll == 1u) {
                faults++;
                if (MON_PROG_CNT[0] != pass_all_cnt ||
                    kmemcmp((const uint8_t *)MON_PROG,
                            (const uint8_t *)pass_all_ins, NBYTES) != 0 ||
                    MON_PROG_B_CNT[0] != 0u || MON_PROG_FAULT[0] != 0u) {
                    fails++;
                    uart_puts("shadow restore wrong\n");
                }
                /* the faulted round's verdicts are zeros by design;
                 * the next round runs the restored program cleanly */
                verify_pending = 1;
            } else {
                /* silent flip: the flipped image stays live by design;
                 * reconstruct the expected bytes for the check */
                uint8_t want[NBYTES];
                for (uint32_t i = 0; i < NBYTES; i++)
                    want[i] = ((const uint8_t *)pass_all_ins)[i];
                want[bit >> 3] ^= (uint8_t)(1u << (bit & 7));
                if (kmemcmp(live, want, NBYTES) != 0) {
                    fails++;
                    uart_puts("silent flip drifted\n");
                }
                advance = 1;
            }
        }
        if (STATUS[S_GATE] != 0xc0de0000u || halted()) {
            fails++;
            uart_puts("gate/halt\n");
        }
        if (advance) {
            bit++;
            if (bit == NBITS) {
                state = 2;
                uart_puts("\nbits done: ");
                uart_putdec(faults);
                uart_puts(" faulted of ");
                uart_putdec(NBITS);
                /* consume the shadow with a guaranteed fault (exit ->
                 * mod-by-zero) so the no-shadow case starts clean */
                install_pass_twice();
                roll_base = STATUS[S_ROLL];
                fatal_flip();
            } else {
                install_pass_twice();
                roll_base = STATUS[S_ROLL];
                flip_bit(bit >> 6, 1ull << (bit & 63));
            }
        }
        /* no advance: the verification round runs unflipped */
    } else if (state == 2) {
        /* the forced fault consumed the shadow: live = pass_all,
         * shadow empty */
        state = 3;
        if (STATUS[S_ROLL] - roll_base != 1u ||
            MON_PROG_CNT[0] != pass_all_cnt ||
            MON_PROG_B_CNT[0] != 0u) {
            fails++;
            uart_puts("shadow-consume setup wrong\n");
        }
        roll_base = STATUS[S_ROLL];
        fatal_flip();
    } else if (state == 3) {
        /* no shadow: the strike restores the builtin policy; the
         * faulted round's verdicts are zeros by design, so the proof
         * of restoration is the next round */
        state = 4;
        if (STATUS[S_ROLL] - roll_base != 1u ||
            MON_PROG_CNT[0] != 0u || halted()) {
            fails++;
            uart_puts("builtin rollback wrong: roll=");
            uart_putdec(STATUS[S_ROLL] - roll_base);
            uart_puts(" cnt=");
            uart_putdec(MON_PROG_CNT[0]);
            uart_puts("\n");
        }
    } else if (state == 4) {
        /* the round after the no-shadow rollback: the builtin policy
         * runs clean over the six operator packets */
        state = 5;
        if (MON_PROG_CNT[0] != 0u || !verdicts_ok(want_builtin)
            || halted()) {
            fails++;
            uart_puts("builtin not running: cnt=");
            uart_putdec(MON_PROG_CNT[0]);
            uart_puts(" verdicts=");
            for (int i = 0; i < 6; i++) {
                uart_putdec(STATUS[S_CAIJUE + i]);
                uart_puts(" ");
            }
            uart_puts("\n");
        }
        uart_puts(fails ? "\n== ROLL FAIL ==\n" : "\n== ROLL PASS ==\n");
        qemu_exit(fails ? 1 : 0);
    }
    if (fails > 8u) {
        uart_puts("\n== ROLL FAIL ==\n");
        qemu_exit(1);
    }
    hot_round();
}

__attribute__((section(".text.startup")))
void boot(void) {
    /* the builtin policy is only deterministic over the same operator
     * input the capacity sweep uses: preload the mailbox exactly like
     * the fixture driver does */
    for (uint32_t i = 0; i < 8u + 42u * sweeps[0].n; i++)
        mailbox_ram[i] = sweeps[0].data[i];
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
