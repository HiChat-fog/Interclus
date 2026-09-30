/* QEMU hot-swap acceptance: the runtime program path must reject a
 * statically-bad image without disturbing the schedule, promote a
 * statically-legal one, and roll back to last-known-good after its first
 * interpreter fault. Three rounds, then one verdict line:
 *   == HOT PASS == / == HOT FAIL ==
 * Round 1: pass_all loaded at boot, verdicts [1 1 0 1 1 1].
 * Round 2: pass_all rejected (bad opcode), mov-to-r10 promoted — it is
 *          static-legal on purpose (the verifier allows r10 as dst; the
 *          interpreter faults FP at run) — the round faults, the
 *          supervisor rolls back to the shadow.
 * Round 3: pass_all restored from the shadow, verdicts return. */

#include <stdint.h>
#include "../core/platform.h"
#include "../modules/examples/pass_all.c"

void uart_puts(const char *s);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
void qemu_exit(int code);

static const uint32_t want[6] = { 1, 1, 0, 1, 1, 1 };
static const uint64_t badstat_ins[] = { 0xdeadbeefdeadbeefULL };
static const uint64_t badrun_ins[] = { EBPF_ENC(0xb7, 10, 0, 0, 1) };

static volatile unsigned state;

/* stage an image + magic into a program area; u64 stores match the
 * little-endian reassembly the loader does on the bytes */
static void stage(uint32_t addr, uint32_t magic,
                  const uint64_t *ins, uint32_t cnt) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint64_t *p = (volatile uint64_t *)(addr + 8u);
    a[0] = magic;
    a[1] = cnt;
    for (uint32_t i = 0; i < cnt; i++) p[i] = ins[i];
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
        ok = STATUS[S_LOAD] == 1u && verdicts_ok();
        stage(PROG_PEND_ADDR, PROG_PEND_MAGIC, badstat_ins, 1u);
        hot_swap();
        if (STATUS[S_HREJ] != 1u || STATUS[S_HLOAD] != 0u ||
            MON_PROG_CNT[0] != pass_all_cnt) ok = 0;
        stage(PROG_PEND_ADDR, PROG_PEND_MAGIC, badrun_ins, 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u || MON_PROG_CNT[0] != 1u ||
            MON_PROG_B_CNT[0] != pass_all_cnt) ok = 0;
    } else if (state == 1) {
        state = 2;
        /* the round ran the bad program: one strike, rolled back */
        ok = STATUS[S_ROLL] == 1u && MON_PROG_CNT[0] == pass_all_cnt &&
             MON_PROG_B_CNT[0] == 0u && MON_PROG_FAULT[0] == 0u;
    } else {
        ok = verdicts_ok() && STATUS[S_HLOAD] == 1u &&
             STATUS[S_HREJ] == 1u && STATUS[S_ROLL] == 1u;
        uart_puts(ok ? "\n== HOT PASS ==\n" : "\n== HOT FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== HOT FAIL ==\n");
        qemu_exit(1);
    }
    hot_round();
}

__attribute__((section(".text.startup")))
void boot(void) {
    stage(PROG_AREA, PROG_MAGIC, pass_all_ins, pass_all_cnt);
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
