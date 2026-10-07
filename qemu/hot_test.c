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
void uart_puthex(uint32_t v);
void uart_putdec(uint32_t v);
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

/* the boot program area keeps magic-first (the boot loader is not a
 * poller); the hot staging area keeps magic-LAST so the running service
 * loop never sees a half-written image */
static void stage_boot(uint32_t addr, const uint64_t *ins, uint32_t cnt) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint64_t *p = (volatile uint64_t *)(addr + 8u);
    a[0] = PROG_MAGIC;
    a[1] = cnt;
    for (uint32_t i = 0; i < cnt; i++) p[i] = ins[i];
}

static void stage_pend(uint32_t addr, const uint64_t *ins, uint32_t cnt) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint64_t *p = (volatile uint64_t *)(addr + 8u);
    a[0] = cnt;
    a[1] = PEND_EBPF;
    for (uint32_t i = 0; i < cnt; i++) p[i] = ins[i];
    a[0x208u / 4u] = PROG_PEND_MAGIC;                 /* lands last */
}

extern const uint8_t _binary_native_variant_qemu_bin_start[];
extern const uint8_t _binary_native_variant_qemu_bin_end[];

/* native PEND image: [0]=len, [1]=kind, [2]=entry, code at +12 */
static void stage_native(uint32_t addr, const uint8_t *code, uint32_t len,
                         uint32_t entry) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint8_t *p = (volatile uint8_t *)(addr + 12u);
    a[0] = len;
    a[1] = PEND_NATIVE;
    a[2] = entry;
    for (uint32_t i = 0; i < len; i++) p[i] = code[i];
    a[0x208u / 4u] = PROG_PEND_MAGIC;
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
        stage_pend(PROG_PEND_ADDR, badstat_ins, 1u);
        hot_swap();
        if (STATUS[S_HREJ] != 1u || STATUS[S_HLOAD] != 0u ||
            MON_PROG_CNT[0] != pass_all_cnt) ok = 0;
        stage_pend(PROG_PEND_ADDR, badrun_ins, 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u || MON_PROG_CNT[0] != 1u ||
            MON_PROG_B_CNT[0] != pass_all_cnt) ok = 0;
    } else if (state == 1) {
        state = 2;
        /* the round ran the bad program: one strike, rolled back */
        ok = STATUS[S_ROLL] == 1u && MON_PROG_CNT[0] == pass_all_cnt &&
             MON_PROG_B_CNT[0] == 0u && MON_PROG_FAULT[0] == 0u;
    } else if (state == 2) {
        state = 3;
        ok = verdicts_ok() && STATUS[S_HLOAD] == 1u &&
             STATUS[S_HREJ] == 1u && STATUS[S_ROLL] == 1u;
        /* eBPF path closed: now hot-load the native variant module —
         * its proof word 0xC0DE0003 must replace the demo's 0xC0DE0002 */
        stage_native(PROG_PEND_ADDR, _binary_native_variant_qemu_bin_start,
                     (uint32_t)(_binary_native_variant_qemu_bin_end
                                - _binary_native_variant_qemu_bin_start), 0u);
        hot_swap();
        if (STATUS[S_HLOAD] != 2u) ok = 0;
    } else if (state == 3) {
        state = 4;
        ok = STATUS[S_NAT2] == 0xC0DE0003u;
        /* the fetch-fault variant: auipc t0,0; jalr x0,0x1000(t0) —
         * lands in NAT_SRAM where X is denied; target-independent */
        {
            static uint8_t badnat[0x1F0u];
            uint32_t len = (uint32_t)(_binary_native_variant_qemu_bin_end
                                      - _binary_native_variant_qemu_bin_start);
            for (uint32_t i = 0; i < len; i++)
                badnat[i] = _binary_native_variant_qemu_bin_start[i];
            badnat[0] = 0x97; badnat[1] = 0x02; badnat[2] = 0x00; badnat[3] = 0x00;
            badnat[4] = 0x67; badnat[5] = 0x80; badnat[6] = 0x02; badnat[7] = 0x10;
            stage_native(PROG_PEND_ADDR, badnat, len, 0u);
        }
        hot_swap();
        if (STATUS[S_HLOAD] != 3u) ok = 0;
    } else if (state == 4) {
        state = 5;
        /* the bad native was evicted at phase 5: nat2 reads zero this
         * round, the shadow (variant) is restored for the next one */
        ok = STATUS[S_ROLL] == 2u && STATUS[S_NAT2] == 0u;
    } else {
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_HLOAD] == 3u &&
             STATUS[S_HREJ] == 1u && STATUS[S_ROLL] == 2u && verdicts_ok();
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
    stage_boot(PROG_AREA, pass_all_ins, pass_all_cnt);
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
