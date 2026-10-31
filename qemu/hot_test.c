/* QEMU hot-swap acceptance: the runtime program path must reject a
 * statically-bad image without disturbing the schedule, promote a
 * statically-legal one, and roll back to last-known-good after its first
 * interpreter fault. The native path follows the slot table (E22): an
 * install remaps the exec window, a fault evicts the slot and the
 * boundary remaps to the other resident image. Nine rounds, then one
 * verdict line: == HOT PASS == / == HOT FAIL ==
 * Round 1: pass_all loaded at boot, verdicts [1 1 0 1 1 1].
 * Round 2: pass_all rejected (bad opcode), mov-to-r10 promoted — it is
 *          static-legal on purpose (the verifier allows r10 as dst; the
 *          program itself is well-formed with a proper exit; the
 *          interpreter faults FP at run) — the round faults, the
 *          supervisor rolls back to the shadow.
 * Round 3: pass_all restored from the shadow, verdicts return.
 * Round 4: variant installed into slot 0 (remap drill ran); proof
 *          0xC0DE0003 replaces the demo's 0xC0DE0002.
 * Round 5: fetch-fault variant installed into slot 1; slot 0 still holds
 *          the good variant.
 * Round 6: slot 1 faults at phase 5: the evicted round produces no
 *          proof (nat2 reads zero), the boundary remapped to slot 0.
 * Round 7: slot 0 runs, proof returns — the rollback was the remap.
 * Round 8: slot 1 revived with its good variant; then slot 0 poisoned,
 *          evicted at phase 5, boundary remaps back to slot 1.
 * Round 9: cumulative verdict. */

#include <stdint.h>
#include "../core/platform.h"
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
void qemu_exit(int code);

static const uint32_t want[6] = { 1, 1, 0, 1, 1, 1 };
static const uint64_t badstat_ins[] = { 0xdeadbeefdeadbeefULL };
/* static-legal, run-time fatal: writes r10 (allowed by the verifier, FP
 * fault at run), then exits properly — the register gate demands the
 * well-formed tail */
static const uint64_t badrun_ins[] = { EBPF_ENC(0xb7, 10, 0, 0, 1),
                                       EBPF_ENC(0xb7, 0, 0, 0, 1),
                                       EBPF_ENC(0x95, 0, 0, 0, 0) };

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
    trust_stamp((volatile uint8_t *)addr, 8u + cnt * 8u);
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;                 /* lands last */
}

extern const uint8_t _binary_native_variant_qemu_bin_start[];
extern const uint8_t _binary_native_variant_qemu_bin_end[];
extern const uint8_t _binary_native_variant_s1_qemu_bin_start[];
extern const uint8_t _binary_native_variant_s1_qemu_bin_end[];
extern const uint8_t _binary_native_trap_s1_qemu_bin_start[];
extern const uint8_t _binary_native_trap_s1_qemu_bin_end[];
extern const uint8_t _binary_native_trap_qemu_bin_start[];
extern const uint8_t _binary_native_trap_qemu_bin_end[];

/* native PEND image: [0]=len, [1]=kind, [2]=entry, [3]=slot, code at +16 */
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

/* the hostile payload is now a signed module (native_trap): it fetches
 * +0x1000 into the SRAM window where X is denied — identity proven by
 * the trust gate, safety still the PMP's job */
static uint32_t badnat(const uint8_t *src, uint32_t len, uint32_t slot) {
    stage_native(PROG_PEND_ADDR, src, len, 0u, slot);
    return len;
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
        stage_pend(PROG_PEND_ADDR, badrun_ins, 3u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u || MON_PROG_CNT[0] != 3u ||
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
        /* eBPF path closed: now hot-load the native variant module into
         * slot 0 — its proof word 0xC0DE0003 must replace the demo's
         * 0xC0DE0002, and the remap drill must have run */
        stage_native(PROG_PEND_ADDR, _binary_native_variant_qemu_bin_start,
                     (uint32_t)(_binary_native_variant_qemu_bin_end
                                - _binary_native_variant_qemu_bin_start),
                     0u, 0u);
        hot_swap();
        if (STATUS[S_HLOAD] != 2u || STATUS[S_NSLOT] != 0u ||
            STATUS[S_REMAP] == 0u || STATUS[S_REMAP] > 1000u) ok = 0;
    } else if (state == 3) {
        state = 4;
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_NSLOT] == 0u;
        /* the fetch-fault variant into slot 1: slot 0 keeps the good
         * image as last-known-good */
        badnat(_binary_native_trap_s1_qemu_bin_start,
               (uint32_t)(_binary_native_trap_s1_qemu_bin_end
                          - _binary_native_trap_s1_qemu_bin_start), 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 3u || STATUS[S_NSLOT] != 1u) ok = 0;
    } else if (state == 4) {
        state = 5;
        /* slot 1 was evicted at phase 5: nat2 reads zero this round and
         * the boundary remapped to slot 0 */
        ok = STATUS[S_NAT2] == 0u && STATUS[S_NSLOT] == 0u &&
             STATUS[S_ROLL] == 2u;
    } else if (state == 5) {
        state = 6;
        /* slot 0 ran: proof returns — the rollback was the remap */
        ok = STATUS[S_NAT2] == 0xC0DE0003u && verdicts_ok();
        /* revive slot 1 with its good variant: the install is a fresh
         * lifetime, so the eviction is cleared and it goes live */
        stage_native(PROG_PEND_ADDR, _binary_native_variant_s1_qemu_bin_start,
                     (uint32_t)(_binary_native_variant_s1_qemu_bin_end
                                - _binary_native_variant_s1_qemu_bin_start),
                     0u, 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 4u || STATUS[S_NSLOT] != 1u) ok = 0;
    } else if (state == 6) {
        state = 7;
        /* slot 1 ran its own image: proof from NAT2_SRAM */
        ok = STATUS[S_NAT2] == 0xC0DE0003u && verdicts_ok();
        /* now poison slot 0: install clears its eviction and goes live */
        badnat(_binary_native_trap_qemu_bin_start,
               (uint32_t)(_binary_native_trap_qemu_bin_end
                          - _binary_native_trap_qemu_bin_start), 0u);
        hot_swap();
        if (STATUS[S_HLOAD] != 5u || STATUS[S_NSLOT] != 0u) ok = 0;
    } else if (state == 7) {
        state = 8;
        /* slot 0 evicted, remap back to slot 1 (variant_s1 resident) */
        ok = STATUS[S_NAT2] == 0u && STATUS[S_NSLOT] == 1u &&
             STATUS[S_ROLL] == 3u;
    } else {
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_HLOAD] == 5u &&
             STATUS[S_HREJ] == 1u && STATUS[S_ROLL] == 3u &&
             STATUS[S_NSLOT] == 1u && verdicts_ok();
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
