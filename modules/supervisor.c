
#include <stdint.h>
#include "../core/contract.h"
#include "../core/compartment.h"
#include "../core/loader.h"
#include "../core/uart.h"
#include "../descriptions/demo.h"
#include "policies/mavlink.h"
#include "policies/screening.h"
#include "../core/platform.h"

#define MO_SHU  0x5741524Du
#define MAX_SWARM 64u
#ifdef QEMU_TARGET
#include "../qemu/report.h"
#endif


extern void trap_entry(void);
extern void supervisor_resume(void);
extern void supervisor_fault(uint32_t yuanyin, uint32_t zhi);
extern void monitor_entry(void);
extern void attacker_entry(void);
extern void attacker_v1(void);
extern void attacker_v2(void);
extern void attacker_v3(void);
extern void attacker_v4(void);
extern void attacker_v5(void);
extern void attacker_v6(void);
extern char trap_sp0_top[];       /* M-mode fault scratch stack, from trap.S */
extern void *memcpy(void *dst, const void *src, unsigned int n);

volatile uint32_t g_ri_index = 0;
volatile uint32_t g_ri_cause[8];
volatile uint32_t g_ri_addr[8];
static volatile uint32_t g_phase = 1;
static volatile uint32_t g_input_sum = 0;
static volatile uint32_t g_stk0 = 0;
static volatile uint32_t g_alerts = 0;
static volatile uint32_t g_conflict_n = 0;
static volatile uint32_t g_source = 0;
static volatile uint32_t g_atk_vec = 0;   /* attacker lifetime in flight */

static void enter_checked(unsigned i);
static void schedule_round(void);
static void heartbeat(void);

__attribute__((noinline))
static void heartbeat(void) {
    STATUS[3]++;
    for (volatile int k = 0; k < 20000; ++k) __asm__ volatile ("nop");
}

static void csr_write(unsigned csr, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n" (csr), "r" (v) : "memory");
}

static uint32_t input_sum(void) {
    uint32_t s = 0;
    for (int i = 0; i < 6; i++) {
        uint32_t sz = MON_SIZES[i];
        for (uint32_t j = 0; j < sz; j++) s += MON_INPUT[MON_OFF[i] + j];
    }
    return s;
}

static const uint8_t SWARM_LON33[4] = { 0x60, 0x2E, 0x36, 0x07 };
static const uint8_t SWARM_LON34[4] = { 0xC2, 0xBC, 0xEB, 0x00 };

/* boot gate: shipped descriptions must be well-formed and must match the
 * map the PMP is about to get. Run before any phase, fail closed. */
static uint32_t spec_match(const ic_compartment_spec *a,
                           const ic_compartment_spec *b) {
    return a->text_base == b->text_base && a->text_size == b->text_size &&
           a->sram_base == b->sram_base && a->sram_size == b->sram_size;
}

static uint32_t boot_gate(void) {
    const ic_compartment_spec mon = { MON_TEXT, 8192u, MON_BOX, 8192u };
    const ic_compartment_spec atk = { ATK_TEXT, 8192u, ATK_BOX, 8192u };
    if (ic_compartment_check(&ic_comp_monitor) != IC_OK) return 1u;
    if (ic_compartment_check(&ic_comp_attacker) != IC_OK) return 2u;
    if (ic_module_check(&ic_module_monitor) != IC_OK) return 3u;
    if (ic_module_check(&ic_module_attacker) != IC_OK) return 4u;
    if (ic_module_check(&ic_module_mavlink) != IC_OK) return 5u;
    if (ic_module_check(&ic_module_screening) != IC_OK) return 6u;
    if (!spec_match(&ic_comp_monitor, &mon)) return 7u;
    if (!spec_match(&ic_comp_attacker, &atk)) return 8u;
    if (ic_compartment_check(&ic_comp_native) != IC_OK) return 9u;
    if (ic_module_check(&ic_module_nativedemo) != IC_OK) return 10u;
    {
        const ic_compartment_spec nat = { NAT_TEXT, 0x1000u, NAT_SRAM, 0x1000u };
        if (!spec_match(&ic_comp_native, &nat)) return 11u;
    }
    return 0u;
}

/* boot-time program load: external bytes in the program area pass the same
 * gates as compiled-in modules, then land in the monitor slot. No magic
 * means no load was attempted; a failed gate falls back to the built-in
 * policy and records why — external input never parks the device. */
static void load_program(void) {
    const volatile uint32_t *area = (const volatile uint32_t *)PROG_AREA;
    uint32_t cnt;
    MON_PROG_CNT[0] = 0u;
    MON_PROG_B_CNT[0] = 0u;      /* shadow starts empty every boot */
    MON_PROG_FAULT[0] = 0u;
    STATUS[S_LOAD] = 0u;
    if (area[0] != PROG_MAGIC) return;
    cnt = area[1];
    if (!cnt || cnt > IC_PROG_MAX_INSNS) { STATUS[S_LOAD] = 2u; return; }
    {
        ic_module_desc d = { IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                             IC_MODULE_EBPF, (uint32_t)MON_PROG, cnt * 8u,
                             0u, 0u, 0u, 0u };
        if (ic_module_check(&d) != IC_OK) { STATUS[S_LOAD] = 3u; return; }
    }
    {
        const volatile uint8_t *src = (const volatile uint8_t *)PROG_AREA + 8u;
        volatile uint64_t *slot = MON_PROG;
        for (uint32_t i = 0; i < cnt; i++) {
            uint64_t v = 0;
            for (int b = 7; b >= 0; b--)
                v = (v << 8) | src[i * 8u + (uint32_t)b];
            slot[i] = v;
        }
    }
    if (ic_program_check((const uint64_t *)MON_PROG, cnt) != IC_OK) {
        STATUS[S_LOAD] = 4u;
        return;
    }
    MON_PROG_CNT[0] = cnt;
    STATUS[S_LOAD] = 1u;
}

/* a console frame, if one arrives during the boot window, stages the
 * program image and only then commits it to PROG_AREA; a bad frame never
 * touches what is already there. The gates stay in load_program. */
static void uart_load(void) {
    uint8_t *stage = (uint8_t *)PROG_AREA + 0x400u;
    uint32_t n = uart_recv(stage, UART_FRAME_MAX);
    volatile uint8_t *dst = (volatile uint8_t *)PROG_AREA;
    for (uint32_t i = 0; i < n; i++) dst[i] = stage[i];
}

void boot_main(void) {
    uint32_t gate = boot_gate();
    if (gate) {
        STATUS[S_GATE] = 0xC0DE0000u | gate;
#ifdef QEMU_TARGET
        uart_puts("== GATE FAIL ");
        uart_putdec(gate);
        uart_puts(" ==\n");
        for (;;) qemu_exit(1);
#else
        for (;;) heartbeat();
#endif
    }
    STATUS[S_GATE] = 0xC0DE0000u;
    csr_write(0x340, (uint32_t)trap_sp0_top);   /* mscratch: fault scratch */
    STATUS[0] = 0xDEADBEEFu;
    STATUS[1] = 0xC0DE0008u;
    {
        volatile char *q = STATUS_NAME;
        const char *msg = "PMP-EBPF-3";
        while (*msg) *q++ = *msg++;
        *q = 0;
    }
    TIMER_INIT();
    uart_init();
    uart_puts("interclus\n");
    {
        /* TX timing self-test: 64 bytes on the wire, paced by the
         * peripheral at the programmed baud; STK measures the truth */
        uint32_t t0 = TIMER_NOW();
        for (int i = 0; i < 64; i++) uart_putc('U');
        STATUS[S_UTX] = TIMER_NOW() - t0;
    }
#ifndef QEMU_TARGET
    {
        /* loopback proof: needs PA9 wired to PA10, else times out to 0 */
        uint32_t t0 = TIMER_NOW();
        uint32_t ok = 1;
        for (int i = 0; i < 64 && ok; i++) {
            int c;
            for (;;) {
                c = uart_getc();
                if (c >= 0) break;
                if (TIMER_NOW() - t0 > 400000u) { ok = 0; break; }
            }
            if (ok && c != 'U') ok = 0;
        }
        STATUS[S_URX] = ok;
    }
#endif
    uart_load();
    load_program();

    csr_write(0x305, (uint32_t)trap_entry);
    schedule_round();
}

/* one schedule pass: refresh the monitor's inputs from the mailbox, wire
 * all three compartments fresh, and enter the monitor. boot_main does this
 * after the gates; hot_round does it alone — the schedule re-runs without
 * a reboot, which is the whole point of the hot path. */
__attribute__((noinline))
static void schedule_round(void) {
    {
        uint32_t off = 0;
        const uint8_t *bao[6] = { PKT_GPI, PKT_HB, PKT_BADMAGIC,
                                   PKT_BADMSGID, PKT_BIGLEN, PKT_BADLAT };
        const uint32_t sizes[6] = { sizeof(PKT_GPI), sizeof(PKT_HB),
                                    sizeof(PKT_BADMAGIC), sizeof(PKT_BADMSGID),
                                    sizeof(PKT_BIGLEN), sizeof(PKT_BADLAT) };
        for (int i = 0; i < 6; i++) {
            MON_OFF[i] = off;
            MON_SIZES[i] = sizes[i];
            for (uint32_t j = 0; j < sizes[i]; j++) MON_INPUT[off + j] = bao[i][j];
            off += sizes[i];
        }
    }

    g_conflict_n = 0;
    if (MAILBOX[0] == MO_SHU && MAILBOX[1] >= 1u && MAILBOX[1] <= MAX_SWARM) {
        g_conflict_n = MAILBOX[1];
        for (uint32_t i = 0; i < g_conflict_n; i++) {
            MON_SOFF[i] = i * 42u;
            MON_SSIZES[i] = 42u;
            for (uint32_t j = 0; j < 42u; j++)
                MON_DATA[i * 42u + j] = MB_DATA[i * 42u + j];
        }
        g_source = 1;
    } else {
        g_conflict_n = 8;
        for (uint32_t i = 0; i < 8; i++) {
            MON_SOFF[i] = i * 42u;
            MON_SSIZES[i] = 42u;
            for (uint32_t j = 0; j < 10u; j++)
                MON_DATA[i * 42u + j] = PKT_GPI[j];
            MON_DATA[i * 42u + 10u] = 0x80;
            MON_DATA[i * 42u + 11u] = 0x2F;
            MON_DATA[i * 42u + 12u] = 0x77;
            MON_DATA[i * 42u + 13u] = 0x12;
            const uint8_t *lon = (i < 4) ? SWARM_LON33 : SWARM_LON34;
            for (uint32_t j = 0; j < 4u; j++)
                MON_DATA[i * 42u + 14u + j] = lon[j];
            for (uint32_t j = 18u; j < 42u; j++)
                MON_DATA[i * 42u + j] = PKT_GPI[j];
        }
        g_source = 0;
    }
    MON_CONFN[0] = g_conflict_n;
    for (uint32_t c = 0; c < MAP_CELLS; c++) MON_MAP[c] = 0;

    compartment_set(0u, &ic_comp_monitor, (uint32_t)monitor_entry - MON_TEXT);
    compartment_set(1u, &ic_comp_attacker, (uint32_t)attacker_entry - ATK_TEXT);
    compartment_set(2u, &ic_comp_native, 0u);
    {
        extern const uint8_t _binary_native_demo_bin_start[];
        extern const uint8_t _binary_native_demo_bin_end[];
        const uint8_t *src = _binary_native_demo_bin_start;
        volatile uint8_t *dst = (volatile uint8_t *)NAT_TEXT;
        while (src < _binary_native_demo_bin_end) *dst++ = *src++;
    }
    compartment_arm(0u);
    g_phase = 1;
    MON_MODE[0] = 0u;
    g_stk0 = TIMER_NOW();
    enter_checked(0u);
}

#ifdef QEMU_TARGET
void supervisor_reset(void) {
#else
void supervisor_reset(void) {
#endif
    g_phase = 1;
    g_input_sum = 0;
    g_stk0 = 0;
    g_alerts = 0;
    g_conflict_n = 0;
    g_source = 0;
    g_atk_vec = 0;
    g_ri_index = 0;
    for (int i = 0; i < 8; i++) { g_ri_cause[i] = 0; g_ri_addr[i] = 0; }
}

/* contract v1.1 hot path: a transport stages an image at PROG_PEND under
 * PROG_PEND_MAGIC; between rounds it must pass the same gates as a boot
 * image before it may replace the live program. The live image moves to
 * the shadow slot as last-known-good. A rejected image is consumed and
 * recorded — the running schedule is never touched. */
void hot_swap(void) {
    volatile uint32_t *pend = (volatile uint32_t *)PROG_PEND_ADDR;
    const volatile uint8_t *src;
    uint32_t cnt, i;
    int b;
    if (pend[0] != PROG_PEND_MAGIC) return;
    cnt = pend[1];
    if (!cnt || cnt > IC_PROG_MAX_INSNS) { STATUS[S_HREJ]++; pend[0] = 0u; return; }
    {
        ic_module_desc d = { IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                             IC_MODULE_EBPF, (uint32_t)MON_PROG, cnt * 8u,
                             0u, 0u, 0u, 0u };
        if (ic_module_check(&d) != IC_OK ||
            ic_program_check((const uint64_t *)(PROG_PEND_ADDR + 8u), cnt) != IC_OK) {
            STATUS[S_HREJ]++; pend[0] = 0u; return;
        }
    }
    MON_PROG_B_CNT[0] = MON_PROG_CNT[0];              /* live -> shadow */
    memcpy((void *)MON_PROG_B, (void *)MON_PROG, 512u);
    src = (const volatile uint8_t *)PROG_PEND_ADDR + 8u;
    for (i = 0; i < cnt; i++) {                       /* staged -> live */
        uint64_t v = 0;
        for (b = 7; b >= 0; b--) v = (v << 8) | src[i * 8u + (uint32_t)b];
        MON_PROG[i] = v;
    }
    MON_PROG_CNT[0] = cnt;
    MON_PROG_FAULT[0] = 0u;
    pend[0] = 0u;                                     /* consumed */
    STATUS[S_HLOAD]++;
}

/* re-run the schedule without a reboot: same compartments, current live
 * program. The box slots (live/shadow) persist; phase and forensics state
 * start clean. This is the runtime half of hot loading. */
void hot_round(void) {
    supervisor_reset();
    schedule_round();
}

/* the schedule must never hand the CPU to an evicted lifetime: refuse
 * loudly (gate-style heartbeat, visible in a dump) instead of parking the
 * core silently inside the mechanism's fail-stop */
static void enter_checked(unsigned i) {
    if (compartment_evicted(i)) {
        for (;;) heartbeat();
    }
    compartment_enter(i);
}

static void (*const atk_vec[7])(void) = {
    attacker_entry, attacker_v1, attacker_v2, attacker_v3,
    attacker_v4, attacker_v5, attacker_v6
};

static void atk_schedule(unsigned v) {
    compartment_set(1u, &ic_comp_attacker,
                    (uint32_t)atk_vec[v] - ATK_TEXT);   /* fresh lifetime */
    compartment_arm(1u);
    enter_checked(1u);
}

static void atk_advance(void) {
    uint32_t v = g_atk_vec;
    if (v == 0u) STATUS[S_OWNOOK] = (*ATK_OWN == 0xBEEF5EEDu);
    if (v == 6u) STATUS[S_RDROK] = (*ATK_PROOF == 0x5EEDC0DEu);
    g_atk_vec = v + 1u;
    if (g_atk_vec < 7u) atk_schedule(g_atk_vec);

    /* all seven lifetimes ran: finalize, then the native compartment */
    static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };
    uint32_t vok = 1, iok = (input_sum() == g_input_sum);
    for (int i = 0; i < 6; i++) {
        if (MON_VERDICTS[i] != want[i] || STATUS[S_CAIJUE + i] != want[i]) vok = 0;
    }
    STATUS[S_VINTACT] = vok;
    STATUS[S_IINTACT] = iok;
    STATUS[S_INTER] = g_ri_index;
    for (int i = 0; i < 5; i++) {
        STATUS[S_LOG0C + i * 2] = g_ri_cause[i];
        STATUS[S_LOG0C + 1 + i * 2] = g_ri_addr[i];
    }
    STATUS[S_NAT2] = 0u;
    g_phase = 5;
    enter_checked(2u);
}

static void native_done(void) {
    STATUS[S_NAT2] = *(volatile uint32_t *)NAT_SRAM;
    STATUS[S_DONE] = 0x600DF00Du;

#ifdef QEMU_TARGET
    report();
    __asm__ volatile ("j sweep_next");   /* no caller frame: jump, don't return */
#else
    uart_puts("\nverdicts:");
    for (int i = 0; i < 6; i++) {
        uart_puts(" ");
        uart_putdec(STATUS[S_CAIJUE + i]);
    }
    uart_puts("\n");
    {
        /* service loop: poll the staging area, and on a promotion re-run
         * the whole schedule against the new program — the board stays
         * live across swaps */
        uint32_t seen = STATUS[S_HLOAD];
        for (;;) {
            hot_swap();
            if (STATUS[S_HLOAD] != seen) {
                seen = STATUS[S_HLOAD];
                hot_round();             /* noreturn: re-enters here */
            }
            heartbeat();
        }
    }
#endif
}

/* U-mode fault resume (contract v1.1): the running compartment's first
 * fault ends its lifetime. The trap path already saved the frame into the
 * TCB, wiped the register file, and logged mcause/mtval in the ring. */
void supervisor_fault(uint32_t yuanyin, uint32_t zhi) {
    (void)yuanyin; (void)zhi;
    compartment_evict(cur_comp);
    if (g_phase == 4) {
        atk_advance();
    } else if (g_phase >= 5) {
        native_done();               /* evicted native: nat2 stays 0 */
    } else {
        for (;;) heartbeat();        /* monitor fault: fail-stop */
    }
}

void supervisor_resume(void) {
    if (g_phase == 1) {                       
        uint32_t cyc = TIMER_NOW() - g_stk0;
        for (int i = 0; i < 6; i++) {
            STATUS[S_CAIJUE + i] = MON_VERDICTS[i];
            STATUS[S_INSNS + i] = MON_INSNS[i];
        }
        STATUS[S_CYC0] = cyc;
        g_input_sum = input_sum();
        /* the live program just had a round: an interpreter fault here is
         * a one-strike rollback to the shadow (last-known-good), or to the
         * built-in policy when no shadow exists */
        if (MON_PROG_CNT[0] && MON_PROG_FAULT[0]) {
            if (MON_PROG_B_CNT[0]) {
                memcpy((void *)MON_PROG, (void *)MON_PROG_B, 512u);
                MON_PROG_CNT[0] = MON_PROG_B_CNT[0];
                MON_PROG_B_CNT[0] = 0u;
            } else {
                MON_PROG_CNT[0] = 0u;
            }
            MON_PROG_FAULT[0] = 0u;
            STATUS[S_ROLL]++;
        }
        compartment_arm(0u);
        g_phase = 2;
        MON_MODE[0] = 1u;
        g_stk0 = TIMER_NOW();
        enter_checked(0u);
    } else if (g_phase == 2) {                
        uint32_t cyc = TIMER_NOW() - g_stk0;
        uint32_t alerts = 0;
        for (uint32_t i = 0; i < g_conflict_n && i < 8u; i++) {
            STATUS[S_BAN_CAIJUE + i] = MON_SCREEN_VERD[i];
            STATUS[S_CINSNS + i] = MON_SCREEN_INSNS[i];
        }
        for (uint32_t i = 0; i < g_conflict_n; i++) {
            if (MON_SCREEN_VERD[i] == 5u) alerts++;
        }
        g_alerts = alerts;
        STATUS[S_CYC1] = cyc;
        STATUS[S_JINGBAO] = g_alerts;
        STATUS[S_CHONGTU_N] = g_conflict_n;
        STATUS[S_LAIYUAN] = g_source;
        compartment_arm(0u);
        g_phase = 3;
        MON_MODE[0] = 2u;
        g_stk0 = TIMER_NOW();
        enter_checked(0u);
    } else if (g_phase == 3) {                
        uint32_t cyc = TIMER_NOW() - g_stk0;
        static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };
        uint32_t natok = 1;
        for (int i = 0; i < 6; i++) {
            if (MON_NATIVE_VERD[i] != want[i]) natok = 0;
        }
        STATUS[S_CYC2] = cyc;
        STATUS[S_NATOK] = natok;
        g_phase = 4;
        g_atk_vec = 0;
        atk_schedule(0u);
    } else if (g_phase == 4) {             /* an attacker lifetime yielded */
        atk_advance();
    } else {
        native_done();
    }
}
