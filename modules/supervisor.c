
#include <stdint.h>
#include "../core/contract.h"
#include "../core/compartment.h"
#include "../core/loader.h"
#include "../core/uart.h"
#include "../descriptions/demo.h"
#include "policies/mavlink.h"
#include "policies/screening.h"
#include "../core/update.h"
extern int flash_mirror_write(uint32_t slot, const uint8_t *code,
                              uint32_t len, uint32_t entry);
extern uint32_t flash_mirror_read(uint32_t slot, uint8_t *out,
                                  uint32_t cap, uint32_t *entry);
void sha256(const uint8_t *data, uint32_t len, uint8_t out[32]);
#include "../core/platform.h"

#define MO_SHU  0x5741524Du
#define MAX_SWARM 64u
/* a compartment's slice: overrunning this is a strike, exactly like a
 * fault (v1.1 has no pause/resume, so the overrunner is evicted) */
#define BUDGET_TICKS 2000000u
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

/* E22 native slot table: two resident modules, one PMP exec window. The
 * schedule boundary remaps the window onto whichever entry is live; a
 * faulting slot is evicted in the table and the boundary remaps to the
 * other one (its image is the last-known-good module). Both dead means
 * the native phase retires for the session — the schedule continues. */
struct nat_slot {
    uint32_t len;      /* image bytes in the slot, 0 = empty */
    uint32_t entry;    /* entry offset into the slot */
    uint32_t valid;    /* an image has been installed */
    uint32_t evicted;  /* v1.1: faulted once, never scheduled again */
};
static struct nat_slot g_nat[2];
static uint32_t g_nat_live;     /* slot index wired into compartment 2 */
static uint32_t g_nat_retired;  /* no runnable native slot left */
static update_rx g_update;
static uint32_t g_update_hload;
static uint32_t g_update_hrej;
static void update_send_reply(const update_reply *r);

extern const uint8_t _binary_native_demo_bin_start[];
extern const uint8_t _binary_native_demo_bin_end[];

static void enter_checked(unsigned i);
static void schedule_round(void);
static void heartbeat(void);
static void native_done(uint32_t proof);

/* the spec of native slot k, straight from the map */
static void nat_spec(uint32_t k, ic_compartment_spec *s) {
    s->text_base = k ? NAT2_TEXT : NAT_TEXT;
    s->text_size = 0x1000u;
    s->sram_base = k ? NAT2_SRAM : NAT_SRAM;
    s->sram_size = 0x1000u;
}

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
        /* the generated spec pins slot 0; slot 1 is derived from the map */
        ic_compartment_spec nat, nat2;
        nat_spec(0u, &nat);
        nat_spec(1u, &nat2);
        if (!spec_match(&ic_comp_native, &nat)) return 11u;
        if (ic_compartment_check(&nat2) != IC_OK) return 12u;
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
    STATUS[S_HLOAD] = 0u;        /* hot-path counters start clean too —
                                    the STATUS window is raw RAM, and a
                                    counter incrementing from stale junk
                                    reads as chaos in a dump */
    STATUS[S_HREJ] = 0u;
    STATUS[S_ROLL] = 0u;
    STATUS[S_REARM] = 0u;
    STATUS[S_PREEMPT] = 0u;
    STATUS[S_TXABORT] = 0u;
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
    {   /* the STATUS window is raw SRAM: boot owns it, so every field
         * starts the session at zero — no retained junk reads as live */
        for (unsigned i = 0; i < STATUS_WORDS; i++) STATUS[i] = 0u;
    }
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
    WDT_ARM();                     /* past the gate: runtime fails reboots */
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
    BUDGET_INIT();
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
    WDT_FEED();
    /* Boot is the one true transport reset: no half-finished transaction
     * and no stale PEND image may survive into the new session. */
    update_reset(&g_update);
    g_update_hload = 0;
    g_update_hrej = 0;
    PROG_PEND_OK[0] = 0u;

    {   /* E33: the verifier meets random images at boot — every round
         * must return a verdict, never hang the device. The acceptance
         * count is sanity: random 8-insn junk passes rarely. */
        uint32_t st = 0xC0FFEE1u, acc = 0, rej = 0;
        for (uint32_t r = 0; r < 2048u; r++) {
            uint64_t ins[8];
            for (int i = 0; i < 8; i++) {
                st ^= st << 13; st ^= st >> 17; st ^= st << 5;
                ins[i] = (uint64_t)st;
                st ^= st << 13; st ^= st >> 17; st ^= st << 5;
                ins[i] |= (uint64_t)st << 32;
            }
            if (ic_program_check(ins, 8) == IC_OK) acc++; else rej++;
        }
        STATUS[S_FUZZA] = acc;
        STATUS[S_FUZZR] = rej;
    }

    {   /* slot 0 serves the built-in demo blob; the bytes land once —
           U-mode cannot write its own text (PMP R/X), and the rollback
           path remaps instead of restoring bytes */
        g_nat[0].len = (uint32_t)(_binary_native_demo_bin_end
                                  - _binary_native_demo_bin_start);
        memcpy((void *)NAT_TEXT, _binary_native_demo_bin_start,
               g_nat[0].len);
        g_nat[0].entry = 0u;
        g_nat[0].valid = 1u;
        g_nat[0].evicted = 0u;
        g_nat[1].len = 0u; g_nat[1].entry = 0u;
        g_nat[1].valid = 0u; g_nat[1].evicted = 0u;
        g_nat_live = 0u;
        g_nat_retired = 0u;
        /* E25 restore: a mirrored slot comes back as the live module.
         * The bytes are untrusted flash contents, so the descriptor gate
         * runs before the table accepts them; a blank page keeps the
         * built-in demo. */
        for (uint32_t k = 0; k < 2u; k++) {
            uint32_t len = flash_mirror_read(k, (uint8_t *)(k ? NAT2_TEXT
                                                              : NAT_TEXT),
                                             0x1F0u, &g_nat[k].entry);
            if (!len) continue;
            {
                ic_compartment_spec sp;
                ic_module_desc d;
                nat_spec(k, &sp);
                d.magic = IC_MODULE_MAGIC; d.contract_ver = IC_CONTRACT_VERSION;
                d.kind = IC_MODULE_NATIVE; d.text_base = sp.text_base;
                d.text_size = 0x1000u; d.sram_base = sp.sram_base;
                d.sram_size = 0x1000u; d.entry_offset = g_nat[k].entry;
                d.reserved = 0u;
                if (ic_module_check(&d) != IC_OK) {
                    *(volatile uint32_t *)(k ? NAT2_SRAM : NAT_SRAM) = 0u;
                    continue;
                }
            }
            g_nat[k].len = len;
            g_nat[k].valid = 1u;
            g_nat[k].evicted = 0u;
            g_nat_live = k;
        }
    }

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
    {   /* the native window follows the live table entry: the next
           compartment_arm rewrites the PMP pair onto that slot's base —
           the schedule-boundary remap (S_REMAP pins its cost) */
        ic_compartment_spec s;
        nat_spec(g_nat_live, &s);
        compartment_set(2u, &s, g_nat[g_nat_live].entry);
        *(volatile uint32_t *)(g_nat_live ? NAT2_SRAM : NAT_SRAM) = 0u;
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
    /* A schedule round is not a transport reset: an in-flight update must
     * survive unrelated swarm commits and hot rounds. Only boot and ABORT
     * discard transaction state. */
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
 * PROG_PEND_MAGIC (magic lands last); between rounds it must pass the
 * same gates as a boot image before it may go live. Word 1 picks the
 * kind: an eBPF program swaps into the monitor slot (shadowed by the B
 * slot), a native module swaps into NAT_TEXT (shadowed at PROG_NSH). A
 * rejected image is consumed and recorded — the schedule is never
 * touched. */
/* the trust root: digests of the modules this build accepts, computed
 * by tools/sign_module.py over the exact staged bytes. A digest not on
 * this list is a module this firmware has never seen — rejected. */
#include "trusted_digests.h"
#include "../core/layout_asserts.h"
#define TRUSTED_N (sizeof(g_trusted) / sizeof(g_trusted[0]))

/* E26 gate: the staged image is [header..payload][32-byte digest].
 * Recompute over everything before the digest; mismatch = tampered in
 * transit. Digest not pinned = unknown module. Both reject. */
static int trust_check(const uint8_t *img, uint32_t body,
                       const uint8_t *digest) {
    uint8_t calc[32];
    sha256(img, body, calc);
    for (uint32_t k = 0; k < 32u; k++)
        if (calc[k] != digest[k]) return 0;
    for (uint32_t t = 0; t < TRUSTED_N; t++) {
        uint32_t ok = 1u;
        for (uint32_t k = 0; k < 32u; k++)
            if (g_trusted[t][k] != digest[k]) { ok = 0u; break; }
        if (ok) return 1;
    }
    return 0;
}

void hot_swap(void) {
    volatile uint32_t *pend = (volatile uint32_t *)PROG_PEND_ADDR;
    uint32_t w0, kind, i;
    if (PROG_PEND_OK[0] != PROG_PEND_MAGIC) return;   /* magic lands last */
    w0 = pend[0];
    kind = pend[1];
    {
        /* the trailer digest rides after the payload; recompute over
         * everything before it, then require it pinned */
        uint32_t body;
        /* Validate the discriminant and multiply only after the bounded
         * count check; malformed w0 must not wrap into the trust window. */
        if (kind == PEND_NATIVE) {
            if (!w0 || w0 > 0x1F0u) goto rej;
            body = 16u + w0;
        } else if (kind == PEND_EBPF) {
            if (!w0 || w0 > IC_PROG_MAX_INSNS) goto rej;
            body = 8u + w0 * 8u;
        } else {
            goto rej;
        }
        if (body > PROG_PEND_MAGIC_OFF - 8u - SHA256_LEN || body < 16u) goto rej;
        if (!trust_check((const uint8_t *)PROG_PEND_ADDR, body,
                         (const uint8_t *)PROG_PEND_ADDR + body)) goto rej;
    }
    if (kind == PEND_NATIVE) {
        uint32_t entry = pend[2];
        uint32_t slot = pend[3];
        ic_module_desc d;
        ic_compartment_spec s;
        if (!w0 || w0 > 0x1F0u || (entry & 1u) || entry >= 0x1000u ||
            slot > 1u) goto rej;
        nat_spec(slot, &s);
        d.magic = IC_MODULE_MAGIC; d.contract_ver = IC_CONTRACT_VERSION;
        d.kind = IC_MODULE_NATIVE; d.text_base = s.text_base;
        d.text_size = 0x1000u;
        d.sram_base = s.sram_base; d.sram_size = 0x1000u;
        d.entry_offset = entry; d.reserved = 0u;
        if (ic_module_check(&d) != IC_OK) goto rej;
        memcpy((void *)s.text_base,
               (const void *)(PROG_PEND_ADDR + 16u), w0);  /* staged -> slot */
        STATUS[S_FPROG] = (uint32_t)flash_mirror_write(
            slot, (const uint8_t *)(PROG_PEND_ADDR + 16u), w0, entry);
        g_nat[slot].len = w0;
        g_nat[slot].entry = entry;
        g_nat[slot].valid = 1u;
        g_nat[slot].evicted = 0u;      /* an install is a fresh lifetime */
        g_nat_live = slot;
        g_nat_retired = 0u;
        STATUS[S_NSLOT] = slot;        /* visible immediately, not only at
                                          the next phase boundary */
        {   /* remap drill: rewrite the exec pair onto the new base now —
             * the same CSR sequence the schedule boundary repeats */
            uint32_t t0 = TIMER_NOW();
            compartment_set(2u, &s, entry);
            compartment_arm(2u);
            STATUS[S_REMAP] = TIMER_NOW() - t0;
        }
    } else if (kind == PEND_EBPF) {
        volatile uint64_t *s = (volatile uint64_t *)(PROG_PEND_ADDR + 8u);
        ic_module_desc d;
        if (!w0 || w0 > IC_PROG_MAX_INSNS) goto rej;
        d.magic = IC_MODULE_MAGIC; d.contract_ver = IC_CONTRACT_VERSION;
        d.kind = IC_MODULE_EBPF; d.text_base = (uint32_t)MON_PROG;
        d.text_size = w0 * 8u;
        d.sram_base = 0u; d.sram_size = 0u;
        d.entry_offset = 0u; d.reserved = 0u;
        if (ic_module_check(&d) != IC_OK ||
            ic_program_check((const uint64_t *)(PROG_PEND_ADDR + 8u), w0) != IC_OK) {
            goto rej;
        }
        MON_PROG_B_CNT[0] = MON_PROG_CNT[0];              /* live -> shadow */
        memcpy((void *)MON_PROG_B, (void *)MON_PROG, 512u);
        for (i = 0; i < w0; i++) MON_PROG[i] = s[i];      /* staged -> live */
        MON_PROG_CNT[0] = w0;
        MON_PROG_FAULT[0] = 0u;
    } else {
        goto rej;
    }
    PROG_PEND_OK[0] = 0u;                                 /* consumed */
    STATUS[S_HLOAD]++;
    return;
rej:
    STATUS[S_HREJ]++;
    PROG_PEND_OK[0] = 0u;
}

int hot_update_finalize(void) {
    update_reply reply;
    uint32_t hload, hrej;
    int accepted;
    if (g_update.state != UPDATE_STATE_STAGED) return 0;
    hload = STATUS[S_HLOAD];
    hrej = STATUS[S_HREJ];
    if (hload == g_update_hload && hrej == g_update_hrej) return 0;
    accepted = (hload != g_update_hload && hrej == g_update_hrej);
    update_finish(&g_update, accepted);
    reply.id = g_update.id;
    reply.next_seq = g_update.next_seq;
    reply.code = accepted ? UPDATE_ACCEPT : UPDATE_REJECT;
    reply.detail = accepted ? 0u : UPDATE_ERR_STATE;
    update_send_reply(&reply);
    return accepted ? 1 : -1;
}

/* E24 telemetry: fault evidence leaves the device as one frame. slot is
 * the native table entry (0xFF for the eBPF program), the rest is the
 * forensics chain verbatim. */
static void tele_fault(uint32_t slot) {
    uint8_t p[16];
    uint32_t i = g_ri_index ? g_ri_index - 1u : 0u;
    p[0] = (uint8_t)i;
    p[1] = (uint8_t)cur_comp;
    p[2] = (uint8_t)slot;
    for (int k = 0; k < 4; k++) p[4 + k] = (uint8_t)(g_ri_cause[i] >> (8 * k));
    for (int k = 0; k < 4; k++) p[8 + k] = (uint8_t)(g_ri_addr[i] >> (8 * k));
    p[12] = (uint8_t)g_nat_live;
    p[13] = (uint8_t)g_nat_retired;
    /* best effort: a stalled receiver must never park the supervisor
     * inside the eviction path — abandon the frame, the evidence stays
     * in the TCB and the STATUS ring either way */
    if (!uart_send_frame_limited(FRAME_TELE, p, 16u, 50000u))
        STATUS[S_TXABORT]++;
}

/* E21 runtime channel: one console frame per call, non-blocking. The
 * assembler (core/frame.c) owns transport validity — checksum, bounds —
 * so everything here arrived intact; this owns shape and policy:
 *   type 1 — PROG image (boot layout): stages the PEND slot for
 *            hot_swap, which runs the gates. Returns 2.
 *   type 2 — mailbox image (magic, count, 42-byte packets): committed
 *            after the shape check; the next round consumes it as if
 *            the debugger had written it. Returns 1.
 *   type 3 — native PEND image (len, kind, entry, slot, code): staged
 *            verbatim for hot_swap. Returns 2.
 * Anything else is channel noise: dropped, the live state never moves. */
static uint8_t g_chan_stage[8u + 42u * 64u]
    __attribute__((section(".chan_stage")));

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void update_send_reply(const update_reply *r) {
    uint8_t p[10];
    uint16_t crc;
    p[0] = r->code;
    p[1] = (uint8_t)r->id;
    p[2] = (uint8_t)(r->id >> 8);
    p[3] = (uint8_t)(r->id >> 16);
    p[4] = (uint8_t)(r->id >> 24);
    p[5] = (uint8_t)r->next_seq;
    p[6] = (uint8_t)(r->next_seq >> 8);
    p[7] = r->detail;
    crc = update_crc16(p, 8u);
    p[8] = (uint8_t)crc;
    p[9] = (uint8_t)(crc >> 8);
    uart_send_frame_limited(FRAME_UPDATE_REPLY, p, 10u, 50000u);
}

int chan_poll(uart_frame_rx *rx) {
    unsigned n = uart_poll_frame(g_chan_stage, sizeof g_chan_stage, rx);
    if (!n) return 0;
    if (rx->type == FRAME_UPDATE) {
        update_reply reply;
        int accepted = update_process(&g_update, g_chan_stage, n,
                                     (volatile uint8_t *)PROG_PEND_ADDR,
                                     PROG_PEND_OK, &reply);
        update_send_reply(&reply);
        if (accepted && reply.code == UPDATE_REPLY_STAGED) {
            g_update_hload = STATUS[S_HLOAD];
            g_update_hrej = STATUS[S_HREJ];
            return 5;
        }
        return accepted ? 6 : 0;
    }
    if (rx->type == 1u) {
        /* the payload is [PROG header][insns][32-byte digest]; the
         * digest stays in the frame — the gate recomputes over the
         * staged body after the image lands in PEND */
        if (n < 8u + SHA256_LEN || le32(g_chan_stage) != PROG_MAGIC)
            return 0;
        uint32_t cnt = le32(g_chan_stage + 4u);
        if (!cnt || cnt > IC_PROG_MAX_INSNS ||
            n != 8u + cnt * 8u + SHA256_LEN) return 0;
        volatile uint32_t *pend = (volatile uint32_t *)PROG_PEND_ADDR;
        volatile uint8_t *dst = (volatile uint8_t *)(PROG_PEND_ADDR + 8u);
        pend[0] = cnt;
        pend[1] = PEND_EBPF;
        for (unsigned i = 0; i < n - 8u; i++)
            dst[i] = g_chan_stage[8u + i];   /* body + trailing digest */
        PROG_PEND_OK[0] = PROG_PEND_MAGIC;               /* lands last */
        return 2;
    }
    if (rx->type == 2u) {
        if (n < 12u) return 0;         /* magic + count + one packet */
        uint32_t magic = le32(g_chan_stage), cnt = le32(g_chan_stage + 4u);
        if (magic != MO_SHU || !cnt || cnt > MAX_SWARM ||
            n != 8u + 42u * cnt) return 0;
        for (unsigned i = 0; i < n; i++)
            ((volatile uint8_t *)MAILBOX)[i] = g_chan_stage[i];
        return 1;
    }
    if (rx->type == FRAME_STATUS) {
        /* observability without a debugger: the whole guarded STATUS
         * window goes back over the same wire. Window 0 is the core
         * table; the reply is [window:1][words LE]. Read-only — no
         * schedule side effects. */
        volatile uint32_t *sw = STATUS;
        volatile uint8_t *out = (volatile uint8_t *)g_chan_stage;
        if (n < 1u) return 0;
        if (g_chan_stage[0] != 0u) return 4;
        out[0] = 0u; out[1] = 0u; out[2] = 0u; out[3] = 0u;
        for (unsigned i = 0; i < STATUS_WORDS; i++) {
            uint32_t v = sw[i];
            out[4u + 4u * i + 0u] = (uint8_t)v;
            out[4u + 4u * i + 1u] = (uint8_t)(v >> 8);
            out[4u + 4u * i + 2u] = (uint8_t)(v >> 16);
            out[4u + 4u * i + 3u] = (uint8_t)(v >> 24);
        }
        uart_send_frame(FRAME_STATUS, (const uint8_t *)g_chan_stage,
                        4u + STATUS_WORDS * 4u);
        return 4;
    }
    if (rx->type == FRAME_REARM) {
        /* operator re-arms a slot: the eviction is cleared and the slot
         * goes live again. A human decision, never automatic (v1.1);
         * the frame is 4 bytes = slot index. */
        uint32_t slot;
        if (n != 4u) return 0;
        slot = le32(g_chan_stage);
        if (slot > 1u || !g_nat[slot].valid) {
            uart_send_frame(FRAME_REARM, g_chan_stage, 4u);
            return 3;
        }
        g_nat[slot].evicted = 0u;
        g_nat_live = slot;
        g_nat_retired = 0u;
        STATUS[S_NSLOT] = slot;
        STATUS[S_REARM]++;
        uart_send_frame(FRAME_REARM, g_chan_stage, 4u);
        return 3;
    }
    if (rx->type == 3u) {
        if (n < 16u || n > 0x200u) return 0;   /* PEND payload window */
        volatile uint8_t *dst = (volatile uint8_t *)PROG_PEND_ADDR;
        for (unsigned i = 0; i < n; i++) dst[i] = g_chan_stage[i];
        PROG_PEND_OK[0] = PROG_PEND_MAGIC;               /* lands last */
        return 2;
    }
    return 0;
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
        STATUS[S_HALT] = 0x48414C54u;
        STATUS[S_HALTC] = 0xEE00u | i;   /* schedule bug, not a victim */
        for (;;) heartbeat();
    }
    BUDGET_ARM(BUDGET_TICKS);
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
    if (g_nat_retired || !g_nat[g_nat_live].valid ||
        g_nat[g_nat_live].evicted) {
        /* no runnable native slot: the phase retires this session —
         * the schedule continues without it (Tock-style, no collateral) */
        STATUS[S_NSLOT] = 0xFFFFFFFFu;
        native_done(0u);
        return;
    }
    STATUS[S_NSLOT] = g_nat_live;
    g_phase = 5;
    enter_checked(2u);
}

static void native_done(uint32_t proof) {
    STATUS[S_NAT2] = proof ? *(volatile uint32_t *)
        (g_nat_live ? NAT2_SRAM : NAT_SRAM) : 0u;
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
        /* service loop: the console is a live channel now. Polled, no
         * ISR, and USART1 has no FIFO — the loop must stay tight or the
         * line outruns it (a 20k-nop heartbeat loses ~15 bytes at
         * 115200). A data frame re-runs the schedule against the new
         * swarm; a program frame stages PEND and hot_swap promotes it.
         * The rx state resets on every re-entry: a round eats bytes
         * anyway, so a half-received frame is corrupt by definition. */
        uint32_t seen = STATUS[S_HLOAD];
        uart_frame_rx rx = { 0, 0, 0, 0, 0 };
        for (;;) {
            WDT_FEED();
            int ev = chan_poll(&rx);
            hot_swap();
            hot_update_finalize();
            if (STATUS[S_HLOAD] != seen) {
                seen = STATUS[S_HLOAD];
                hot_round();             /* noreturn: re-enters here */
            }
            if (ev == 1) hot_round();    /* new swarm committed */
            STATUS[3]++;
        }
    }
#endif
}

/* U-mode fault resume (contract v1.1): the running compartment's first
 * fault ends its lifetime. The trap path already saved the frame into the
 * TCB, wiped the register file, and logged mcause/mtval in the ring. */
void supervisor_fault(uint32_t yuanyin, uint32_t zhi) {
    (void)zhi;
    if (yuanyin & 0x80000000u) {
        BUDGET_ACK();
        STATUS[S_PREEMPT]++;          /* timer fire: slice overrun */
    }
    compartment_evict(cur_comp);
    if (g_phase == 4) {
        atk_advance();
    } else if (g_phase >= 5) {
        /* an evicted native compartment is that slot's one strike: the
         * rollback is the remap — the schedule boundary moves the PMP
         * window onto the other entry (its resident image is the
         * last-known-good module). No bytes are restored; both slots
         * dead retires the native phase for the session. The evicted
         * round produces no proof (S_NAT2 reads zero), and the remap
         * counts as a rollback to last-known-good. */
        if (cur_comp == 2u) {
            uint32_t dead = g_nat_live;
            uint32_t other = dead ^ 1u;
            g_nat[dead].evicted = 1u;
            STATUS[S_NAT2] = 0u;
            tele_fault(dead);
            if (g_nat[other].valid && !g_nat[other].evicted) {
                g_nat_live = other;
                g_nat_retired = 0u;
                STATUS[S_ROLL]++;
            } else {
                g_nat_retired = 1u;      /* schedule keeps running */
            }
            STATUS[S_NSLOT] = g_nat_retired ? 0xFFFFFFFFu : g_nat_live;
        }
        native_done(0u);             /* evicted native: nat2 stays 0 */
    } else {
        STATUS[S_HALT] = 0x48414C54u;
        STATUS[S_HALTC] = ((g_phase & 0xFFu) << 24) | (yuanyin & 0xFFFFFFu);
        for (;;) heartbeat();        /* monitor fault: no feed, dog reboots */
    }
}

void supervisor_resume(void) {
    WDT_FEED();
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
        native_done(1u);
    }
}
