
#include <stdint.h>
#include "../core/contract.h"
#include "../core/loader.h"
#include "../descriptions/demo.h"
#include "policies/mavlink.h"
#include "policies/screening.h"
#include "../core/platform.h"

#define MO_SHU  0x5741524Du
#define MAX_SWARM 64u
#ifdef QEMU_TARGET
#include "../qemu/report.h"
#endif


extern void xianjing_rukou(void);
extern void guanli_huifu(void);
extern void monitor_entry(void);
extern void attacker_entry(void);
extern void attacker_recover(void);

volatile uint32_t g_ri_xuhao = 0;
volatile uint32_t g_ri_yuanyin[8];
volatile uint32_t g_ri_zhi[8];
volatile uint32_t g_zhiding = 0;   
static volatile uint32_t g_jieduan = 1;
static volatile uint32_t g_shuru_he = 0;
static volatile uint32_t g_stk0 = 0;
static volatile uint32_t g_jingbao = 0;
static volatile uint32_t g_chongtu_n = 0;
static volatile uint32_t g_laiyuan = 0;

static void csr_xie(unsigned csr, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n" (csr), "r" (v) : "memory");
}

static void pmp_bufang(int monitor) {
    uint32_t a0 = monitor ? MON_RAM_PMP : ATK_RAM_PMP;
    uint32_t a1 = monitor ? MON_FLASH_PMP : ATK_FLASH_PMP;
    uint32_t cfgw = 0x1Bu | (0x1Du << 8) | (0x00u << 16) | (0x18u << 24);
    csr_xie(0x3a0, 0u);
    csr_xie(0x3b0, a0);
    csr_xie(0x3b1, a1);
    csr_xie(0x3b2, 0u);
    csr_xie(0x3b3, PMP_DENY);
    csr_xie(0x3a0, cfgw);
}

static void jin_yonghu(uint32_t pc) {
    uint32_t ms;
    __asm__ volatile ("csrr %0, mstatus" : "=r" (ms));
    ms &= ~(3u << 11);
    ms &= ~(1u << 17);
    __asm__ volatile ("csrw mstatus, %0" :: "r" (ms) : "memory");
    csr_xie(0x341, pc);
    __asm__ volatile ("mret");
}

static uint32_t shuru_he(void) {
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

void rukou(void) {
    uint32_t gate = boot_gate();
    if (gate) {
        STATUS[S_GATE] = 0xC0DE0000u | gate;
#ifdef QEMU_TARGET
        uart_puts("== GATE FAIL ");
        uart_putdec(gate);
        uart_puts(" ==\n");
        for (;;) qemu_exit(1);
#else
        for (;;) {
            STATUS[3]++;
            for (volatile int k = 0; k < 20000; ++k) __asm__ volatile ("nop");
        }
#endif
    }
    STATUS[S_GATE] = 0xC0DE0000u;
    load_program();
    STATUS[0] = 0xDEADBEEFu;
    STATUS[1] = 0xC0DE0008u;
    {
        volatile char *q = STATUS_NAME;
        const char *msg = "PMP-EBPF-3";
        while (*msg) *q++ = *msg++;
        *q = 0;
    }
    TIMER_INIT();

    csr_xie(0x305, (uint32_t)xianjing_rukou);

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

    g_chongtu_n = 0;
    if (MAILBOX[0] == MO_SHU && MAILBOX[1] >= 1u && MAILBOX[1] <= MAX_SWARM) {
        g_chongtu_n = MAILBOX[1];
        for (uint32_t i = 0; i < g_chongtu_n; i++) {
            MON_SOFF[i] = i * 42u;
            MON_SSIZES[i] = 42u;
            for (uint32_t j = 0; j < 42u; j++)
                MON_DATA[i * 42u + j] = MB_DATA[i * 42u + j];
        }
        g_laiyuan = 1;
    } else {
        g_chongtu_n = 8;
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
        g_laiyuan = 0;
    }
    MON_CONFN[0] = g_chongtu_n;
    for (uint32_t c = 0; c < MAP_CELLS; c++) MON_MAP[c] = 0;

    pmp_bufang(1);
    g_jieduan = 1;
    MON_MODE[0] = 0u;
    g_stk0 = TIMER_NOW();
    jin_yonghu((uint32_t)monitor_entry);
}


#ifdef QEMU_TARGET
void supervisor_reset(void) {
    g_jieduan = 1;
    g_shuru_he = 0;
    g_stk0 = 0;
    g_jingbao = 0;
    g_chongtu_n = 0;
    g_laiyuan = 0;
    g_ri_xuhao = 0;
    for (int i = 0; i < 8; i++) { g_ri_yuanyin[i] = 0; g_ri_zhi[i] = 0; }
}
#endif

void guanli_huifu(void) {
    if (g_jieduan == 1) {                       
        uint32_t cyc = TIMER_NOW() - g_stk0;
        for (int i = 0; i < 6; i++) {
            STATUS[S_CAIJUE + i] = MON_VERDICTS[i];
            STATUS[S_INSNS + i] = MON_INSNS[i];
        }
        STATUS[S_CYC0] = cyc;
        g_shuru_he = shuru_he();
        pmp_bufang(1);
        g_jieduan = 2;
        MON_MODE[0] = 1u;
        g_stk0 = TIMER_NOW();
        jin_yonghu((uint32_t)monitor_entry);
    } else if (g_jieduan == 2) {                
        uint32_t cyc = TIMER_NOW() - g_stk0;
        uint32_t alerts = 0;
        for (uint32_t i = 0; i < g_chongtu_n && i < 8u; i++) {
            STATUS[S_BAN_CAIJUE + i] = MON_SCREEN_VERD[i];
            STATUS[S_CINSNS + i] = MON_SCREEN_INSNS[i];
        }
        for (uint32_t i = 0; i < g_chongtu_n; i++) {
            if (MON_SCREEN_VERD[i] == 5u) alerts++;
        }
        g_jingbao = alerts;
        STATUS[S_CYC1] = cyc;
        STATUS[S_JINGBAO] = g_jingbao;
        STATUS[S_CHONGTU_N] = g_chongtu_n;
        STATUS[S_LAIYUAN] = g_laiyuan;
        pmp_bufang(1);
        g_jieduan = 3;
        MON_MODE[0] = 2u;
        g_stk0 = TIMER_NOW();
        jin_yonghu((uint32_t)monitor_entry);
    } else if (g_jieduan == 3) {                
        uint32_t cyc = TIMER_NOW() - g_stk0;
        static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };
        uint32_t natok = 1;
        for (int i = 0; i < 6; i++) {
            if (MON_NATIVE_VERD[i] != want[i]) natok = 0;
        }
        STATUS[S_CYC2] = cyc;
        STATUS[S_NATOK] = natok;
        pmp_bufang(0);
        g_zhiding = (uint32_t)attacker_recover;
        g_jieduan = 4;
        jin_yonghu((uint32_t)attacker_entry);
    } else {                                  
        static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };
        uint32_t vok = 1, iok = (shuru_he() == g_shuru_he);
        for (int i = 0; i < 6; i++) {
            if (MON_VERDICTS[i] != want[i] || STATUS[S_CAIJUE + i] != want[i]) vok = 0;
        }
        STATUS[S_VINTACT] = vok;
        STATUS[S_IINTACT] = iok;
        STATUS[S_OWNOOK] = (*ATK_OWN == 0xBEEF5EEDu);
        STATUS[S_INTER] = g_ri_xuhao;
        STATUS[S_LOG0C] = g_ri_yuanyin[0];
        STATUS[S_LOG0C + 1] = g_ri_zhi[0];
        STATUS[S_LOG0C + 2] = g_ri_yuanyin[1];
        STATUS[S_LOG0C + 3] = g_ri_zhi[1];
        STATUS[S_LOG0C + 4] = g_ri_yuanyin[2];
        STATUS[S_LOG0C + 5] = g_ri_zhi[2];
        STATUS[S_LOG0C + 6] = g_ri_yuanyin[3];
        STATUS[S_LOG0C + 7] = g_ri_zhi[3];
        STATUS[S_RDROK] = (*ATK_PROOF == 0x5EEDC0DEu);
        STATUS[S_DONE] = 0x600DF00Du;

#ifdef QEMU_TARGET
        report();
        __asm__ volatile ("j sweep_next");   /* no caller frame: jump, don't return */
#else
        uint32_t hb = 0;
        for (;;) {
            STATUS[3] = hb++;
            for (volatile int k = 0; k < 20000; ++k) __asm__ volatile ("nop");
        }
#endif
    }
}
