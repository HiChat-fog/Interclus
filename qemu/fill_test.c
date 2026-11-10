/* swap-in drill + icount bill. The five correctness phases prove fill,
 * violation, and cross-domain semantics; the timing phases measure the
 * arm sequences and one E2E swap-in per operation with rdcycle under
 * qemu -icount shift=0 (one count per instruction). Run with:
 *   qemu-system-riscv32 -M virt -bios none -kernel build/fw_fill.elf -nographic \
 *     -icount shift=0,align=off,sleep=off */

#include <stdint.h>
#include "../core/pmp/icp.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void uart_init(void);

void qemu_exit(int code) {
#ifdef QEMU_TARGET
    *(volatile uint32_t *)0x100000u = 0x5555u;
#endif
    for (;;) { __asm__ volatile ("wfi"); }
}

volatile uint32_t cur_tcb, cur_comp;
volatile uint32_t g_ri_index = 0;
volatile uint32_t g_ri_cause[8];
volatile uint32_t g_ri_addr[8];

extern void trap_entry(void);
extern char trap_sp0_top[];

#ifdef QEMU_TARGET
#define PROBE_TEXT 0x80220000u
#define PROBE_RAM  0x80221000u
#define PROBE_SWAP 0x80222000u
#define PROBE_FAR  0x80223000u
#define OTHER_ROW  0x80224000u
#define OUTSIDE    0x80225000u
#define PROBE_SZ   0x1000u
#define PROBE_SP   0x80221F00u
#else
#define PROBE_TEXT 0x08003000u
#define PROBE_FAR  0x08003400u
#define PROBE_RAM  0x2000D800u
#define PROBE_SWAP 0x2000E000u
#define OTHER_ROW  0x2000E400u
#define OUTSIDE    0x2000E800u
#define PROBE_SZ   0x400u
#define PROBE_SP   0x2000DBF0u
#define STK_BASE   0xE000F000u
#define STK_CTLR   (*(volatile uint32_t *)STK_BASE)
#define STK_CNT    (*(volatile uint32_t *)(STK_BASE + 8u))
#endif

static icp_state dom[2];
static volatile uint32_t phase, fault_cause, fault_addr, ok = 1u;
static volatile uint32_t *const ram = (volatile uint32_t *)PROBE_RAM;

static volatile uint32_t m_arm_new, m_arm_old, m_cal, m_nop4;
static volatile uint32_t m_load, m_store, m_fetch, m_warm_load, m_warm_call;
static volatile uint32_t m_thrash_base;

#ifdef QEMU_TARGET
#define CYC(v) __asm__ volatile ("rdcycle %0" : "=r" (v) :: "memory")
#else
#define CYC(v) do { \
    uint32_t _b; \
    __asm__ volatile ("lui %0, 0xe000f\n\tlw %0, 8(%0)" : "=&r" (v), "=r" (_b) :: "memory"); \
} while (0)
#endif

static inline void csrw_(unsigned c, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n" (c), "r" (v) : "memory");
}

#define NAPOT(b, s) (((b) >> 2) | ((s) >> 3) - 1u)

static struct { uint32_t sram_base, sram_size, text_base, text_size; }
    legacy_spec;
static volatile uint32_t legacy_armed[4];

static void old_arm(void) {
    uint32_t cfgw = 0x1Bu | (0x1Du << 8) | (0x00u << 16) | (0x18u << 24);
    csrw_(0x3a0, 0u);
    csrw_(0x3b0, NAPOT(legacy_spec.sram_base, legacy_spec.sram_size));
    csrw_(0x3b1, NAPOT(legacy_spec.text_base, legacy_spec.text_size));
    csrw_(0x3b2, 0u);
    csrw_(0x3b3, 0xFFFFFFFFu);
    csrw_(0x3a0, cfgw);
    for (unsigned j = 0; j < 4u; j++) legacy_armed[j] = 0u;
    legacy_armed[0] = 1u;
}

#define STR2X(x) #x
#define STRX(x) STR2X(x)
__asm__(
    ".section .probe.text, \"ax\"\n"
    ".globl probe_entry\n"
    ".align 2\n"
    "probe_entry:\n"
    "  li   sp, " STRX(PROBE_SP) "\n"
    "  call probe_run\n"
    "  ecall\n"
    "1: j 1b\n"
);

__attribute__((section(".probe.far"), noinline))
uint32_t far_marker(void) {
    return 0xC0DE00C5u;
}

__attribute__((section(".probe.text"), noinline))
uint32_t warm_fn(void) {
    return 0x51C0DEu;
}

__attribute__((section(".probe.text"), noinline, optnone))
uint32_t probe_run(uint32_t mode) {
    volatile uint32_t *swp = (volatile uint32_t *)PROBE_SWAP;
    volatile uint32_t *out = (volatile uint32_t *)OUTSIDE;
    volatile uint32_t *txt = (volatile uint32_t *)PROBE_TEXT;
    uint32_t r = 0u;
    if (mode == 0u) {
        uint32_t (*volatile f)(void) = (uint32_t (*)(void))PROBE_FAR;
        r = swp[0];
        ram[8] = f();
        ram[31] = (r == 0u && ram[8] == 0xC0DE00C5u) ? 0xC0DE0051u : 0xBAD00000u;
    } else if (mode == 1u) {
        swp[0] = 0x51C0DEu;
        r = swp[0];
        ram[31] = (r == 0x51C0DEu) ? 0xC0DE0051u : 0xBAD00001u;
    } else if (mode == 2u) {
        ram[31] = out[0];
    } else if (mode == 3u) {
        ram[8] = 0x51C0DEu;
        ram[31] = swp[0];
    } else if (mode == 4u) {
        txt[0] = 0x51C0DEu;
        ram[31] = 0xBAD00001u;
    } else if (mode == 5u) {
        uint32_t t0;
        CYC(t0);
        r = swp[2];
        uint32_t t1;
        CYC(t1);
        ram[32] = t1 - t0;
        ram[35] = (r == 0u);
    } else if (mode == 6u) {
        uint32_t t0;
        CYC(t0);
        swp[3] = 0x51C0DEu;
        uint32_t t1;
        CYC(t1);
        ram[32] = t1 - t0;
    } else if (mode == 7u) {
        uint32_t (*volatile f)(void) = (uint32_t (*)(void))PROBE_FAR;
        uint32_t t0;
        CYC(t0);
        r = f();
        uint32_t t1;
        CYC(t1);
        ram[32] = t1 - t0;
        ram[35] = (r == 0xC0DE00C5u);
    } else if (mode == 8u) {
        uint32_t t0;
        CYC(t0);
        r = ram[9];
        uint32_t t1;
        CYC(t1);
        ram[33] = t1 - t0;
    } else if (mode == 10u) {
        volatile uint32_t *farr = (volatile uint32_t *)PROBE_FAR;
        uint32_t i, v = 0;
        for (i = 0; i < 100u; i++) {
            swp[4] = i;
            v ^= swp[4];
            v ^= farr[1];
        }
        ram[31] = v;
        ram[35] = (v == 0u);
    } else {
        uint32_t (*volatile f)(void) = (uint32_t (*)(void))warm_fn;
        uint32_t t0;
        CYC(t0);
        r = f();
        uint32_t t1;
        CYC(t1);
        ram[34] = t1 - t0;
        ram[35] &= (r == 0x51C0DEu);
    }
    return r;
}

__attribute__((noreturn))
static void enter_probe(uint32_t mode) {
    register uint32_t pc asm("a1") = PROBE_TEXT;
    register uint32_t md asm("a2") = mode;
    __asm__ volatile (
        "csrw mepc, %0\n"
        "mv   a0, %1\n"
        "csrr t3, mstatus\n"
        "li   t4, 0x21800\n"
        "not  t4, t4\n"
        "and  t3, t3, t4\n"
        "csrw mstatus, t3\n"
        "mret\n"
        :: "r" (pc), "r" (md) : "t3", "t4", "memory");
    __builtin_unreachable();
}

static void next_phase(uint32_t dom_ix, uint32_t mode) {
    icp_arm(&dom[dom_ix]);
    enter_probe(mode);
}

void supervisor_resume(void) {
    uint32_t p = phase;
    if (p == 0u) {
        ok &= (ram[31] == 0xC0DE0051u) && (dom[0].swaps == 2u);
        phase = 1u;
        next_phase(0u, 1u);
    } else if (p == 1u) {
        ok &= (ram[31] == 0xC0DE0051u) && (dom[0].swaps == 3u);
        phase = 2u;
        next_phase(0u, 2u);
    } else if (p == 2u) {
        ok &= (fault_cause == 5u) && (fault_addr == OUTSIDE);
        phase = 3u;
        next_phase(1u, 3u);
    } else if (p == 3u) {
        ok &= (fault_cause == 5u) && (fault_addr == PROBE_SWAP) &&
              (dom[1].swaps >= 1u);
        phase = 4u;
        next_phase(0u, 4u);
    } else if (p == 4u) {
        ok &= (fault_cause == 7u) && (fault_addr == PROBE_TEXT);
        phase = 5u;
        next_phase(0u, 5u);
    } else if (p == 5u) {
        m_load = ram[32];
        ok &= ram[35];
        phase = 6u;
        next_phase(0u, 6u);
    } else if (p == 6u) {
        m_store = ram[32];
        phase = 7u;
        next_phase(0u, 7u);
    } else if (p == 7u) {
        m_fetch = ram[32];
        ok &= ram[35];
        phase = 8u;
        next_phase(0u, 8u);
    } else if (p == 8u) {
        m_warm_load = ram[33];
        phase = 9u;
        next_phase(0u, 9u);
    } else if (p == 9u) {
        m_warm_call = ram[34];
        ok &= ram[35];
        m_thrash_base = dom[0].swaps;
        phase = 10u;
        next_phase(0u, 10u);
    } else if (p == 10u) {
        ok &= (ram[31] == 0u) &&
              (dom[0].swaps == m_thrash_base + 200u);
        m_warm_call = ram[34];
        ok &= ram[35];
        uart_puts("\nbill: arm_new=");
        uart_putdec(m_arm_new);
        uart_puts(" arm_old=");
        uart_putdec(m_arm_old);
        uart_puts(" cal=");
        uart_putdec(m_cal);
        uart_puts("/");
        uart_putdec(m_nop4);
        uart_puts(" warm_load=");
        uart_putdec(m_warm_load);
        uart_puts(" warm_call=");
        uart_putdec(m_warm_call);
        uart_puts(" fill_load=");
        uart_putdec(m_load);
        uart_puts(" fill_store=");
        uart_putdec(m_store);
        uart_puts(" fill_fetch=");
        uart_putdec(m_fetch);
        uart_puts(" sw=");
        uart_putdec(dom[0].swaps);
        uart_puts(ok ? "\n== FILL PASS ==\n" : "\n== FILL FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
}

void supervisor_fault(uint32_t cause, uint32_t addr) {
    fault_cause = cause;
    fault_addr = addr;
    supervisor_resume();
}

__attribute__((section(".text.startup")))
void boot(void) {
    cur_tcb = 0u;
    cur_comp = 0u;
    ok = 1u;
    fault_cause = 0u;
    fault_addr = 0u;
    {
        volatile uint32_t *p = (volatile uint32_t *)PROBE_RAM;
        volatile uint32_t *q = (volatile uint32_t *)PROBE_SWAP;
        for (unsigned i = 0; i < PROBE_SZ / 4u; i++) {
            p[i] = 0u;
            q[i] = 0u;
        }
    }
    uart_init();
    uart_puts("== icp swap-in drill ==\n");
    __asm__ volatile ("csrw mscratch, %0" :: "r" ((uint32_t)trap_sp0_top));
    __asm__ volatile ("csrw mtvec, %0" :: "r" ((uint32_t)trap_entry));
#ifndef QEMU_TARGET
    STK_CTLR |= 1u;
#else
    __asm__ volatile ("csrw mcounteren, %0" :: "r" (7u));
    __asm__ volatile ("csrw scounteren, %0" :: "r" (7u));
#endif
    {
        uint32_t mc, sc, t0, t1;
        __asm__ volatile ("csrr %0, mcounteren" : "=r" (mc));
        __asm__ volatile ("csrr %0, scounteren" : "=r" (sc));
        CYC(t0);
        CYC(t1);
        m_cal = mc;
        m_nop4 = sc;
        m_arm_old = t1 - t0;
    }
    icp_init(&dom[0]);
    legacy_spec.sram_base = PROBE_RAM;
    legacy_spec.sram_size = PROBE_SZ;
    legacy_spec.text_base = PROBE_TEXT;
    legacy_spec.text_size = PROBE_SZ;
    icp_mount(&dom[0], PROBE_RAM, PROBE_SZ, ICP_R | ICP_W);
    icp_mount(&dom[0], PROBE_TEXT, PROBE_SZ, ICP_R | ICP_X);
#ifndef QEMU_TARGET
    icp_mount(&dom[0], STK_BASE, 0x400u, ICP_R | ICP_W);
#endif
    icp_mount(&dom[0], PROBE_SWAP, PROBE_SZ, ICP_R | ICP_W);
    icp_mount(&dom[0], PROBE_FAR, PROBE_SZ, ICP_R | ICP_X);
    icp_lock(&dom[0]);
    icp_init(&dom[1]);
    icp_mount(&dom[1], OTHER_ROW, PROBE_SZ, ICP_R | ICP_W);
    icp_mount(&dom[1], PROBE_TEXT, PROBE_SZ, ICP_R | ICP_X);
    icp_mount(&dom[1], PROBE_RAM, PROBE_SZ, ICP_R | ICP_W);
    icp_lock(&dom[1]);

    {
        uint32_t t0;
        CYC(t0);
        uint32_t t1;
        CYC(t1);
        m_cal = t1 - t0;
        CYC(t0);
#ifdef QEMU_TARGET
        __asm__ volatile ("nop\n\tnop\n\tnop\n\tnop");
#else
        {
            uint32_t k;
            __asm__ volatile ("li %0, 1024\n1: addi %0, %0, -1\n\tbnez %0, 1b"
                              : "=&r" (k) :: "memory");
        }
#endif
        CYC(t1);
        m_nop4 = t1 - t0 - m_cal;

        CYC(t0);
        icp_arm(&dom[0]);
        CYC(t1);
        m_arm_new = t1 - t0;

        CYC(t0);
        old_arm();
        CYC(t1);
        m_arm_old = t1 - t0;
    }

    phase = 0u;
    next_phase(0u, 0u);
    for (;;) { __asm__ volatile ("wfi"); }
}

__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
#ifndef QEMU_TARGET
    "  lui  t0, %hi(__bss_start)\n"
    "  addi t0, t0, %lo(__bss_start)\n"
    "  lui  t1, %hi(__bss_end)\n"
    "  addi t1, t1, %lo(__bss_end)\n"
    "1: bgeu t0, t1, 2f\n"
    "  sw   zero, 0(t0)\n"
    "  addi t0, t0, 4\n"
    "  j    1b\n"
    "2:\n"
#endif
    "  j    boot\n"
);
