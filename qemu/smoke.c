/* QEMU smoke test: PMP boxing + trap forensics + UART, no board needed.
 * Boots on `qemu-system-riscv32 -M virt -bios none -kernel smoke.elf -nographic`.
 * Boxes a U-mode worker with PMP; the worker writes inside the box (lands),
 * then outside it (store access fault -> logged -> skipped), then yields. */

#include <stdint.h>

#define UART0 ((volatile uint8_t *)0x10000000u)

static void putc_(char c) {
    UART0[0] = (uint8_t)c;   /* QEMU 16550 needs no flow control at reset */
}
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void puthex(uint32_t v) {
    for (int i = 28; i >= 0; i -= 4) {
        uint8_t n = (v >> i) & 0xFu;
        putc_(n < 10 ? '0' + n : 'a' + n - 10);
    }
}

#define MON_BASE 0x80100000u   /* worker box, 8 KiB NAPOT */
#define OUT_ADDR 0x80102000u   /* just past the box: entry1 deny-all */

static inline void csr_wr(unsigned addr, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n"(addr), "r"(v) : "memory");
}
static inline uint32_t csr_rd(unsigned addr) {
    uint32_t v;
    __asm__ volatile ("csrr %0, %1" : "=r"(v) : "i"(addr));
    return v;
}

volatile uint32_t g_faults;
volatile uint32_t g_mtval;

void trap_entry(void);
__attribute__((section(".worker.text"))) void worker_main(void);
void m_resume(void);

void main(void) {
    puts_("qemu-pmp-smoke\n");

    csr_wr(0x305, (uint32_t)trap_entry);           /* mtvec */

    /* entry0: NAPOT RWX 8 KiB worker box; entry1: NAPOT no-perm whole space */
    csr_wr(0x3a0, 0u);
    csr_wr(0x3b0, (MON_BASE >> 2) | (8192u >> 3) - 1u);
    csr_wr(0x3b1, 0xFFFFFFFFu);
    csr_wr(0x3a0, 0x1Fu | (0x18u << 8));

    /* drop to U-mode, run the worker; s7 holds the M-mode resume point */
    __asm__ volatile (
        "la   s7, 1f\n"
        "csrr t0, mstatus\n"
        "li   t1, 0xFFFFE7FF\n"        /* ~MPP mask */
        "and  t0, t0, t1\n"
        "csrw mstatus, t0\n"           /* MPP = U */
        "csrw mepc, %0\n"
        "mret\n"
        "1:\n"
        :: "r"((uint32_t)worker_main)
        : "s7", "t0", "t1", "memory");

    /* M-mode again: evidence */
    puts_("faults=");
    puthex(g_faults);
    puts_(" mtval=");
    puthex(g_mtval);
    puts_("\n");
    uint32_t ok = (g_faults == 1) && (g_mtval == OUT_ADDR);
    puts_(ok ? "SMOKE PASS\n" : "SMOKE FAIL\n");
    for (;;) { __asm__ volatile ("wfi"); }
}

__attribute__((section(".worker.text")))
void worker_main(void) {
    volatile uint32_t *box = (volatile uint32_t *)MON_BASE;
    box[0] = 0x11111111u;                          /* inside: grant */
    *(volatile uint32_t *)OUT_ADDR = 0x22222222u;  /* outside: deny -> fault */
    __asm__ volatile ("ecall");                    /* yield back to M-mode */
    for (;;) { __asm__ volatile ("wfi"); }
}



__asm__(
    ".text\n"
    ".align 2\n"
    "trap_entry:\n"
    "  addi sp, sp, -16\n"
    "  sw   a0, 0(sp)\n"
    "  sw   a1, 4(sp)\n"
    "  csrr a0, mcause\n"
    "  li   a2, 8\n"
    "  beq  a0, a2, .Lgom\n"                        /* ecall -> yield */
    "  lui  t0, %hi(g_faults)\n"
    "  addi t0, t0, %lo(g_faults)\n"
    "  lw   t1, 0(t0)\n"
    "  addi t1, t1, 1\n"
    "  sw   t1, 0(t0)\n"
    "  csrr t2, mtval\n"
    "  lui  t0, %hi(g_mtval)\n"
    "  addi t0, t0, %lo(g_mtval)\n"
    "  sw   t2, 0(t0)\n"
    "  csrr a1, mepc\n"
    "  lhu  t1, 0(a1)\n"
    "  andi t1, t1, 3\n"
    "  addi a1, a1, 2\n"
    "  li   t2, 3\n"
    "  bne  t1, t2, .Lsk\n"
    "  addi a1, a1, 2\n"
    ".Lsk:\n"
    "  csrw mepc, a1\n"                            /* skip faulting insn */
    "  lw   a0, 0(sp)\n"
    "  lw   a1, 4(sp)\n"
    "  addi sp, sp, 16\n"
    "  mret\n"
    ".Lgom:\n"
    "  lw   a0, 0(sp)\n"
    "  lw   a1, 4(sp)\n"
    "  addi sp, sp, 16\n"
    "  csrw mepc, s7\n"
    "  csrr t1, mstatus\n"
    "  li   t2, 0x1800\n"
    "  or   t1, t1, t2\n"
    "  csrw mstatus, t1\n"                         /* MPP = M */
    "  mret\n"
);

__asm__(
    ".section .text.startup\n"    /* must sit at DRAM base: QEMU -bios none
                                     jumps to 0x80000000, not the ELF entry */
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_stack_top)\n"
    "  addi sp, sp, %lo(_stack_top)\n"
    "  j    main\n"
);
