/* E36 containment sweep. The fourth gate (the PMP backstop) gets the
 * same treatment the verifier got in E35: for every reachable PMP
 * configuration, a U-mode probe walks all 2^20 pages of the 32-bit
 * space and probes load, store, and fetch, comparing each outcome
 * against the policy recomputed from its own window arguments. Plus
 * byte-granular probes of all eight window edges, and a NAPOT
 * round-trip lemma over every reachable encoding. The M-mode handler
 * resumes the probe after every contained fault and never lets one
 * escape. Policy under test (the implemented one): sram = R/W, text =
 * R/X, everything else denied. The contract's "execute-only text" is
 * not what the hardware grants today — rodata is linked inside the
 * text windows, so text is R/X; the sweep pins that truth down instead
 * of trusting the prose. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/compartment.h"

void uart_puts(const char *s);
void uart_putdec(uint32_t v);
void uart_init(void);

#ifdef QEMU_TARGET
/* sifive test finisher: the standard virt exit device */
void qemu_exit(int code) {
    *(volatile uint32_t *)0x100000u = (uint32_t)code;
    for (;;) { }
}
static const uint8_t cfg_list[4] = {0, 1, 2, 3};
static const uint8_t cfg_fetch[4] = {1, 1, 1, 1};
#else
/* the board parks on the result block at AUDIT_RESULT; the monitor and
 * attacker text windows live in flash where the probe cannot be
 * injected, so the board audit covers the two RAM-backed native slots */
static volatile uint32_t * const AUDIT_RESULT =
    (volatile uint32_t *)0x20003400u;
extern volatile uint32_t g_cfgw;
static const uint8_t cfg_list[2] = {2, 3};
static const uint8_t cfg_fetch[2] = {1, 1};
#define NCFG 2u
#endif

#define EBREAK 0x00100073u

/* full-space sweep by default; the debug range covers every window
 * page for fast iterations (it is not the official audit) */
#ifdef E36_DEBUG_RANGE
#define E36_PSTART 0x800FEu
#define E36_PEND   0x80216u
#else
#define E36_PSTART 0u
#define E36_PEND   1048576u
#endif
#define E36_PAGES ((uint32_t)(E36_PEND - E36_PSTART))
#define E36_STR2(x) #x
#define E36_STR(x) E36_STR2(x)

static const ic_compartment_spec cfgs[4] = {
    { MON_TEXT, 8192u, MON_BOX, 8192u },      /* monitor compartment   */
    { ATK_TEXT, 8192u, ATK_BOX, 8192u },      /* attacker              */
    { NAT_TEXT, 0x1000u, NAT_SRAM, 0x1000u }, /* native slot 0         */
    { NAT2_TEXT, 0x1000u, NAT2_SRAM, 0x1000u },
};
#ifndef NCFG
#define NCFG 4u
#endif

static uint32_t g_cfg;
static uint32_t cfg_index;
static uint32_t g_lemma_bad;
static uint32_t g_pmpcfg0;
static struct { uint32_t mism, pages, page, kind; } res[NCFG];

/* ---- the U-mode probe (.option norvc: mepc fixups advance by 4) ----
 * Registers: a0 sram base, a1 sram size, a2 text base, a3 text size;
 * s0 mismatches, s1 index, s2 log cursor, s3 log limit, s4 page count,
 * s5 page size, s6 page index, s7 edge table, t6 fault flag. The probe
 * is copied to the END of the text window; every word before it is
 * ebreak, so fetch probes of page bases are contained. */
void probe_entry(void);
void probe_end(void);

__asm__(
    ".option push\n"
    ".option norvc\n"
    ".text\n"
    ".balign 4\n"
    ".globl probe_entry\n"
    "probe_entry:\n"
    "  ecall\n"                          /* bootstrap: handler fills args */
    "  li   s0, 0\n"                     /* mismatches */
    "  li   s9, 0\n"                     /* first mismatch page */
    "  li   s10, 0\n"                    /* first mismatch kind */
    "  li   s4, " E36_STR(E36_PEND) "\n"
    "  li   s6, " E36_STR(E36_PSTART) "\n"
    "  mv   a5, a4\n"                     /* fetch policy flag */
    "ploop:\n"
    "  slli t0, s6, 12\n"
    /* load: allowed inside sram OR text (text is R/X today) */
    "  li   t6, 0\n"
    "  lbu  t1, 0(t0)\n"
    "  j    lchk\n"
    "lchk:\n"
    "  sub  t2, t0, a0\n"
    "  sltu t3, t2, a1\n"
    "  sub  t2, t0, a2\n"
    "  sltu t4, t2, a3\n"
    "  or   t3, t3, t4\n"
    "  xori t4, t6, 1\n"
    "  bne  t3, t4, lbad\n"
    "  j    lnext\n"
    "lbad:\n"
    "  addi s0, s0, 1\n"
    "  bnez s9, 1f\n"
    "  mv   s9, s6\n"
    "  li   s10, 1\n"
    "1:\n"
    "lnext:\n"
    /* store: allowed inside sram only */
    "  li   t6, 0\n"
    "  sb   t1, 0(t0)\n"
    "  j    schk\n"
    "schk:\n"
    "  sub  t2, t0, a0\n"
    "  sltu t3, t2, a1\n"
    "  xori t4, t6, 1\n"
    "  bne  t3, t4, sbad\n"
    "  j    snext\n"
    "sbad:\n"
    "  addi s0, s0, 1\n"
    "  bnez s9, 2f\n"
    "  mv   s9, s6\n"
    "  li   s10, 2\n"
    "2:\n"
    "snext:\n"
    /* fetch: allowed inside text only */
    "  beqz a5, fnext\n"                 /* flash-backed text: unprobed */
    "  sub  t2, t0, a2\n"
    "  sltu t3, t2, a3\n"
    "  auipc ra, 0\n"
    "  addi  ra, ra, 12\n"
    "  jr   0(t0)\n"
    "fcont:\n"
    "  xori t4, t6, 1\n"
    "  bne  t3, t4, fbad\n"
    "  j    fnext\n"
    "fbad:\n"
    "  addi s0, s0, 1\n"
    "  bnez s9, 3f\n"
    "  mv   s9, s6\n"
    "  li   s10, 3\n"
    "3:\n"
    "fnext:\n"
    "  addi s6, s6, 1\n"
    "  addi s8, s8, 1\n"
    "  bltu s6, s4, ploop\n"
    /* ---- edge probes: the eight window boundaries ---- */
    "  li   s11, 4096\n"
    "  add  s7, a0, s11\n"
    "  addi t0, a0, -1\n"
    "  sw   t0, 0(s7)\n"
    "  sw   a0, 4(s7)\n"
    "  add  t0, a0, a1\n"
    "  addi t0, t0, -1\n"
    "  sw   t0, 8(s7)\n"
    "  add  t0, a0, a1\n"
    "  sw   t0, 12(s7)\n"
    "  addi t0, a2, -1\n"
    "  sw   t0, 16(s7)\n"
    "  sw   a2, 20(s7)\n"
    "  add  t0, a2, a3\n"
    "  addi t0, t0, -1\n"
    "  sw   t0, 24(s7)\n"
    "  add  t0, a2, a3\n"
    "  sw   t0, 28(s7)\n"
    "  li   s1, 0\n"
    "eloop:\n"
    "  slli t6, s1, 2\n"
    "  add  t0, s7, t6\n"
    "  lw   t0, 0(t0)\n"
    "  andi t1, s1, 1\n"                 /* odd index = aligned edge */
    "  /* load */\n"
    "  li   t6, 0\n"
    "  lbu  t2, 0(t0)\n"
    "  j    elchk\n"
    "elchk:\n"
    "  sub  t2, t0, a0\n"
    "  sltu t3, t2, a1\n"
    "  sub  t2, t0, a2\n"
    "  sltu t4, t2, a3\n"
    "  or   t3, t3, t4\n"
    "  xori t4, t6, 1\n"
    "  beq  t3, t4, elok1\n"
    "  addi s0, s0, 1\n"
    "elok1:\n"
    "  beqz t1, elnxt\n"
    "  /* store */\n"
    "  li   t6, 0\n"
    "  sb   t2, 0(t0)\n"
    "  j    eschk\n"
    "eschk:\n"
    "  sub  t2, t0, a0\n"
    "  sltu t3, t2, a1\n"
    "  xori t4, t6, 1\n"
    "  beq  t3, t4, elok2\n"
    "  addi s0, s0, 1\n"
    "elok2:\n"
    "  /* fetch */\n"
    "  beqz a5, elnxt\n"
    "  sub  t2, t0, a2\n"
    "  sltu t3, t2, a3\n"
    "  auipc ra, 0\n"
    "  addi  ra, ra, 12\n"
    "  jr   0(t0)\n"
    "efcont:\n"
    "  xori t4, t6, 1\n"
    "  beq  t3, t4, elok3\n"
    "  addi s0, s0, 1\n"
    "elok3:\n"
    "elnxt:\n"
    "  addi s1, s1, 1\n"
    "  li   t5, 8\n"
    "  bltu s1, t5, eloop\n"
    "pdone:\n"
    "  li   a0, 0xE36D0E1\n"
    "  mv   a1, s0\n"
    "  mv   a2, s8\n"
    "  mv   a3, s9\n"
    "  mv   a4, s10\n"
    "  ecall\n"
    "1: j 1b\n"
    ".globl probe_end\n"
    ".balign 4\n"
    "probe_end:\n"
    ".option pop\n"
);

/* ---- the M-mode trap handler: save, dispatch, restore, mret ---- */
void audit_trap(void);

__asm__(
    ".option push\n"
    ".option norvc\n"
    ".text\n"
    ".balign 4\n"
    ".globl audit_trap\n"
    "audit_trap:\n"
    "  csrw mscratch, sp\n"
#ifdef QEMU_TARGET
    "  li   sp, 0x80011000\n"
#else
    "  li   sp, 0x20002C00\n"
#endif
    "  addi sp, sp, -132\n"
    "  sw   ra, 0(sp)\n"
    "  sw   gp, 8(sp)\n"
    "  sw   tp, 12(sp)\n"
    "  sw   t0, 16(sp)\n"
    "  sw   t1, 20(sp)\n"
    "  sw   t2, 24(sp)\n"
    "  sw   s0, 28(sp)\n"
    "  sw   s1, 32(sp)\n"
    "  sw   a0, 36(sp)\n"
    "  sw   a1, 40(sp)\n"
    "  sw   a2, 44(sp)\n"
    "  sw   a3, 48(sp)\n"
    "  sw   a4, 52(sp)\n"
    "  sw   a5, 56(sp)\n"
    "  sw   a6, 60(sp)\n"
    "  sw   a7, 64(sp)\n"
    "  sw   s2, 68(sp)\n"
    "  sw   s3, 72(sp)\n"
    "  sw   s4, 76(sp)\n"
    "  sw   s5, 80(sp)\n"
    "  sw   s6, 84(sp)\n"
    "  sw   s7, 88(sp)\n"
    "  sw   s8, 92(sp)\n"
    "  sw   s9, 96(sp)\n"
    "  sw   s10, 100(sp)\n"
    "  sw   s11, 104(sp)\n"
    "  sw   t3, 108(sp)\n"
    "  sw   t4, 112(sp)\n"
    "  sw   t5, 116(sp)\n"
    "  sw   t6, 120(sp)\n"
    "  csrr t0, mepc\n"
    "  sw   t0, 124(sp)\n"
    "  csrr t0, mstatus\n"
    "  sw   t0, 128(sp)\n"
    "  csrr a0, mcause\n"
    "  csrr a1, mtval\n"
    "  mv   a2, sp\n"
    "  call audit_dispatch\n"
    "  mv   t0, a0\n"
    "  csrw mepc, t0\n"
    "  lw   ra, 0(sp)\n"
    "  lw   gp, 8(sp)\n"
    "  lw   tp, 12(sp)\n"
    "  lw   t0, 16(sp)\n"
    "  lw   t1, 20(sp)\n"
    "  lw   t2, 24(sp)\n"
    "  lw   s0, 28(sp)\n"
    "  lw   s1, 32(sp)\n"
    "  lw   a0, 36(sp)\n"
    "  lw   a1, 40(sp)\n"
    "  lw   a2, 44(sp)\n"
    "  lw   a3, 48(sp)\n"
    "  lw   a4, 52(sp)\n"
    "  lw   a5, 56(sp)\n"
    "  lw   a6, 60(sp)\n"
    "  lw   a7, 64(sp)\n"
    "  lw   s2, 68(sp)\n"
    "  lw   s3, 72(sp)\n"
    "  lw   s4, 76(sp)\n"
    "  lw   s5, 80(sp)\n"
    "  lw   s6, 84(sp)\n"
    "  lw   s7, 88(sp)\n"
    "  lw   s8, 92(sp)\n"
    "  lw   s9, 96(sp)\n"
    "  lw   s10, 100(sp)\n"
    "  lw   s11, 104(sp)\n"
    "  lw   t3, 108(sp)\n"
    "  lw   t4, 112(sp)\n"
    "  lw   t5, 116(sp)\n"
    "  lw   t6, 120(sp)\n"
    "  csrr sp, mscratch\n"
    "  mret\n"
    ".option pop\n"
);

/* frame word offsets used by dispatch */
#define F_RA   0u
#define F_A0   9u
#define F_A1  10u
#define F_A2  11u
#define F_A3  12u
#define F_A4  13u
#define F_T6  30u
#define F_MEPC 31u

void audit_next(void);

/* C dispatch: contained faults resume the probe (t6 = fault flag);
 * bootstrap and done ecalls rewrite the argument frame or chain the
 * next stage. Anything unexpected parks the core visibly. */
uint32_t audit_dispatch(uint32_t mcause, uint32_t mtval, uint32_t *f) {
    if (mcause == 8u || mcause == 11u) {
        if (f[F_A0] == 0xE36D0E1u) {              /* config done */
            res[g_cfg].mism = f[F_A1];
            res[g_cfg].pages = f[F_A2];
            res[g_cfg].page = f[F_A3];
            res[g_cfg].kind = f[F_A4];
            audit_next();
        }
        /* any other ecall is the bootstrap: the probe's first word,
         * entered with a zeroed register file from the TCB */
        const ic_compartment_spec *s = &cfgs[cfg_list[g_cfg]];
        cfg_index = cfg_list[g_cfg];
        f[F_A0] = s->sram_base;
        f[F_A1] = s->sram_size;
        f[F_A2] = s->text_base;
        f[F_A3] = s->text_size;
        return f[F_MEPC] + 4u;
    }
    switch (mcause) {
    case 1u:                                  /* fetch denied */
    case 2u:                                  /* fetch misaligned */
        f[F_T6] = 1u;
        return f[F_RA];
    case 3u:                                  /* ebreak: fetch allowed */
        f[F_T6] = 0u;
        return f[F_RA];
    case 5u:
    case 7u:
        f[F_T6] = 1u;
        return f[F_MEPC] + 4u;
    default:
        for (;;) { }
    }
}

/* ---- NAPOT round-trip lemma ---- */
static uint32_t napot_tail(uint32_t enc) {
    uint32_t k = 0;
    while (k < 30u && ((enc >> k) & 1u)) k++;
    return k;
}

static int napot_decode(uint32_t enc, uint32_t *base, uint32_t *size) {
    if (enc == 0xFFFFFFFFu) { *base = 0u; *size = 0u; return 1; }
    if (enc == 0u) return 0;
    uint32_t k = napot_tail(enc);
    if (k == 0u) { *base = enc << 2; *size = 4u; return 1; }
    if (k > 19u) return 0;
    if ((enc >> k) & 1u) return 0;
    *base = (enc & ~((1u << (k + 1u)) - 1u)) << 2;
    *size = 1u << (k + 3u);
    return 1;
}

static uint32_t lemma(void) {
    uint32_t bad = 0u;
    for (uint32_t ci = 0; ci < NCFG; ci++) {
        uint32_t c = cfg_list[ci];
        const uint32_t bs[2] = { cfgs[c].text_base, cfgs[c].sram_base };
        const uint32_t sz[2] = { cfgs[c].text_size, cfgs[c].sram_size };
        for (int w = 0; w < 2; w++) {
            uint32_t b, s;
            if (!napot_decode(NAPOT(bs[w], sz[w]), &b, &s) ||
                b != bs[w] || s != sz[w]) bad |= (1u << (c * 2u + w));
        }
    }
    for (uint32_t n = 10u; n <= 20u; n++) {
        uint32_t size = 1u << n, b, s;
        if (!napot_decode(NAPOT(0x80000000u, size), &b, &s) ||
            b != 0x80000000u || s != size) bad |= 0x10000u;
    }
    {
        uint32_t b, s;
        if (!napot_decode(PMP_DENY, &b, &s) || b != 0u || s != 0u)
            bad |= 0x20000u;
    }
    return bad;
}

/* ---- stage chain: arm config g_cfg and enter the probe ---- */
static void stage_setup(void) {
    const ic_compartment_spec *s = &cfgs[cfg_list[g_cfg]];
    uint32_t len = ((uint32_t)probe_end - (uint32_t)probe_entry + 3u) & ~3u;
    uint32_t probe_at = s->text_base + s->text_size - len;
    for (uint32_t a = s->text_base; a < s->text_base + s->text_size; a += 4)
        *(volatile uint32_t *)a = EBREAK;
    const uint32_t *src = (const uint32_t *)probe_entry;
    for (uint32_t i = 0; i < len; i += 4)
        *(volatile uint32_t *)(probe_at + i) = src[i >> 2];
    compartment_set(2u, s, probe_at - s->text_base);
    compartment_arm(2u);
#ifdef QEMU_TARGET
    compartment_enter(2u);
#else
    {   /* WARL readback: what did the silicon keep? */
        uint32_t rb;
        __asm__ volatile ("csrr %0, pmpcfg0" : "=r"(rb));
        g_pmpcfg0 = rb;
        compartment_enter(2u);
    }
#endif
}

static void finish(void) {
    uart_puts("\n== E36 RESULT ==\n");
    uint32_t bad = g_lemma_bad;
    for (uint32_t c = 0; c < NCFG; c++) {
        uart_putdec(c);
        uart_puts(": mism=");
        uart_putdec(res[c].mism);
        uart_puts(" pages=");
        uart_putdec(res[c].pages);
        uart_puts(" first=");
        uart_putdec(res[c].page);
        uart_puts("/");
        uart_putdec(res[c].kind);
        uart_puts("\n");
        if (res[c].mism != 0u || res[c].pages != E36_PAGES) bad |= 1u << c;
    }
    uart_puts(bad ? "E36 CONTAINMENT FAIL\n" : "E36 CONTAINMENT PASS\n");
#ifdef QEMU_TARGET
    qemu_exit(bad ? 1 : 0);
#else
    AUDIT_RESULT[0] = 0xE36D0001u;
    AUDIT_RESULT[1] = g_lemma_bad;
    for (uint32_t c = 0; c < NCFG; c++) {
        AUDIT_RESULT[2 + c * 4 + 0] = res[c].mism;
        AUDIT_RESULT[2 + c * 4 + 1] = res[c].pages;
        AUDIT_RESULT[2 + c * 4 + 2] = res[c].page;
        AUDIT_RESULT[2 + c * 4 + 3] = res[c].kind;
    }
    AUDIT_RESULT[2 + NCFG * 4] = g_pmpcfg0;
    AUDIT_RESULT[3 + NCFG * 4] = g_cfgw;
    for (;;) { __asm__ volatile ("wfi"); }
#endif
}

void audit_next(void) {
    g_cfg++;
    uart_puts("\ncfg ");
    uart_putdec(g_cfg);
    if (g_cfg < NCFG) {
        stage_setup();
    }
    finish();
}

void boot_main(void);

void boot_main(void) {
#ifdef QEMU_TARGET
    uart_puts("== E36 containment sweep ==\n");
#else
    uart_init();
    uart_puts("== E36 containment sweep ==\n");
#endif
    g_lemma_bad = lemma();
    uart_puts("lemma: ");
    uart_putdec(g_lemma_bad);
    uart_puts("\ncfg 0\n");
    __asm__ volatile ("csrw mtvec, %0" :: "r"(audit_trap));
    g_cfg = 0u;
    stage_setup();
}

#ifdef QEMU_TARGET
__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot_main\n"
);
#endif
