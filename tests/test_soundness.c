/* E35 soundness audit. The verifier is the one gate that reasons about
 * code semantics; every other gate trusts its verdict. This file
 * machine-checks that verdict against the interpreter over exhaustive
 * small models: opcode totality (256), read/write/successor table
 * agreement, end-to-end verdict + benign-fault sweeps over all
 * instruction pairs and a pruned triple space, bit-flip immunity, and
 * adversarial lattice cases. Digests are cross-checked against an
 * independent oracle in tools/soundness.py. The safety theorem being
 * checked: accepted ⟹ fault ∈ {OK, DIV0, MEM, FP, STEPS} for every
 * input, never OPCODE/PC/STORE/CALL, and every memory access inside
 * the declared context window. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/ebpf.h"
#include "../core/ebpf_asm.h"
#include "../core/loader.c"

static int violations, table_mismatch, flow_mismatch, adv_mismatch;

static unsigned long long fnv(unsigned long long h, unsigned long long v) {
    for (int i = 0; i < 8; i++) {
        h ^= (v >> (8 * i)) & 0xffu;
        h *= 0x100000001b3ull;
    }
    return h;
}

/* ---- audit side: re-derived from the ISA contract, not the verifier ---- */

static int aud_defined(uint8_t op) {
    uint8_t cls = op & 0x07u, hi = op & 0xf0u;
    if (cls == 0x01u) return (op & 0xe0u) == 0x60u;
    if (cls == 0x04u || cls == 0x07u) return hi <= 0xd0u;
    if (cls == 0x05u || cls == 0x06u) return hi <= 0xd0u;
    return 0;
}

static uint32_t aud_reads(uint64_t e) {
    uint8_t op = (uint8_t)e, dst = (uint8_t)((e >> 8) & 0xfu);
    uint8_t src = (uint8_t)((e >> 12) & 0xfu);
    uint8_t cls = op & 0x07u, hi = op & 0xf0u, sx = op & 0x08u;
    if (cls == 0x04u || cls == 0x07u) {
        if (hi == 0xb0u) return sx ? 1u << src : 0u;
        if (hi == 0x80u || hi == 0xd0u) return 1u << dst;
        return (1u << dst) | (sx ? 1u << src : 0u);
    }
    if (cls == 0x05u || cls == 0x06u) {
        if (hi == 0x90u) return 1u;
        if (hi == 0x80u)
            return ((e >> 32) == 2u) ? ((1u << 1) | (1u << 2)) : (1u << 1);
        if (hi == 0x00u) return 0u;
        return (1u << dst) | (sx ? 1u << src : 0u);
    }
    if (cls == 0x01u) return 1u << src;
    return 0u;
}

static uint32_t aud_writes(uint64_t e) {
    uint8_t op = (uint8_t)e, dst = (uint8_t)((e >> 8) & 0xfu);
    uint8_t cls = op & 0x07u;
    if (cls == 0x01u || cls == 0x04u || cls == 0x07u) return 1u << dst;
    if ((cls == 0x05u || cls == 0x06u) && (op & 0xf0u) == 0x80u) return 1u;
    return 0u;
}

static int aud_succ(uint64_t e, uint32_t pc, uint32_t succ[2]) {
    uint8_t op = (uint8_t)e, cls = op & 0x07u;
    if (cls == 0x05u || cls == 0x06u) {
        uint8_t hi = op & 0xf0u;
        if (hi == 0x90u) return 0;
        if (hi == 0x00u) {
            succ[0] = (uint32_t)((int32_t)pc + 1 +
                                 (int16_t)((e >> 16) & 0xffffu));
            return 1;
        }
        if (hi == 0x80u) { succ[0] = pc + 1; return 1; }
        succ[0] = pc + 1;
        succ[1] = (uint32_t)((int32_t)pc + 1 +
                             (int16_t)((e >> 16) & 0xffffu));
        return 2;
    }
    succ[0] = pc + 1;
    return 1;
}

/* ---- sweep 1: opcode totality over all 256 bytes ---- */

static unsigned long long sweep_tables(void) {
    unsigned long long h = 0xcbf29ce484222325ull;
    for (unsigned op = 0; op < 256u; op++) {
        int k = opcode_known((uint8_t)op), d = aud_defined((uint8_t)op);
        if (k && !d) {
            table_mismatch++;
            printf("table mismatch: op %02x known but undefined\n", op);
        }
        h = fnv(h, op);
        h = fnv(h, (unsigned)k);
        h = fnv(h, (unsigned)d);
    }
    return h;
}

/* ---- sweep 2: read/write/successor table agreement ---- */

static unsigned long long sweep_flow(void) {
    unsigned long long h = 0xcbf29ce484222325ull;
    for (unsigned op = 0; op < 256u; op++) {
        uint8_t o8 = (uint8_t)op;
        if (!opcode_known(o8)) continue;
        int is_call = ((o8 & 0x07u) == 0x05u || (o8 & 0x07u) == 0x06u) &&
                      (o8 & 0xf0u) == 0x80u;
        for (unsigned dst = 0; dst <= 10u; dst++)
        for (unsigned src = 0; src <= 10u; src++)
        for (unsigned imm = 0; imm < (is_call ? 3u : 1u); imm++)
        for (int off = -2; off <= 1; off++) {
            uint64_t e = EBPF_ENC(o8, dst, src, off, imm);
            uint32_t cr = insn_reads(e), cw = insn_writes(e);
            uint32_t ar = aud_reads(e), aw = aud_writes(e);
            uint32_t cs[2] = {0, 0}, as[2] = {0, 0};
            int cn = insn_succ(e, 1u, cs), an = aud_succ(e, 1u, as);
            if (cr != ar || cw != aw || cn != an ||
                (cn > 0 && cs[0] != as[0]) ||
                (cn > 1 && cs[1] != as[1])) {
                flow_mismatch++;
                printf("flow mismatch op=%02x dst=%u src=%u imm=%u off=%d "
                       "r %08x/%08x w %08x/%08x s %d/%d\n", o8, dst, src,
                       imm, off, cr, ar, cw, aw, cn, an);
            }
            h = fnv(h, op);
            h = fnv(h, dst);
            h = fnv(h, src);
            h = fnv(h, imm);
            h = fnv(h, (unsigned)(off + 8));
            h = fnv(h, ar);
            h = fnv(h, aw);
            h = fnv(h, (unsigned)an);
            if (an > 0) h = fnv(h, as[0]);
            if (an > 1) h = fnv(h, as[1]);
        }
    }
    return h;
}

/* ---- battery ----
 * The context buffers live at fixed addresses: the ctx pointer leaks
 * into observable values only through LDX bases (bounds-checked), helper
 * indices (masked to zero), and jump comparisons — the last must not
 * depend on ASLR, or the digests are meaningless. The oracle models the
 * same three constants. */
#include <sys/mman.h>
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#define CTX_BASE 0x20000000u

static uint32_t map_a[1] = {7}, map_b[1] = {0};
static const uint8_t CTX_A[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                                  13, 14, 15};
static const uint8_t CTX_B[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff};
static const uint8_t CTX_C[4] = {0, 1, 2, 3};
static struct { const uint8_t *ctx; uint32_t size; uint32_t *map;
                uint32_t init; } BATT[4] = {
    {(uint8_t *)CTX_BASE, 16, map_a, 7},
    {(uint8_t *)(CTX_BASE + 0x100u), 16, map_a, 7},
    {(uint8_t *)(CTX_BASE + 0x200u), 4, map_a, 7},
    {(uint8_t *)CTX_BASE, 16, map_b, 0},
};

static int benign(uint8_t f) {
    return f == EBPF_OK || f == EBPF_FAULT_DIV0 || f == EBPF_FAULT_MEM ||
           f == EBPF_FAULT_FP || f == EBPF_FAULT_STEPS;
}

static void run_prog(const uint64_t *ins, uint32_t cnt, int b,
                     struct ebpf_result *r) {
    struct ebpf_prog p;
    p.ins = ins;
    p.insn_cnt = cnt;
    p.ctx = BATT[b].ctx;
    p.ctx_size = BATT[b].size;
    p.max_steps = 64u;
    p.map = BATT[b].map;
    p.map_cells = 1u;
    BATT[b].map[0] = BATT[b].init;
    ebpf_run(&p, r);
}

/* ---- sweep 3: exhaustive pairs + pruned triples ---- */

#define E(op, d, s, o, i) EBPF_ENC(op, d, s, o, i)

static const struct { uint64_t e; const char *n; } A2[] = {
    { E(0x95,0,0,0,0), "exit" },
    { E(0x05,0,0,-1,0), "ja-1" },
    { E(0x05,0,0,1,0), "ja+1" },
    { E(0x05,0,0,2,0), "ja+2" },
    { E(0x15,0,0,1,0), "jeq r0,0,+1" },
    { E(0x15,0,0,-1,0), "jeq r0,0,-1" },
    { E(0x15,0,0,0,0), "jeq r0,0,0" },
    { E(0x15,1,0,1,0), "jeq r1,0,+1" },
    { E(0x1d,0,0,0,0), "jeq r0,r0,0" },
    { E(0x5d,0,0,1,0), "jne r0,r0,+1" },
    { E(0x65,0,0,1,-1), "jsgt r0,-1,+1" },
    { E(0x4d,0,1,1,0), "jset r0,r1,+1" },
    { E(0x16,0,0,1,0), "jeq32 r0,0,+1" },
    { E(0xc6,0,0,1,1), "jslt32 r0,1,+1" },
    { E(0x85,0,0,0,1), "call1" },
    { E(0x85,0,0,0,2), "call2" },
    { E(0x85,0,0,0,3), "call3" },
    { E(0x86,0,0,0,1), "jmp32call" },
    { E(0xb7,0,0,0,1), "mov r0,1" },
    { E(0xb7,2,0,0,1), "mov r2,1" },
    { E(0xb7,5,0,0,2), "mov r5,2" },
    { E(0xb7,1,0,0,0), "mov r1,0" },
    { E(0xb7,10,0,0,0), "mov r10,0" },
    { E(0xbf,3,1,0,0), "mov r3,r1" },
    { E(0xbf,0,0,0,0), "mov r0,r0" },
    { E(0x07,0,0,0,1), "add r0,1" },
    { E(0x0f,0,1,0,0), "add r0,r1" },
    { E(0x0f,2,0,0,0), "add r2,r0" },
    { E(0x0f,0,10,0,0), "add r0,r10" },
    { E(0x17,0,0,0,1), "sub r0,1" },
    { E(0x27,0,0,0,3), "mul r0,3" },
    { E(0x37,0,0,0,0), "div r0,0" },
    { E(0x37,0,0,0,2), "div r0,2" },
    { E(0x3f,0,2,0,0), "div r0,r2" },
    { E(0x97,0,0,0,0), "mod r0,0" },
    { E(0x97,0,0,0,3), "mod r0,3" },
    { E(0x47,0,0,0,0xf0), "or r0,0xf0" },
    { E(0x57,0,0,0,0xff), "and r0,0xff" },
    { E(0x67,0,0,0,1), "lsh r0,1" },
    { E(0x77,0,0,0,1), "rsh r0,1" },
    { E(0xc7,0,0,0,1), "arsh r0,1" },
    { E(0x87,0,0,0,0), "neg r0" },
    { E(0x8f,0,3,0,0), "neg r0,x" },
    { E(0xd7,0,0,0,16), "bswap16" },
    { E(0xd7,0,0,0,32), "bswap32" },
    { E(0xd7,0,0,0,8), "bswap8" },
    { E(0xd4,0,0,0,32), "end imm" },
    { E(0xdf,0,0,0,8), "bswapreg8" },
    { E(0xdf,0,0,0,16), "bswapreg16" },
    { E(0x71,0,1,0,0), "ldxb" },
    { E(0x61,0,1,0,0), "ldxw" },
    { E(0x69,0,1,0,0), "ldxh" },
    { E(0x79,0,1,0,0), "ldxdw" },
    { E(0x71,0,1,12,0), "ldxb+12" },
    { E(0x71,0,1,-1,0), "ldxb-1" },
    { E(0x71,0,1,32767,0), "ldxb far" },
    { E(0x71,2,1,0,0), "ldxb r2" },
    { E(0x71,0,10,0,0), "ldxb r10 base" },
    { E(0x71,0,2,0,0), "ldxb r2 base" },
    { E(0x62,0,0,0,0), "stw" },
    { E(0x63,0,1,0,0), "stxw" },
    { E(0x04,0,0,0,1), "add32" },
    { E(0xc4,0,0,0,1), "arsh32" },
    { E(0x07,1,0,0,1), "add r1,1" },
};
#define A2_N (sizeof A2 / sizeof A2[0])

static const struct { uint64_t e; const char *n; } C3[] = {
    { E(0x95,0,0,0,0), "exit" },
    { E(0x05,0,0,1,0), "ja+1" },
    { E(0x05,0,0,-1,0), "ja-1" },
    { E(0x15,0,0,-1,0), "jeq r0,0,-1" },
    { E(0xb7,0,0,0,1), "mov r0,1" },
    { E(0xb7,2,0,0,1), "mov r2,1" },
    { E(0xb7,5,0,0,2), "mov r5,2" },
    { E(0xb7,1,0,0,0), "mov r1,0" },
    { E(0xbf,3,1,0,0), "mov r3,r1" },
    { E(0x07,0,0,0,1), "add r0,1" },
    { E(0x37,0,0,0,2), "div r0,2" },
    { E(0x3f,0,2,0,0), "div r0,r2" },
    { E(0x71,0,1,0,0), "ldxb" },
    { E(0x85,0,0,0,1), "call1" },
    { E(0x85,0,0,0,2), "call2" },
    { E(0x87,0,0,0,0), "neg r0" },
    { E(0xd7,0,0,0,16), "bswap16" },
    { E(0x57,0,0,0,0xff), "and r0,0xff" },
    { E(0xdf,0,0,0,16), "bswapreg16" },
    { E(0xdf,0,0,0,8), "bswapreg8" },
};
#define C3_N (sizeof C3 / sizeof C3[0])

static unsigned long long sweep_small(void) {
    unsigned long long h = 0xcbf29ce484222325ull;
    for (unsigned i = 0; i < A2_N; i++)
    for (unsigned j = 0; j < A2_N; j++) {
        uint64_t ins[2] = { A2[i].e, A2[j].e };
        ic_status v = ic_program_check(ins, 2u);
        if (v == IC_OK) {
            for (int b = 0; b < 4; b++) {
                struct ebpf_result r;
                run_prog(ins, 2u, b, &r);
                if (!benign(r.fault)) {
                    violations++;
                    printf("small violation %s | %s batt=%d fault=%u\n",
                           A2[i].n, A2[j].n, b, r.fault);
                }
                h = fnv(h, r.fault);
                h = fnv(h, r.retval);
                h = fnv(h, r.insns_executed);
            }
            struct ebpf_result r1, r2;
            run_prog(ins, 2u, 0, &r1);
            run_prog(ins, 2u, 0, &r2);
            if (r1.retval != r2.retval || r1.fault != r2.fault ||
                r1.insns_executed != r2.insns_executed) violations++;
        } else if (v != IC_ERR_VALIDATE && v != IC_ERR_ARGUMENT) {
            violations++;
            printf("small odd verdict %d at %s | %s\n", (int)v,
                   A2[i].n, A2[j].n);
        }
        h = fnv(h, (unsigned)v);
    }
    for (unsigned i = 0; i < C3_N; i++)
    for (unsigned j = 0; j < C3_N; j++)
    for (unsigned k = 0; k < C3_N; k++) {
        uint64_t ins[3] = { C3[i].e, C3[j].e, C3[k].e };
        ic_status v = ic_program_check(ins, 3u);
        if (v == IC_OK) {
            for (int b = 0; b < 4; b++) {
                struct ebpf_result r;
                run_prog(ins, 3u, b, &r);
                if (!benign(r.fault)) {
                    violations++;
                    printf("small violation %s | %s | %s batt=%d fault=%u\n",
                           C3[i].n, C3[j].n, C3[k].n, b, r.fault);
                }
                h = fnv(h, r.fault);
                h = fnv(h, r.retval);
                h = fnv(h, r.insns_executed);
            }
        } else if (v != IC_ERR_VALIDATE && v != IC_ERR_ARGUMENT) {
            violations++;
        }
        h = fnv(h, (unsigned)v);
    }
    return h;
}

/* ---- sweep 4: single-bit flips of real programs ---- */

static const uint64_t F1[7] = {
    E(0x71,0,1,0,0), E(0xb7,1,0,0,0xFD), E(0x1d,0,1,2,0), E(0xb7,0,0,0,0),
    E(0x95,0,0,0,0), E(0xb7,0,0,0,1), E(0x95,0,0,0,0),
};
static const uint64_t F2[3] = { E(0xb7,0,0,0,0), E(0x05,0,0,-1,0),
                                E(0x95,0,0,0,0) };
static const uint64_t F3[3] = { E(0xb7,2,0,0,7), E(0x85,0,0,0,2),
                                E(0x95,0,0,0,0) };

static unsigned long long sweep_flip(void) {
    const struct { const uint64_t *ins; uint32_t cnt; } P[3] = {
        {F1, 7}, {F2, 3}, {F3, 3}
    };
    unsigned long long h = 0xcbf29ce484222325ull;
    for (unsigned p = 0; p < 3u; p++)
    for (unsigned w = 0; w < P[p].cnt; w++)
    for (unsigned bit = 0; bit < 64u; bit++) {
        uint64_t ins[8];
        memcpy(ins, P[p].ins, P[p].cnt * sizeof ins[0]);
        ins[w] ^= 1ull << bit;
        ic_status v = ic_program_check(ins, P[p].cnt);
        if (v == IC_OK) {
            struct ebpf_result r;
            run_prog(ins, P[p].cnt, 0, &r);
            if (!benign(r.fault)) {
                violations++;
                printf("flip violation p=%u w=%u bit=%u fault=%u\n",
                       p, w, bit, r.fault);
            }
            h = fnv(h, r.fault);
            h = fnv(h, r.retval);
        }
        h = fnv(h, (unsigned)v);
        h = fnv(h, p);
        h = fnv(h, w * 64u + bit);
    }
    return h;
}

/* ---- sweep 5: adversarial lattice cases with expected verdicts ---- */

static const struct {
    const char *name;
    uint64_t ins[4];
    uint32_t cnt;
    int accept;
    int fault;      /* -1 = any */
    int has_ret;
    uint64_t ret;
    int batt;
} ADV[] = {
    { "empty", {0,0,0,0}, 0, 0, -1, 0, 0, 0 },
    { "exit r0 unwritten", {E(0x95,0,0,0,0),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "ldxb exit", {E(0x71,0,1,0,0),E(0x95,0,0,0,0),0,0}, 2, 1, EBPF_OK, 1, 0, 0 },
    { "ldxw exit C", {E(0x61,0,1,0,0),E(0x95,0,0,0,0),0,0}, 2, 1, EBPF_OK,
                      1, 0x03020100ull, 2 },
    { "ldxb oob", {E(0x71,0,1,4,0),E(0x95,0,0,0,0),0,0}, 2, 1,
                   EBPF_FAULT_MEM, 0, 0, 2 },
    { "ldxb neg", {E(0x71,0,1,-1,0),E(0x95,0,0,0,0),0,0}, 2, 1,
                   EBPF_FAULT_MEM, 0, 0, 2 },
    { "ldxb far", {E(0x71,0,1,32767,0),E(0x95,0,0,0,0)}, 2, 1,
                   EBPF_FAULT_MEM, 0, 0, 0 },
    { "scalar base", {E(0xb7,1,0,0,0),E(0x71,0,1,0,0),0,0}, 2, 0, -1, 0, 0, 0 },
    { "alu ctx dst", {E(0x0f,1,1,0,0),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "mov ctx copy", {E(0xbf,3,1,0,0),E(0x71,0,3,0,0),0,0}, 2, 0, -1, 0, 0, 0 },
    { "scalar base 2", {E(0xb7,2,0,0,1),E(0x71,0,2,0,0),0,0}, 2, 0, -1, 0, 0, 0 },
    { "two ldx", {E(0x71,0,1,0,0),E(0x71,2,1,1,0),E(0x95,0,0,0,0)}, 3, 1,
                  EBPF_OK, 1, 0, 0 },
    { "branch both write", {E(0xb7,0,0,0,1),E(0x55,0,0,1,1),E(0xb7,0,0,0,5),
                            E(0x95,0,0,0,0)}, 4, 1, EBPF_OK, 1, 5, 0 },
    { "reg div0", {E(0xb7,0,0,0,9),E(0xb7,2,0,0,0),E(0x3f,0,2,0,0),
                   E(0x95,0,0,0,0)}, 4, 1, EBPF_FAULT_DIV0, 0, 0, 0 },
    { "div imm0", {E(0xb7,0,0,0,9),E(0x37,0,0,0,0),0,0}, 2, 0, -1, 0, 0, 0 },
    { "mod imm0", {E(0xb7,0,0,0,9),E(0x97,0,0,0,0),0,0}, 2, 0, -1, 0, 0, 0 },
    { "fp write", {E(0xb7,0,0,0,1),E(0xb7,10,0,0,2),E(0x95,0,0,0,0)}, 3, 1,
                   EBPF_FAULT_FP, 0, 0, 0 },
    { "self loop", {E(0xb7,0,0,0,0),E(0x05,0,0,-1,0),E(0x95,0,0,0,0)}, 3, 1,
                    EBPF_FAULT_STEPS, 0, 0, 0 },
    { "call 3", {E(0x85,0,0,0,3),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "call 0", {E(0x85,0,0,0,0),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "call 2 store", {E(0xb7,2,0,0,7),E(0x85,0,0,0,2),E(0x95,0,0,0,0)}, 3, 1,
                       EBPF_OK, 1, 0, 0 },
    { "call 1 load", {E(0x85,0,0,0,1),E(0x95,0,0,0,0)}, 2, 1, EBPF_OK, 1, 7, 0 },
    { "bswap imm8", {E(0xd7,0,0,0,8),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "bswap imm17", {E(0xd7,0,0,0,17),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "bswap imm-src", {E(0xd7,0,0,0,16),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "bswapreg 8", {E(0xdf,0,0,0,8),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "bswapreg 17", {E(0xdf,0,0,0,17),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "bswapreg 16", {E(0xb7,0,0,0,0x1234),E(0xdf,0,0,0,16),E(0x95,0,0,0,0)},
                      3, 1, EBPF_OK, 1, 0x3412ull, 0 },
    { "jmp32 call", {E(0x86,0,0,0,1),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "exit dst3", {E(0x95,3,0,0,0),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "ja src3", {E(0xb7,0,0,0,7),E(0x0d,0,3,0,0),E(0x95,0,0,0,0)}, 3, 1,
                  EBPF_OK, 1, 7, 0 },
    { "neg sx", {E(0xb7,0,0,0,5),E(0x8f,0,3,0,0),E(0x95,0,0,0,0)}, 3, 1,
                 EBPF_OK, 1, 0xFFFFFFFFFFFFFFFBull, 0 },
    { "stw", {E(0x62,0,0,0,0),0,0,0}, 1, 0, -1, 0, 0, 0 },
    { "ldxdw small ctx", {E(0x79,0,1,0,0),E(0x95,0,0,0,0)}, 2, 1,
                           EBPF_FAULT_MEM, 0, 0, 2 },
    { "ldxdw big ctx", {E(0x79,0,1,0,0),E(0x95,0,0,0,0)}, 2, 1, EBPF_OK, 1,
                        0x0706050403020100ull, 0 },
    { "fallthrough escape", {E(0xb7,0,0,0,1),E(0x15,0,0,-1,0),0,0}, 2, 0,
                              -1, 0, 0, 0 },
    { "backward ja loop", {E(0xb7,0,0,0,1),E(0x05,0,0,-1,0)}, 2, 1,
                            EBPF_FAULT_STEPS, 0, 0, 0 },
    { "ldxw exit A", {E(0x61,0,1,0,0),E(0x95,0,0,0,0),0,0}, 2, 1, EBPF_OK, 1,
                      0x03020100ull, 0 },
};
#define ADV_N (sizeof ADV / sizeof ADV[0])

static unsigned long long sweep_adv(void) {
    unsigned long long h = 0xcbf29ce484222325ull;
    for (unsigned i = 0; i < ADV_N; i++) {
        ic_status v = ic_program_check(ADV[i].ins, ADV[i].cnt);
        int okv = ADV[i].accept ? (v == IC_OK) : (v != IC_OK);
        if (!okv) {
            adv_mismatch++;
            printf("adv %s: verdict %d want %s\n", ADV[i].name, (int)v,
                   ADV[i].accept ? "accept" : "reject");
        }
        if (ADV[i].accept && v == IC_OK) {
            struct ebpf_result r;
            run_prog(ADV[i].ins, ADV[i].cnt, ADV[i].batt, &r);
            if (!benign(r.fault)) {
                violations++;
                printf("adv %s: fault %u violates the theorem\n",
                       ADV[i].name, r.fault);
            }
            if (ADV[i].fault >= 0 && r.fault != ADV[i].fault) {
                adv_mismatch++;
                printf("adv %s: fault %u want %d\n", ADV[i].name, r.fault,
                       ADV[i].fault);
            }
            if (ADV[i].has_ret && r.retval != ADV[i].ret) {
                adv_mismatch++;
                printf("adv %s: ret %llx want %llx\n", ADV[i].name,
                       (unsigned long long)r.retval,
                       (unsigned long long)ADV[i].ret);
            }
            h = fnv(h, i);
            h = fnv(h, r.fault);
            h = fnv(h, r.retval);
            h = fnv(h, r.insns_executed);
        } else {
            h = fnv(h, i);
            h = fnv(h, (unsigned)v);
            h = fnv(h, 0xdeadull);
            h = fnv(h, 0);
        }
    }
    return h;
}

int main(void) {
    void *win = mmap((void *)CTX_BASE, 0x1000u, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                     -1, 0);
    if (win != (void *)CTX_BASE) {
        printf("RESULT: SOUNDNESS FAIL (fixed context window unavailable)\n");
        return 2;
    }
    memcpy((void *)CTX_BASE, CTX_A, 16);
    memcpy((void *)(CTX_BASE + 0x100u), CTX_B, 16);
    memcpy((void *)(CTX_BASE + 0x200u), CTX_C, 4);
    BATT[0].ctx = (uint8_t *)CTX_BASE;
    BATT[1].ctx = (uint8_t *)(CTX_BASE + 0x100u);
    BATT[2].ctx = (uint8_t *)(CTX_BASE + 0x200u);
    BATT[3].ctx = (uint8_t *)CTX_BASE;
    unsigned long long ht = sweep_tables();
    unsigned long long hf = sweep_flow();
    unsigned long long hs = sweep_small();
    unsigned long long hfl = sweep_flip();
    unsigned long long ha = sweep_adv();
    int bad = violations || table_mismatch || flow_mismatch || adv_mismatch;
    printf("DIGEST table=%016llx flow=%016llx small=%016llx flip=%016llx "
           "adv=%016llx\n", ht, hf, hs, hfl, ha);
    printf("RESULT: SOUNDNESS %s (violations=%d table=%d flow=%d adv=%d)\n",
           bad ? "FAIL" : "PASS", violations, table_mismatch, flow_mismatch,
           adv_mismatch);
    return bad != 0;
}
