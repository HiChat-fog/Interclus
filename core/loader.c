/* loader.c — the module validation gate (contract v1).
 * A pass here means the descriptor is well-formed; the PMP boundary
 * remains the safety guarantee. Native modules are PMP-shaped; eBPF
 * modules are instruction arrays and follow interpreter rules. */

#include "contract.h"
#include "loader.h"

#define IC_MIN_REGION 0x400u
#define IC_VFY __attribute__((section(".vfy_text")))

static int region_ok(uint32_t base, uint32_t size) {
    return base % 0x1000u == 0 && size >= IC_MIN_REGION &&
           (size & (size - 1u)) == 0 && base + size > base;
}

ic_status ic_compartment_check(const ic_compartment_spec *s) {
    if (!s) return IC_ERR_ARGUMENT;
    if (!region_ok(s->text_base, s->text_size)) return IC_ERR_ARGUMENT;
    if (!region_ok(s->sram_base, s->sram_size)) return IC_ERR_ARGUMENT;
    return IC_OK;
}

static ic_status check_native(const ic_module_desc *d) {
    if (!region_ok(d->text_base, d->text_size)) return IC_ERR_ARGUMENT;
    if (!region_ok(d->sram_base, d->sram_size)) return IC_ERR_ARGUMENT;
    if ((d->entry_offset & 1u) || d->entry_offset >= d->text_size)
        return IC_ERR_ARGUMENT;
    return IC_OK;
}

static ic_status check_ebpf(const ic_module_desc *d) {
    if (d->text_base && d->text_base % 8u) return IC_ERR_ARGUMENT;
    if (d->text_size % 8u || d->text_size < 8u) return IC_ERR_ARGUMENT;
    if (d->entry_offset % 8u || d->entry_offset >= d->text_size)
        return IC_ERR_ARGUMENT;
    if (d->sram_size && d->sram_base % 4u) return IC_ERR_ARGUMENT;
    if (d->sram_base && !d->sram_size) return IC_ERR_ARGUMENT;
    return IC_OK;
}

ic_status ic_module_check(const ic_module_desc *d) {
    if (!d) return IC_ERR_ARGUMENT;
    if (d->magic != IC_MODULE_MAGIC) return IC_ERR_CONTRACT;
    if (d->contract_ver != IC_CONTRACT_VERSION) return IC_ERR_CONTRACT;
    if (d->kind != IC_MODULE_EBPF && d->kind != IC_MODULE_NATIVE)
        return IC_ERR_ARGUMENT;
    if (d->reserved != 0u) return IC_ERR_ARGUMENT;
    return (d->kind == IC_MODULE_EBPF) ? check_ebpf(d) : check_native(d);
}

/* opcodes the interpreter executes; LD/ST/STX classes never appear in a
 * program this core accepts (stores are rejected at run time anyway) */
static int opcode_known(uint8_t op) {
    switch (op & 0x07u) {
    case 0x01u:                       /* LDX: plain context loads */
        return (op & 0xe0u) == 0x60u;
    case 0x04u: case 0x07u: {         /* ALU32 / ALU64 */
        uint8_t o = op & 0xf0u;
        if (o == 0xd0u) return (op & 0x08u) != 0;   /* endian swap, reg-src */
        return o <= 0xc0u;
    }
    case 0x05u: case 0x06u: {         /* JMP / JMP32 */
        uint8_t o = op & 0xf0u;
        return o <= 0x90u || (o >= 0xa0u && o <= 0xd0u);
    }
    default:
        return 0;
    }
}

/* ---- register gate with types ----
 * A register must be written before any instruction reads it, and LDX
 * requires a context pointer as its base: a scalar used as an address
 * is a load-time reject, not a run-time fault. Types are 2 bits per
 * register packed in a u32 — 00 BOTTOM (never written), 01 SCALAR,
 * 10 PTR_CTX — so the whole register file is one word. r1 arrives as
 * PTR_CTX; PTR_CTX never propagates: any ALU over it is rejected (the
 * address arithmetic this ISA subset needs is the LDX offset itself),
 * and a join intersects like the written-mask it replaces, so the
 * worklist and its fixed point carry over unchanged. r10 stays
 * writable: writing it faults FP at run, which the rollback drill
 * depends on, and no later read can observe the write. */

#define T_BOTTOM 0x0u
#define T_SCALAR 0x1u
#define T_CTX    0x2u
#define T_WIDE   0x3u
#define T_MASK   0x3u
#define R_CNT    11u
#define IC_LOOP_MAX (1u << 20)

static uint32_t reg_type(uint32_t st, uint8_t r) {
    return (st >> (2u * r)) & T_MASK;
}

static uint32_t set_type(uint32_t st, uint8_t r, uint32_t t) {
    return (st & ~(T_MASK << (2u * r))) | (t << (2u * r));
}

#define SCALARS_ALL 0x155555u                 /* r0..r10 all SCALAR */

static uint32_t insn_reads(uint64_t e) {
    uint8_t op  = (uint8_t)(e & 0xffu);
    uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
    uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
    uint8_t cls = op & 0x07u;
    uint8_t hi  = op & 0xf0u;
    if (cls == 0x04u || cls == 0x07u) {           /* ALU32 / ALU64 */
        if (hi == 0xb0u)                          /* MOV: dst overwritten */
            return (op & 0x08u) ? 1u << src : 0u;
        if (hi == 0x80u || hi == 0xd0u)           /* neg / endian swap:
                                                     the arg never lands */
            return 1u << dst;
        return (1u << dst) | ((op & 0x08u) ? 1u << src : 0u);
    }
    if (cls == 0x05u || cls == 0x06u) {           /* JMP / JMP32 */
        if (hi == 0x90u) return 1u;               /* exit reads r0 */
        if (hi == 0x80u)                          /* call reads r1; helper 2
                                                     also reads r2 */
            return (((e >> 32) & 0xffffffffu) == 2u)
                       ? ((1u << 1) | (1u << 2)) : (1u << 1);
        if (hi == 0x00u) return 0;                /* ja: taken, reads none */
        return (1u << dst) | ((op & 0x08u) ? 1u << src : 0u);
    }
    if (cls == 0x01u)                             /* LDX reads the base */
        return 1u << src;
    return 0;
}

static uint32_t insn_writes(uint64_t e) {
    uint8_t op  = (uint8_t)(e & 0xffu);
    uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
    uint8_t cls = op & 0x07u;
    if (cls == 0x01u || cls == 0x04u || cls == 0x07u) return 1u << dst;
    if ((cls == 0x05u || cls == 0x06u) && (op & 0xf0u) == 0x80u)
        return 1u;                                /* call returns into r0 */
    return 0;
}

/* successors of pc; the jump target itself is already range-checked, so
 * only the fall-through can leave the image */
static int insn_succ(uint64_t e, uint32_t pc, uint32_t succ[2]) {
    uint8_t op  = (uint8_t)(e & 0xffu);
    uint8_t cls = op & 0x07u;
    if (cls == 0x05u || cls == 0x06u) {
        uint8_t hi = op & 0xf0u;
        if (hi == 0x90u) return 0;                /* exit */
        if (hi == 0x00u) {                        /* ja: taken only */
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

typedef struct {
    uint32_t type;
    uint32_t lo[R_CNT], hi[R_CNT];
} vstate;

_Static_assert(sizeof(vstate) == 92u, "workspace layout");

static IC_VFY void st_init(vstate *s) {
    s->type = 0u;
    for (uint32_t r = 0; r < R_CNT; r++) s->lo[r] = s->hi[r] = 0u;
}

static IC_VFY void st_iv(vstate *s, uint8_t r, uint64_t lo, uint64_t hi) {
    if (lo > hi || hi > 0xFFFFFFFFull) {
        s->type = set_type(s->type, r, T_WIDE);
    } else {
        s->type = set_type(s->type, r, T_SCALAR);
        s->lo[r] = (uint32_t)lo;
        s->hi[r] = (uint32_t)hi;
    }
}

static IC_VFY uint32_t ceil_mask(uint32_t hi) {
    uint32_t m = 1u;
    while (m <= hi && m != 0u) m <<= 1;
    return m - 1u;
}

static IC_VFY uint32_t width_of(uint8_t op) {
    if (op == 0x71u) return 1u;
    if (op == 0x69u) return 2u;
    if (op == 0x61u) return 4u;
    return 8u;
}

static IC_VFY void st_transfer(const uint64_t e, const vstate *in, vstate *out) {
    uint8_t op = (uint8_t)(e & 0xffu);
    uint8_t cls = op & 0x07u;
    uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
    uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
    uint8_t hi = op & 0xf0u;
    *out = *in;
    if (cls == 0x01u) {
        if (op == 0x71u) st_iv(out, dst, 0u, 0xFFu);
        else if (op == 0x69u) st_iv(out, dst, 0u, 0xFFFFu);
        else if (op == 0x61u) st_iv(out, dst, 0u, 0xFFFFFFFFull);
        else out->type = set_type(out->type, dst, T_WIDE);
        return;
    }
    if (cls == 0x05u && hi == 0x80u) {
        uint32_t h = (uint32_t)((e >> 32) & 0xffffffffu);
        if (h == 2u) st_iv(out, 0u, 0u, 0u);
        else st_iv(out, 0u, 0u, 0xFFFFFFFFull);
        return;
    }
    if (cls != 0x04u && cls != 0x07u) return;
    {
        int is64 = (cls == 0x07u);
        int wide = 0, wide_rhs = 0;
        uint32_t lo = 0u, vhi = 0u, rlo = 0u, rhi = 0u;
        if (hi == 0x80u) {
            if (reg_type(in->type, dst) == T_SCALAR &&
                in->lo[dst] == 0u && in->hi[dst] == 0u)
                st_iv(out, dst, 0u, 0u);
            else out->type = set_type(out->type, dst, T_WIDE);
            return;
        }
        if (hi == 0xd0u) {
            uint32_t size = (uint32_t)((e >> 32) & 0xffffffffu);
            if (reg_type(in->type, dst) == T_SCALAR && in->lo[dst] == in->hi[dst]) {
                uint64_t v = in->lo[dst];
                if (size == 16u) v = (uint64_t)__builtin_bswap16((uint16_t)v);
                else if (size == 32u) v = (uint64_t)__builtin_bswap32((uint32_t)v);
                else if (size == 64u) v = __builtin_bswap64(v);
                st_iv(out, dst, v, v);
            } else out->type = set_type(out->type, dst, T_WIDE);
            return;
        }
        if ((op & 0x08u) == 0u) {
            int32_t imm = (int32_t)((e >> 32) & 0xffffffffu);
            if (imm < 0) wide_rhs = 1;
            else { rlo = rhi = (uint32_t)imm; }
        } else if (reg_type(in->type, src) == T_SCALAR) {
            rlo = in->lo[src];
            rhi = in->hi[src];
        } else wide_rhs = 1;
        if (hi == 0xb0u) {
            if (wide_rhs) out->type = set_type(out->type, dst, T_WIDE);
            else st_iv(out, dst, rlo, rhi);
            return;
        }
        if (reg_type(in->type, dst) != T_SCALAR) wide = 1;
        else { lo = in->lo[dst]; vhi = in->hi[dst]; }
        if (wide || wide_rhs) {
            out->type = set_type(out->type, dst, T_WIDE);
            return;
        }
        switch (hi) {
        case 0x00u: st_iv(out, dst, (uint64_t)lo + rlo, (uint64_t)vhi + rhi); break;
        case 0x10u:
            if (lo >= rhi) st_iv(out, dst, (uint64_t)lo - rhi, (uint64_t)vhi - rlo);
            else out->type = set_type(out->type, dst, T_WIDE);
            break;
        case 0x20u: st_iv(out, dst, (uint64_t)lo * rlo, (uint64_t)vhi * rhi); break;
        case 0x30u:
            if (rlo == 0u) out->type = set_type(out->type, dst, T_WIDE);
            else st_iv(out, dst, (uint64_t)lo / rhi, (uint64_t)vhi / rlo);
            break;
        case 0x90u:
            if (rlo == 0u) out->type = set_type(out->type, dst, T_WIDE);
            else {
                uint32_t m = rhi - 1u;
                st_iv(out, dst, 0u, vhi < m ? vhi : m);
            }
            break;
        case 0x40u:
            st_iv(out, dst, lo > rlo ? lo : rlo,
                  ceil_mask(vhi > rhi ? vhi : rhi));
            break;
        case 0x50u:
            st_iv(out, dst, 0u, vhi < rhi ? vhi : rhi);
            break;
        case 0xa0u:
            st_iv(out, dst, 0u, ceil_mask(vhi > rhi ? vhi : rhi));
            break;
        case 0x60u:
            if (op & 0x08u) { out->type = set_type(out->type, dst, T_WIDE); break; }
            {
                uint32_t sh = (uint32_t)((e >> 32) & (is64 ? 63u : 31u));
                st_iv(out, dst, (uint64_t)lo << sh, (uint64_t)vhi << sh);
            }
            break;
        case 0x70u:
        case 0xc0u:
            if (op & 0x08u) { out->type = set_type(out->type, dst, T_WIDE); break; }
            {
                uint32_t sh = (uint32_t)((e >> 32) & (is64 ? 63u : 31u));
                st_iv(out, dst, (uint64_t)lo >> sh, (uint64_t)vhi >> sh);
            }
            break;
        default:
            out->type = set_type(out->type, dst, T_WIDE);
        }
    }
}

static IC_VFY uint32_t type_join(uint32_t a, uint32_t b) {
    if (a == b) return a;
    if (a == T_BOTTOM || b == T_BOTTOM) return T_BOTTOM;
    return T_WIDE;
}

static IC_VFY int st_merge(vstate *dst, const vstate *src, uint8_t *seen, int widen) {
    int ch = 0;
    if (!*seen) {
        *dst = *src;
        *seen = 1u;
        return 1;
    }
    for (uint8_t r = 0; r < R_CNT; r++) {
        uint32_t ta = reg_type(dst->type, r);
        uint32_t tb = reg_type(src->type, r);
        uint32_t tj = type_join(ta, tb);
        if (tj != ta) {
            dst->type = set_type(dst->type, r, tj);
            ch = 1;
            if (tj == T_SCALAR) {
                dst->lo[r] = src->lo[r];
                dst->hi[r] = src->hi[r];
            } else {
                dst->lo[r] = 0u;
                dst->hi[r] = 0u;
            }
        } else if (tj == T_SCALAR) {
            uint32_t nl = dst->lo[r] < src->lo[r] ? dst->lo[r] : src->lo[r];
            uint32_t nh = dst->hi[r] > src->hi[r] ? dst->hi[r] : src->hi[r];
            if (widen) {
                if (nl < dst->lo[r]) nl = 0u;
                if (nh > dst->hi[r]) nh = 0xFFFFFFFFu;
            }
            if (nl != dst->lo[r] || nh != dst->hi[r]) {
                dst->lo[r] = nl;
                dst->hi[r] = nh;
                ch = 1;
            }
        }
    }
    return ch;
}

/* bounded-loop proof: straight-line preamble, one exit compare at the
 * header, a single constant decrement per iteration, one back edge. The
 * entry interval comes from replaying the preamble through the same
 * interval transfer, so the bound is an abstract-interpretation result. */
static IC_VFY int loop_bounded(const uint64_t *ins, uint32_t head, uint32_t tail) {
    vstate s, out;
    uint64_t e;
    uint8_t op, hi, r;
    int32_t K;
    uint32_t step = 0, writes = 0;
    if (head == 0u || tail <= head) return 0;
    st_init(&s);
    s.type = set_type(0u, 1u, T_CTX);
    for (uint32_t pc = 0; pc < head; pc++) {
        uint32_t sc[2];
        int ns = insn_succ(ins[pc], pc, sc);
        if (ns != 1 || sc[0] != pc + 1u) return 0;
        st_transfer(ins[pc], &s, &out);
        s = out;
    }
    e = ins[head];
    op = (uint8_t)(e & 0xffu);
    hi = op & 0xf0u;
    r = (uint8_t)((e >> 8) & 0x0fu);
    K = (int32_t)((e >> 32) & 0xffffffffu);
    if ((op & 0x07u) != 0x05u || (op & 0x08u) || K < 0) return 0;
    if (hi != 0x10u && hi != 0xa0u && hi != 0xb0u) return 0;  /* JEQ/JLT/JLE */
    {
        uint32_t sc[2];
        int ns = insn_succ(ins[head], head, sc);
        if (ns != 2) return 0;
        if (sc[0] != head + 1u || sc[1] <= tail) return 0;
    }
    for (uint32_t pc = head + 1u; pc <= tail; pc++) {
        uint32_t sc[2];
        int ns = insn_succ(ins[pc], pc, sc);
        uint32_t want = (pc == tail) ? head : pc + 1u;
        if (ns != 1 || sc[0] != want) return 0;
    }
    for (uint32_t pc = head; pc <= tail; pc++) {
        uint64_t x = ins[pc];
        uint8_t xo = (uint8_t)(x & 0xffu);
        if (!(insn_writes(x) & (1u << r))) continue;
        writes++;
        if ((xo & 0x07u) == 0x07u && (xo & 0xf0u) == 0x10u &&
            (xo & 0x08u) == 0u && ((x >> 8) & 0x0fu) == r &&
            (int32_t)((x >> 32) & 0xffffffffu) > 0)
            step = (uint32_t)((x >> 32) & 0xffffffffu);
        else
            return 0;
    }
    if (writes != 1u || step == 0u) return 0;
    if (reg_type(s.type, r) != T_SCALAR) return 0;
    {
        uint32_t hi_r = s.hi[r];
        uint64_t iters;
        if (hi == 0x10u) {
            if (s.lo[r] != hi_r || hi_r < (uint32_t)K ||
                ((hi_r - (uint32_t)K) % step) != 0u)
                return 0;
            iters = ((uint64_t)hi_r - (uint32_t)K) / step + 1u;
        } else if (hi == 0xa0u) {
            if (K == 0) return 0;
            iters = hi_r >= (uint32_t)K
                        ? ((uint64_t)hi_r - (uint32_t)K) / step + 1u
                        : 1u;
        } else {
            iters = hi_r > (uint32_t)K
                        ? ((uint64_t)hi_r - (uint32_t)K) / step + 1u
                        : 1u;
        }
        return iters <= IC_LOOP_MAX;
    }
}

static IC_VFY ic_status check_regs_full(const uint64_t *ins, uint32_t cnt,
                                 uint32_t ctx_size, const ic_region *region,
                                 ic_vfy_ws *ws) {
    vstate *st = (vstate *)ws->w;
    uint8_t *pend = (uint8_t *)(st + IC_PROG_MAX_INSNS);
    uint8_t *seen = pend + IC_PROG_MAX_INSNS;
    for (uint32_t i = 0; i < cnt; i++) {
        st_init(&st[i]);
        pend[i] = 0u;
        seen[i] = 0u;
    }
    st[0].type = set_type(st[0].type, 1u, T_CTX);
    seen[0] = 1u;
    pend[0] = 1u;
    for (;;) {
        uint32_t pc = cnt;
        vstate out;
        for (uint32_t i = 0; i < cnt; i++)
            if (pend[i]) { pc = i; break; }
        if (pc == cnt) break;
        pend[pc] = 0u;
        {
            uint64_t e = ins[pc];
            uint8_t op = (uint8_t)(e & 0xffu);
            uint8_t cls = op & 0x07u;
            uint8_t hi = op & 0xf0u;
            uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
            uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
            vstate *in = &st[pc];
            uint32_t reads = insn_reads(e);
            for (uint8_t r = 0; r < 11u; r++) {
                uint32_t t;
                if (!(reads & (1u << r))) continue;
                t = reg_type(in->type, r);
                if (t == T_BOTTOM) return IC_ERR_VALIDATE;
                if (cls == 0x01u) {
                    if (t != T_CTX) return IC_ERR_VALIDATE;
                    if (ctx_size) {
                        int32_t off = (int16_t)((e >> 16) & 0xffffu);
                        uint32_t w = width_of(op);
                        if (off < 0 || (uint32_t)off + w > ctx_size)
                            return IC_ERR_VALIDATE;
                    }
                }
                if ((cls == 0x04u || cls == 0x07u) && t == T_CTX)
                    return IC_ERR_VALIDATE;
            }
            if ((cls == 0x04u || cls == 0x07u) &&
                (hi == 0x30u || hi == 0x90u) && !(op & 0x08u) &&
                ((e >> 32) & 0xffffffffu) == 0u)
                return IC_ERR_VALIDATE;
            if (region && cls == 0x05u && hi == 0x80u) {
                uint32_t h = (uint32_t)((e >> 32) & 0xffffffffu);
                if (h == 1u && !(region->perms & IC_REGION_R))
                    return IC_ERR_VALIDATE;
                if (h == 2u && !(region->perms & IC_REGION_W))
                    return IC_ERR_VALIDATE;
            }
            (void)dst; (void)src;
        }
        st_transfer(ins[pc], &st[pc], &out);
        {
            uint32_t succ[2];
            int ns = insn_succ(ins[pc], pc, succ);
            for (int k = 0; k < ns; k++) {
                if (succ[k] >= cnt) return IC_ERR_VALIDATE;
                if (st_merge(&st[succ[k]], &out, &seen[succ[k]],
                             succ[k] <= pc))
                    pend[succ[k]] = 1u;
            }
        }
    }
    for (uint32_t pc = 0; pc < cnt; pc++) {
        uint32_t succ[2];
        int ns = insn_succ(ins[pc], pc, succ);
        for (int k = 0; k < ns; k++) {
            if (succ[k] <= pc && !loop_bounded(ins, succ[k], pc))
                return IC_ERR_VALIDATE;
        }
    }
    return IC_OK;
}

static IC_VFY ic_status prog_static(const uint64_t *ins, uint32_t cnt) {
    if (!ins || !cnt || cnt > IC_PROG_MAX_INSNS) return IC_ERR_ARGUMENT;
    for (uint32_t pc = 0; pc < cnt; pc++) {
        uint64_t e = ins[pc];
        uint8_t op  = (uint8_t)(e & 0xffu);
        uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
        uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
        int16_t off = (int16_t)((e >> 16) & 0xffffu);
        if (dst > 10u || src > 10u) return IC_ERR_VALIDATE;
        if ((op & 0x07u) == 0x01u && dst == 10u)
            return IC_ERR_VALIDATE;       /* LDX into fp: the interpreter
                                             faults it as OPCODE — the
                                             verifier owns that promise */
        if (!opcode_known(op)) return IC_ERR_VALIDATE;
        if ((op & 0x07u) == 0x04u || (op & 0x07u) == 0x07u) {
            if ((op & 0xf0u) == 0xd0u && (op & 0x08u) &&
                (e >> 32) != 16u && (e >> 32) != 32u && (e >> 32) != 64u)
                return IC_ERR_VALIDATE;           /* bswap: only 16/32/64
                                                     have runtime meaning */
        }
        if ((op & 0x07u) == 0x05u || (op & 0x07u) == 0x06u) {
            uint8_t hi = op & 0xf0u;
            if (hi == 0x90u) continue;              /* exit */
            if (hi == 0x80u) {                      /* call: helpers 1 and 2,
                                                       JMP64 class only */
                if ((op & 0x07u) == 0x06u) return IC_ERR_VALIDATE;
                if (op & 0x08u) return IC_ERR_VALIDATE;
                {
                    uint32_t h = (uint32_t)((e >> 32) & 0xffffffffu);
                    if (h == 0u || h > 2u) return IC_ERR_VALIDATE;
                }
                continue;
            }
            {
                int32_t target = (int32_t)pc + 1 + off;
                if (target < 0 || target >= (int32_t)cnt)
                    return IC_ERR_VALIDATE;
            }
        }
    }
    return IC_OK;
}

IC_VFY
ic_status ic_program_check_ws(const uint64_t *ins, uint32_t cnt,
                              uint32_t ctx_size, const ic_region *region,
                              ic_vfy_ws *ws) {
    ic_status v;
    if (!ws) return IC_ERR_ARGUMENT;
    v = prog_static(ins, cnt);
    if (v != IC_OK) return v;
    return check_regs_full(ins, cnt, ctx_size, region, ws);
}

IC_VFY
ic_status ic_program_check_ctx(const uint64_t *ins, uint32_t cnt,
                               uint32_t ctx_size, const ic_region *region) {
    ic_vfy_ws ws;
    return ic_program_check_ws(ins, cnt, ctx_size, region, &ws);
}

IC_VFY
ic_status ic_program_check(const uint64_t *ins, uint32_t cnt) {
    return ic_program_check_ctx(ins, cnt, 0u, 0);
}

IC_VFY
ic_status ic_program_check_region(const uint64_t *ins, uint32_t cnt,
                                  const ic_region *r) {
    if (!r || !r->cells || (r->cells & (r->cells - 1u)) != 0u ||
        (r->perms & ~(IC_REGION_R | IC_REGION_W)) != 0u)
        return IC_ERR_ARGUMENT;
    return ic_program_check_ctx(ins, cnt, 0u, r);
}
