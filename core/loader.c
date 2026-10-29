/* loader.c — the module validation gate (contract v1).
 * A pass here means the descriptor is well-formed; the PMP boundary
 * remains the safety guarantee. Native modules are PMP-shaped; eBPF
 * modules are instruction arrays and follow interpreter rules. */

#include "contract.h"
#include "loader.h"

#define IC_MIN_REGION 0x400u

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
#define T_MASK   0x3u

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

static ic_status check_regs(const uint64_t *ins, uint32_t cnt) {
    uint32_t in_m[IC_PROG_MAX_INSNS];
    uint8_t pending[IC_PROG_MAX_INSNS];
    /* lattice: per register 00 BOTTOM (unwritten on some path), 01
     * SCALAR, 10 PTR_CTX, 11 TOP (unconstrained — the optimistic
     * start that lets loop heads converge; & meets it down). */
    for (uint32_t i = 0; i < cnt; i++) {
        in_m[i] = 0xFFFFFFFFu;                    /* every reg TOP */
        pending[i] = 1u;
    }
    {   /* entry: r1 = ctx pointer, every other register BOTTOM */
        uint32_t entry = 0u;                      /* all BOTTOM */
        in_m[0] = set_type(entry, 1, T_CTX);
    }
    for (;;) {
        uint32_t pc = cnt;
        for (uint32_t i = 0; i < cnt; i++)
            if (pending[i]) { pc = i; break; }
        if (pc == cnt) break;                     /* fixed point */
        pending[pc] = 0;
        {
            uint64_t e = ins[pc];
            uint8_t op  = (uint8_t)(e & 0xffu);
            uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
            uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
            uint8_t cls = op & 0x07u, hi = op & 0xf0u;
            uint32_t st = in_m[pc];
            /* every register this insn reads must be written (BOTTOM
             * fails) and carry a type the insn accepts */
            {
                uint32_t reads = insn_reads(e);
                for (uint8_t r = 0; r < 11u; r++) {
                    if (!(reads & (1u << r))) continue;
                    uint32_t t = reg_type(st, r);
                    if (t == T_BOTTOM) return IC_ERR_VALIDATE;
                    if (cls == 0x01u && t != T_CTX)
                        return IC_ERR_VALIDATE;   /* LDX base must be ctx */
                    if ((cls == 0x04u || cls == 0x07u) && t == T_CTX)
                        return IC_ERR_VALIDATE;   /* ALU over ctx: reject */
                }
            }
            if ((cls == 0x04u || cls == 0x07u) &&
                (hi == 0x30u || hi == 0x90u) && !(op & 0x08u) &&
                ((e >> 32) & 0xffffffffu) == 0u)
                return IC_ERR_VALIDATE;           /* div/mod by imm 0 */
            /* out-state: writes give SCALAR, call clobbers the caller-
             * saved convention, everything else carries over */
            uint32_t out = st;
            {
                uint32_t writes = insn_writes(e);
                for (uint8_t r = 0; r < 11u; r++) {
                    if (writes & (1u << r))
                        out = set_type(out, r, T_SCALAR);
                }
                if ((cls == 0x05u || cls == 0x06u) && hi == 0x80u) {
                    /* this interpreter's helpers touch only the map
                     * and r0 — every register is preserved except the
                     * return value */
                    out = set_type(out, 0, T_SCALAR);
                }
            }
            uint32_t succ[2];
            int ns = insn_succ(e, pc, succ);
            for (int k = 0; k < ns; k++) {
                if (succ[k] >= cnt) return IC_ERR_VALIDATE;
                {
                    uint32_t merged = in_m[succ[k]] & out;
                    if (merged != in_m[succ[k]]) {
                        in_m[succ[k]] = merged;
                        pending[succ[k]] = 1u;
                    }
                }
            }
        }
    }
    return IC_OK;
}

ic_status ic_program_check(const uint64_t *ins, uint32_t cnt) {
    if (!ins || !cnt || cnt > IC_PROG_MAX_INSNS) return IC_ERR_ARGUMENT;
    for (uint32_t pc = 0; pc < cnt; pc++) {
        uint64_t e = ins[pc];
        uint8_t op  = (uint8_t)(e & 0xffu);
        uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
        uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
        int16_t off = (int16_t)((e >> 16) & 0xffffu);
        if (dst > 10u || src > 10u) return IC_ERR_VALIDATE;
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
    return check_regs(ins, cnt);
}
