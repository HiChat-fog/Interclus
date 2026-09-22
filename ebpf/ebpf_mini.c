/* eBPF subset interpreter: 64-bit semantics on RV32, byte-exact on
 * both x86-64 (host tests) and the board. Faults never touch memory. */

#include "ebpf_mini.h"

static void jiema(uint64_t e, struct ebpf_insn *d) {
    d->opcode = (uint8_t)(e & 0xff);
    d->dst    = (uint8_t)((e >> 8) & 0x0f);
    d->src    = (uint8_t)((e >> 12) & 0x0f);
    d->off    = (int16_t)((e >> 16) & 0xffff);
    d->imm    = (int32_t)((e >> 32) & 0xffffffffu);
}

#define CLS_LDX   0x01
#define CLS_ST    0x02
#define CLS_STX   0x03
#define CLS_ALU   0x04
#define CLS_JMP   0x05
#define CLS_JMP32 0x06
#define CLS_ALU64 0x07

#define ALU_ADD 0x00
#define ALU_SUB 0x10
#define ALU_MUL 0x20
#define ALU_DIV 0x30
#define ALU_OR  0x40
#define ALU_AND 0x50
#define ALU_LSH 0x60
#define ALU_RSH 0x70
#define ALU_NEG 0x80
#define ALU_MOD 0x90
#define ALU_XOR 0xa0
#define ALU_MOV 0xb0
#define ALU_ARSH 0xc0
#define ALU_END 0xd0

#define JMP_JA   0x00
#define JMP_JEQ  0x10
#define JMP_JGT  0x20
#define JMP_JGE  0x30
#define JMP_JSET 0x40
#define JMP_JNE  0x50
#define JMP_JSGT 0x60
#define JMP_JSGE 0x70
#define JMP_CALL 0x80
#define JMP_EXIT 0x90
#define JMP_JLT  0xa0
#define JMP_JLE  0xb0
#define JMP_JSLT 0xc0
#define JMP_JSLE 0xd0

#define SRC_X 0x08

#define MODE_MEM 0x60

static uint64_t load_le(const uint8_t *m, uint8_t size) {
    switch (size) {
    case 1: return (uint64_t)m[0];
    case 2: return (uint64_t)m[0] | ((uint64_t)m[1] << 8);
    case 4: return (uint64_t)m[0] | ((uint64_t)m[1] << 8)
                 | ((uint64_t)m[2] << 16) | ((uint64_t)m[3] << 24);
    default: return (uint64_t)m[0] | ((uint64_t)m[1] << 8)
                 | ((uint64_t)m[2] << 16) | ((uint64_t)m[3] << 24)
                 | ((uint64_t)m[4] << 32) | ((uint64_t)m[5] << 40)
                 | ((uint64_t)m[6] << 48) | ((uint64_t)m[7] << 56);
    }
}

int ebpf_run(const struct ebpf_prog *p, struct ebpf_result *r) {
    uint64_t regs[11] = {0};
    uint32_t steps = 0, pc = 0;
    struct ebpf_insn in;
    r->fault = EBPF_OK;
    r->insns_executed = 0;
    regs[1] = (uint64_t)(uintptr_t)p->ctx;

    for (;;) {
        uint8_t cls, op;
        if (pc >= p->insn_cnt) { r->fault = EBPF_FAULT_PC; break; }
        if (++steps > p->max_steps) { r->fault = EBPF_FAULT_STEPS; break; }
        jiema(p->ins[pc], &in);
        r->insns_executed++;
        cls = in.opcode & 0x07;
        op  = in.opcode & 0xf0;

        if (cls == CLS_ALU64 || cls == CLS_ALU) {
            int is64 = (cls == CLS_ALU64);
            uint64_t arg;
            uint64_t v;
            uint8_t shift;
            if (in.opcode & SRC_X) arg = regs[in.src];
            else arg = is64 ? (uint64_t)(int64_t)in.imm
                            : (uint64_t)(uint32_t)in.imm;
            if (in.dst == 10) { r->fault = EBPF_FAULT_FP; goto out; }
            v = regs[in.dst];
            switch (op) {
            case ALU_ADD: v += arg; break;
            case ALU_SUB: v -= arg; break;
            case ALU_MUL: v *= arg; break;
            case ALU_DIV:
                if (arg == 0) { r->fault = EBPF_FAULT_DIV0; goto out; }
                if (is64) v /= arg;
                else v = (uint32_t)v / (uint32_t)arg;
                break;
            case ALU_MOD:
                if (arg == 0) { r->fault = EBPF_FAULT_DIV0; goto out; }
                if (is64) v %= arg;
                else v = (uint32_t)v % (uint32_t)arg;
                break;
            case ALU_OR:  v |= arg; break;
            case ALU_AND: v &= arg; break;
            case ALU_XOR: v ^= arg; break;
            case ALU_MOV: v = arg; break;
            case ALU_LSH:
                shift = is64 ? (uint8_t)(arg & 63) : (uint8_t)(arg & 31);
                v = is64 ? (v << shift) : (uint64_t)((uint32_t)v << shift);
                break;
            case ALU_RSH:
                shift = is64 ? (uint8_t)(arg & 63) : (uint8_t)(arg & 31);
                v = is64 ? (v >> shift) : (uint64_t)((uint32_t)v >> shift);
                break;
            case ALU_ARSH:
                shift = is64 ? (uint8_t)(arg & 63) : (uint8_t)(arg & 31);
                v = is64 ? (uint64_t)((int64_t)v >> shift)
                         : (uint64_t)((int64_t)(int32_t)(uint32_t)v >> shift);
                break;
            case ALU_NEG: v = (uint64_t)(-(int64_t)v); break;
            case ALU_END: {
                uint8_t size = (uint8_t)in.imm;
                if (in.opcode & 0x08) { 
                    if (size == 16)      v = (uint64_t)__builtin_bswap16((uint16_t)v);
                    else if (size == 32) v = (uint64_t)__builtin_bswap32((uint32_t)v);
                    else if (size == 64) v = __builtin_bswap64(v);
                    else { r->fault = EBPF_FAULT_OPCODE; goto out; }
                } 
                break;
            }
            default:
                r->fault = EBPF_FAULT_OPCODE; goto out;
            }
            if (!is64) v &= 0xffffffffu; 
            regs[in.dst] = v;
            pc++;
        } else if (cls == CLS_JMP || cls == CLS_JMP32) {
            int is32 = (cls == CLS_JMP32);
            uint64_t arg;
            uint64_t v;
            int taken;
            if (cls == CLS_JMP && op == JMP_CALL) {

                if (p->map == 0 || p->map_cells == 0) { r->fault = EBPF_FAULT_CALL; goto out; }
                switch (in.imm) {
                case 1:
                    regs[0] = p->map[(uint32_t)regs[1] & (p->map_cells - 1u)];
                    break;
                case 2:
                    p->map[(uint32_t)regs[1] & (p->map_cells - 1u)] = (uint32_t)regs[2];
                    regs[0] = 0;
                    break;
                default:
                    r->fault = EBPF_FAULT_CALL; goto out;
                }
                pc++;
                continue;
            }
            if (in.opcode & SRC_X) arg = regs[in.src];
            else arg = is32 ? (uint64_t)(uint32_t)in.imm : (uint64_t)(int64_t)in.imm;
            v = regs[in.dst];
            if (is32) {
                uint32_t a32 = (uint32_t)v, b32 = (uint32_t)arg;
                switch (op) {
                case JMP_JA:   taken = 1; break;
                case JMP_JEQ:  taken = a32 == b32; break;
                case JMP_JNE:  taken = a32 != b32; break;
                case JMP_JGT:  taken = a32 >  b32; break;
                case JMP_JGE:  taken = a32 >= b32; break;
                case JMP_JLT:  taken = a32 <  b32; break;
                case JMP_JLE:  taken = a32 <= b32; break;
                case JMP_JSET: taken = (a32 & b32) != 0; break;
                case JMP_JSGT: taken = (int32_t)a32 >  (int32_t)b32; break;
                case JMP_JSGE: taken = (int32_t)a32 >= (int32_t)b32; break;
                case JMP_JSLT: taken = (int32_t)a32 <  (int32_t)b32; break;
                case JMP_JSLE: taken = (int32_t)a32 <= (int32_t)b32; break;
                case JMP_CALL: r->fault = EBPF_FAULT_CALL; goto out;
                case JMP_EXIT: r->retval = regs[0]; goto out;
                default: r->fault = EBPF_FAULT_OPCODE; goto out;
                }
            } else {
                switch (op) {
                case JMP_JA:   taken = 1; break;
                case JMP_JEQ:  taken = v == arg; break;
                case JMP_JNE:  taken = v != arg; break;
                case JMP_JGT:  taken = v >  arg; break;
                case JMP_JGE:  taken = v >= arg; break;
                case JMP_JLT:  taken = v <  arg; break;
                case JMP_JLE:  taken = v <= arg; break;
                case JMP_JSET: taken = (v & arg) != 0; break;
                case JMP_JSGT: taken = (int64_t)v >  (int64_t)arg; break;
                case JMP_JSGE: taken = (int64_t)v >= (int64_t)arg; break;
                case JMP_JSLT: taken = (int64_t)v <  (int64_t)arg; break;
                case JMP_JSLE: taken = (int64_t)v <= (int64_t)arg; break;
                case JMP_CALL: r->fault = EBPF_FAULT_CALL; goto out;
                case JMP_EXIT: r->retval = regs[0]; goto out;
                default: r->fault = EBPF_FAULT_OPCODE; goto out;
                }
            }
            pc = taken ? (uint32_t)((int32_t)pc + 1 + in.off) : pc + 1;
        } else if (cls == CLS_LDX) {
            uint8_t szcode, size;
            uint64_t addr;
            if ((in.opcode & 0xe0) != MODE_MEM || in.src == 10 || in.dst == 10) {
                r->fault = EBPF_FAULT_OPCODE; goto out;
            }
            szcode = (uint8_t)((in.opcode >> 3) & 3); 
            size   = (uint8_t)(szcode == 0 ? 4 : szcode == 2 ? 1 : 1u << szcode);
            addr = regs[in.src] + (uint64_t)(int64_t)in.off;

            if (addr < (uint64_t)(uintptr_t)p->ctx ||
                addr - (uint64_t)(uintptr_t)p->ctx + size > p->ctx_size) {
                r->fault = EBPF_FAULT_MEM; goto out;
            }
            regs[in.dst] = load_le((const uint8_t *)(uintptr_t)addr, size);
            pc++;
        } else if (cls == CLS_ST || cls == CLS_STX) {
            (void)op;
            r->fault = EBPF_FAULT_STORE; goto out; 
        } else {
            r->fault = EBPF_FAULT_OPCODE; goto out;
        }
    }
out:
    if (r->fault != EBPF_OK) r->retval = 0;
    return r->fault == EBPF_OK ? 0 : -1;
}
