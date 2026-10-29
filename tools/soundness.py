#!/usr/bin/env python3
"""E35 independent oracle. The verifier and interpreter are re-derived
here from the ISA contract (not translated from core/), then run over
the same exhaustive sweeps as tests/test_soundness.c. Five digests must
match the C binary's: any semantic divergence anywhere in the swept
space changes a digest.

  cd boardlab_repo && python3 tools/soundness.py
"""
import re, struct, subprocess, sys

ROOT = __file__.rsplit("/tools/", 1)[0]
M = (1 << 64) - 1
OK, VALIDATE, ARGUMENT = 0, 4, 2          # ic_status codes that can appear


def enc(op, d, s, o, i):
    return ((op & 0xff) | (((d & 0xf) | ((s & 0xf) << 4)) << 8)
            | ((o & 0xffff) << 16) | ((i & 0xffffffff) << 32))


E = enc


def s64(v):
    return v - (1 << 64) if v >= (1 << 63) else v


def s32(v):
    v &= 0xffffffff
    return v - (1 << 32) if v >= (1 << 31) else v


# ---- the contract, restated ----

def opcode_known(op):
    cls = op & 7
    if cls == 1:
        return (op & 0xe0) == 0x60
    if cls in (4, 7):
        hi = op & 0xf0
        if hi == 0xd0:
            return (op & 0x08) != 0
        return hi <= 0xc0
    if cls in (5, 6):
        hi = op & 0xf0
        return hi <= 0x90 or 0xa0 <= hi <= 0xd0
    return False


def aud_defined(op):
    cls = op & 7
    hi = op & 0xf0
    if cls == 1:
        return (op & 0xe0) == 0x60
    if cls in (4, 7, 5, 6):
        return hi <= 0xd0
    return False


def aud_reads(e):
    op = e & 0xff
    dst = (e >> 8) & 0xf
    src = (e >> 12) & 0xf
    cls = op & 7
    hi = op & 0xf0
    sx = op & 8
    if cls in (4, 7):
        if hi == 0xb0:
            return 1 << src if sx else 0
        if hi in (0x80, 0xd0):
            return 1 << dst
        return (1 << dst) | (1 << src if sx else 0)
    if cls in (5, 6):
        if hi == 0x90:
            return 1
        if hi == 0x80:
            return ((1 << 1) | (1 << 2)) if (e >> 32) == 2 else (1 << 1)
        if hi == 0:
            return 0
        return (1 << dst) | (1 << src if sx else 0)
    if cls == 1:
        return 1 << src
    return 0


def aud_writes(e):
    op = e & 0xff
    dst = (e >> 8) & 0xf
    cls = op & 7
    if cls in (1, 4, 7):
        return 1 << dst
    if cls in (5, 6) and (op & 0xf0) == 0x80:
        return 1
    return 0


def aud_succ(e, pc):
    op = e & 0xff
    cls = op & 7
    off = (e >> 16) & 0xffff
    if off >= 0x8000:
        off -= 0x10000
    if cls in (5, 6):
        hi = op & 0xf0
        if hi == 0x90:
            return []
        if hi == 0:
            return [(pc + 1 + off) & 0xffffffff]
        if hi == 0x80:
            return [pc + 1]
        return [pc + 1, (pc + 1 + off) & 0xffffffff]
    return [pc + 1]


# ---- the verifier, restated ----

def insn_reads(e):
    return aud_reads(e)


def insn_writes(e):
    return aud_writes(e)


def insn_succ(e, pc):
    return aud_succ(e, pc)


def check_regs(ins):
    cnt = len(ins)
    TOP = 0xFFFFFFFF
    BOT, SCAL, CTX = 0, 1, 2
    in_m = [TOP] * cnt
    pending = [1] * cnt
    in_m[0] = CTX << 2          # entry: r1 = ctx, every other register BOTTOM

    def set_t(st, r, t):
        return (st & ~(3 << (2 * r))) | (t << (2 * r))

    def get_t(st, r):
        return (st >> (2 * r)) & 3

    while True:
        pc = next((i for i in range(cnt) if pending[i]), None)
        if pc is None:
            return OK
        pending[pc] = 0
        e = ins[pc]
        op = e & 0xff
        cls = op & 7
        hi = op & 0xf0
        st = in_m[pc]
        for r in range(11):
            if not (insn_reads(e) >> r) & 1:
                continue
            t = get_t(st, r)
            if t == BOT:
                return VALIDATE
            if cls == 1 and t != CTX:
                return VALIDATE
            if cls in (4, 7) and t == CTX:
                return VALIDATE
        if cls in (4, 7) and hi in (0x30, 0x90) and not (op & 8) \
                and (e >> 32) == 0:
            return VALIDATE
        out = st
        for r in range(11):
            if (insn_writes(e) >> r) & 1:
                out = set_t(out, r, SCAL)
        if cls in (5, 6) and hi == 0x80:
            out = set_t(out, 0, SCAL)
        for s in insn_succ(e, pc):
            if s >= cnt:
                return VALIDATE
            merged = in_m[s] & out
            if merged != in_m[s]:
                in_m[s] = merged
                pending[s] = 1


def ic_program_check(ins):
    cnt = len(ins)
    if cnt == 0 or cnt > 64:
        return ARGUMENT
    for pc, e in enumerate(ins):
        op = e & 0xff
        dst = (e >> 8) & 0xf
        src = (e >> 12) & 0xf
        off = (e >> 16) & 0xffff
        if off >= 0x8000:
            off -= 0x10000
        if dst > 10 or src > 10:
            return VALIDATE
        if not opcode_known(op):
            return VALIDATE
        cls = op & 7
        if cls in (4, 7) and (op & 0xf0) == 0xd0 and (op & 8) \
                and (e >> 32) not in (16, 32, 64):
            return VALIDATE
        if cls in (5, 6):
            hi = op & 0xf0
            if hi == 0x90:
                continue
            if hi == 0x80:
                if cls == 6:
                    return VALIDATE
                if op & 8:
                    return VALIDATE
                h = (e >> 32) & 0xffffffff
                if h == 0 or h > 2:
                    return VALIDATE
                continue
            target = pc + 1 + off
            if target < 0 or target >= cnt:
                return VALIDATE
    return check_regs(ins)


# ---- the interpreter, restated ----
# The context pointer is the audit's fixed window base (tests/test_soundness.c
# mmaps the same constants), so jump comparisons over r1 are reproducible.

CTX_BASE = 0x20000000


def interp(ins, ctx, base, map_, max_steps=64):
    cnt = len(ins)
    regs = [0] * 11
    regs[1] = base
    steps = pc = 0
    executed = 0
    fault, ret = OK, 0
    while True:
        if pc >= cnt:
            fault = 1
            break
        steps += 1
        if steps > max_steps:
            fault = 2
            break
        e = ins[pc]
        executed += 1
        op = e & 0xff
        dst = (e >> 8) & 0xf
        src = (e >> 12) & 0xf
        off = (e >> 16) & 0xffff
        if off >= 0x8000:
            off -= 0x10000
        imm = (e >> 32) & 0xffffffff
        if dst > 10 or src > 10:
            fault = 6
            break
        cls = op & 7
        hi = op & 0xf0
        sx = op & 8
        if cls in (4, 7):
            is64 = cls == 7
            arg = 0
            if hi not in (0x80, 0xd0):
                if sx:
                    arg = regs[src]
                elif is64:
                    arg = imm - (1 << 32) if imm >= (1 << 31) else imm
                else:
                    arg = imm
                arg &= M
            if dst == 10:
                fault = 8
                break
            v = 0 if hi == 0xb0 else regs[dst]
            sh = 63 if is64 else 31
            if hi == 0x00:
                v = (v + arg) & M
            elif hi == 0x10:
                v = (v - arg) & M
            elif hi == 0x20:
                v = (v * arg) & M
            elif hi == 0x30:
                if arg == 0:
                    fault = 5
                    break
                v = v // arg if is64 else (v & 0xffffffff) // (arg & 0xffffffff)
            elif hi == 0x90:
                if arg == 0:
                    fault = 5
                    break
                v = v % arg if is64 else (v & 0xffffffff) % (arg & 0xffffffff)
            elif hi == 0x40:
                v = (v | arg) & M
            elif hi == 0x50:
                v = (v & arg) & M
            elif hi == 0x60:
                v = ((v << (arg & sh)) & M) if is64 \
                    else ((v & 0xffffffff) << (arg & sh))
            elif hi == 0x70:
                v = (v >> (arg & sh)) if is64 \
                    else ((v & 0xffffffff) >> (arg & sh))
            elif hi == 0x80:
                v = (-v) & M
            elif hi == 0xa0:
                v = (v ^ arg) & M
            elif hi == 0xb0:
                v = arg
            elif hi == 0xc0:
                if is64:
                    v = (s64(v) >> (arg & sh)) & M
                else:
                    v = (s32(v) >> (arg & sh)) & 0xffffffff
            elif hi == 0xd0:
                if sx:
                    if imm == 16:
                        v = int.from_bytes(struct.pack("<H", v & 0xffff), "big")
                    elif imm == 32:
                        v = int.from_bytes(struct.pack("<I", v & 0xffffffff),
                                           "big")
                    elif imm == 64:
                        v = int.from_bytes(struct.pack("<Q", v), "big")
                    else:
                        fault = 6
                        break
            if not is64:
                v &= 0xffffffff
            regs[dst] = v & M
            pc += 1
        elif cls in (5, 6):
            is32 = cls == 6
            if cls == 5 and hi == 0x80:
                if not map_ or (len(map_) & (len(map_) - 1)) != 0:
                    fault = 7
                    break
                idx = regs[1] & (len(map_) - 1)
                if imm == 1:
                    regs[0] = map_[idx] & M
                elif imm == 2:
                    map_[idx] = regs[2] & 0xffffffff
                    regs[0] = 0
                else:
                    fault = 7
                    break
                pc += 1
                continue
            arg = v = 0
            if hi not in (0x00, 0x90):
                if sx:
                    arg = regs[src]
                elif is32:
                    arg = imm
                else:
                    arg = (imm - (1 << 32) if imm >= (1 << 31) else imm) & M
                v = regs[dst]
            if hi == 0x90:
                ret = regs[0]
                break
            if hi == 0x00:
                taken = True
            elif is32:
                a32, b32 = v & 0xffffffff, arg & 0xffffffff
                taken = {
                    0x10: a32 == b32, 0x50: a32 != b32, 0x20: a32 > b32,
                    0x30: a32 >= b32, 0xa0: a32 < b32, 0xb0: a32 <= b32,
                    0x40: (a32 & b32) != 0, 0x60: s32(a32) > s32(b32),
                    0x70: s32(a32) >= s32(b32), 0xc0: s32(a32) < s32(b32),
                    0xd0: s32(a32) <= s32(b32),
                }.get(hi)
                if taken is None:
                    fault = 7 if hi == 0x80 else 6
                    break
            else:
                taken = {
                    0x10: v == arg, 0x50: v != arg, 0x20: v > arg,
                    0x30: v >= arg, 0xa0: v < arg, 0xb0: v <= arg,
                    0x40: (v & arg) != 0, 0x60: s64(v) > s64(arg),
                    0x70: s64(v) >= s64(arg), 0xc0: s64(v) < s64(arg),
                    0xd0: s64(v) <= s64(arg),
                }.get(hi)
                if taken is None:
                    fault = 7 if hi == 0x80 else 6
                    break
            pc = ((pc + 1 + off) & 0xffffffff) if taken else pc + 1
        elif cls == 1:
            if (op & 0xe0) != 0x60 or src == 10 or dst == 10:
                fault = 6
                break
            sz = (op >> 3) & 3
            size = 4 if sz == 0 else (1 if sz == 2 else (1 << sz))
            addr = (regs[src] + (off & M)) & M
            if addr < base or addr - base + size > len(ctx):
                fault = 3
                break
            regs[dst] = int.from_bytes(ctx[addr - base:addr - base + size],
                                       "little")
            pc += 1
        elif cls in (2, 3):
            fault = 4
            break
        else:
            fault = 6
            break
    return (fault, 0 if fault else ret, executed)


# ---- sweeps: identical vectors and fold order as the C audit ----

def fnv(h, v):
    for i in range(8):
        h ^= (v >> (8 * i)) & 0xff
        h = (h * 0x100000001b3) & M
    return h


A2 = [
    (E(0x95,0,0,0,0), "exit"), (E(0x05,0,0,-1,0), "ja-1"),
    (E(0x05,0,0,1,0), "ja+1"), (E(0x05,0,0,2,0), "ja+2"),
    (E(0x15,0,0,1,0), "jeq r0,0,+1"), (E(0x15,0,0,-1,0), "jeq r0,0,-1"),
    (E(0x15,0,0,0,0), "jeq r0,0,0"), (E(0x15,1,0,1,0), "jeq r1,0,+1"),
    (E(0x1d,0,0,0,0), "jeq r0,r0,0"), (E(0x5d,0,0,1,0), "jne r0,r0,+1"),
    (E(0x65,0,0,1,-1), "jsgt r0,-1,+1"), (E(0x4d,0,1,1,0), "jset r0,r1,+1"),
    (E(0x16,0,0,1,0), "jeq32 r0,0,+1"), (E(0xc6,0,0,1,1), "jslt32 r0,1,+1"),
    (E(0x85,0,0,0,1), "call1"), (E(0x85,0,0,0,2), "call2"),
    (E(0x85,0,0,0,3), "call3"), (E(0x86,0,0,0,1), "jmp32call"),
    (E(0xb7,0,0,0,1), "mov r0,1"), (E(0xb7,2,0,0,1), "mov r2,1"),
    (E(0xb7,5,0,0,2), "mov r5,2"), (E(0xb7,1,0,0,0), "mov r1,0"),
    (E(0xb7,10,0,0,0), "mov r10,0"), (E(0xbf,3,1,0,0), "mov r3,r1"),
    (E(0xbf,0,0,0,0), "mov r0,r0"), (E(0x07,0,0,0,1), "add r0,1"),
    (E(0x0f,0,1,0,0), "add r0,r1"), (E(0x0f,2,0,0,0), "add r2,r0"),
    (E(0x0f,0,10,0,0), "add r0,r10"), (E(0x17,0,0,0,1), "sub r0,1"),
    (E(0x27,0,0,0,3), "mul r0,3"), (E(0x37,0,0,0,0), "div r0,0"),
    (E(0x37,0,0,0,2), "div r0,2"), (E(0x3f,0,2,0,0), "div r0,r2"),
    (E(0x97,0,0,0,0), "mod r0,0"), (E(0x97,0,0,0,3), "mod r0,3"),
    (E(0x47,0,0,0,0xf0), "or r0,0xf0"), (E(0x57,0,0,0,0xff), "and r0,0xff"),
    (E(0x67,0,0,0,1), "lsh r0,1"), (E(0x77,0,0,0,1), "rsh r0,1"),
    (E(0xc7,0,0,0,1), "arsh r0,1"), (E(0x87,0,0,0,0), "neg r0"),
    (E(0x8f,0,3,0,0), "neg r0,x"), (E(0xd7,0,0,0,16), "bswap16"),
    (E(0xd7,0,0,0,32), "bswap32"), (E(0xd7,0,0,0,8), "bswap8"),
    (E(0xd4,0,0,0,32), "end imm"), (E(0xdf,0,0,0,8), "bswapreg8"),
    (E(0xdf,0,0,0,16), "bswapreg16"), (E(0x71,0,1,0,0), "ldxb"),
    (E(0x61,0,1,0,0), "ldxw"), (E(0x69,0,1,0,0), "ldxh"),
    (E(0x79,0,1,0,0), "ldxdw"), (E(0x71,0,1,12,0), "ldxb+12"),
    (E(0x71,0,1,-1,0), "ldxb-1"), (E(0x71,0,1,32767,0), "ldxb far"),
    (E(0x71,2,1,0,0), "ldxb r2"), (E(0x71,0,10,0,0), "ldxb r10 base"),
    (E(0x71,0,2,0,0), "ldxb r2 base"), (E(0x62,0,0,0,0), "stw"),
    (E(0x63,0,1,0,0), "stxw"), (E(0x04,0,0,0,1), "add32"),
    (E(0xc4,0,0,0,1), "arsh32"), (E(0x07,1,0,0,1), "add r1,1"),
]

C3 = [
    (E(0x95,0,0,0,0), "exit"), (E(0x05,0,0,1,0), "ja+1"),
    (E(0x05,0,0,-1,0), "ja-1"), (E(0x15,0,0,-1,0), "jeq r0,0,-1"),
    (E(0xb7,0,0,0,1), "mov r0,1"), (E(0xb7,2,0,0,1), "mov r2,1"),
    (E(0xb7,5,0,0,2), "mov r5,2"), (E(0xb7,1,0,0,0), "mov r1,0"),
    (E(0xbf,3,1,0,0), "mov r3,r1"), (E(0x07,0,0,0,1), "add r0,1"),
    (E(0x37,0,0,0,2), "div r0,2"), (E(0x3f,0,2,0,0), "div r0,r2"),
    (E(0x71,0,1,0,0), "ldxb"), (E(0x85,0,0,0,1), "call1"),
    (E(0x85,0,0,0,2), "call2"), (E(0x87,0,0,0,0), "neg r0"),
    (E(0xd7,0,0,0,16), "bswap16"), (E(0x57,0,0,0,0xff), "and r0,0xff"),
    (E(0xdf,0,0,0,16), "bswapreg16"),
    (E(0xdf,0,0,0,8), "bswapreg8"),
]

CTX_A = list(range(16))
CTX_B = [0xff] * 16
CTX_C = [0, 1, 2, 3]
BATT = [(CTX_A, CTX_BASE, 16, [7]),
        (CTX_B, CTX_BASE + 0x100, 16, [7]),
        (CTX_C, CTX_BASE + 0x200, 4, [7]),
        (CTX_A, CTX_BASE, 16, [0])]

F1 = [E(0x71,0,1,0,0), E(0xb7,1,0,0,0xFD), E(0x1d,0,1,2,0), E(0xb7,0,0,0,0),
      E(0x95,0,0,0,0), E(0xb7,0,0,0,1), E(0x95,0,0,0,0)]
F2 = [E(0xb7,0,0,0,0), E(0x05,0,0,-1,0), E(0x95,0,0,0,0)]
F3 = [E(0xb7,2,0,0,7), E(0x85,0,0,0,2), E(0x95,0,0,0,0)]

ADV = [
    ("empty", [], 0, False),
    ("exit r0 unwritten", [E(0x95,0,0,0,0)], 1, False),
    ("ldxb exit", [E(0x71,0,1,0,0), E(0x95,0,0,0,0)], 2, True),
    ("ldxw exit C", [E(0x61,0,1,0,0), E(0x95,0,0,0,0)], 2, True),
    ("ldxb oob", [E(0x71,0,1,4,0), E(0x95,0,0,0,0)], 2, True),
    ("ldxb neg", [E(0x71,0,1,-1,0), E(0x95,0,0,0,0)], 2, True),
    ("ldxb far", [E(0x71,0,1,32767,0), E(0x95,0,0,0,0)], 2, True),
    ("scalar base", [E(0xb7,1,0,0,0), E(0x71,0,1,0,0)], 2, False),
    ("alu ctx dst", [E(0x0f,1,1,0,0)], 1, False),
    ("mov ctx copy", [E(0xbf,3,1,0,0), E(0x71,0,3,0,0)], 2, False),
    ("scalar base 2", [E(0xb7,2,0,0,1), E(0x71,0,2,0,0)], 2, False),
    ("two ldx", [E(0x71,0,1,0,0), E(0x71,2,1,1,0), E(0x95,0,0,0,0)], 3, True),
    ("branch both write", [E(0xb7,0,0,0,1), E(0x55,0,0,1,1), E(0xb7,0,0,0,5),
                           E(0x95,0,0,0,0)], 4, True),
    ("reg div0", [E(0xb7,0,0,0,9), E(0xb7,2,0,0,0), E(0x3f,0,2,0,0),
                  E(0x95,0,0,0,0)], 4, True),
    ("div imm0", [E(0xb7,0,0,0,9), E(0x37,0,0,0,0)], 2, False),
    ("mod imm0", [E(0xb7,0,0,0,9), E(0x97,0,0,0,0)], 2, False),
    ("fp write", [E(0xb7,0,0,0,1), E(0xb7,10,0,0,2), E(0x95,0,0,0,0)], 3, True),
    ("self loop", [E(0xb7,0,0,0,0), E(0x05,0,0,-1,0), E(0x95,0,0,0,0)], 3, True),
    ("call 3", [E(0x85,0,0,0,3)], 1, False),
    ("call 0", [E(0x85,0,0,0,0)], 1, False),
    ("call 2 store", [E(0xb7,2,0,0,7), E(0x85,0,0,0,2), E(0x95,0,0,0,0)],
     3, True),
    ("call 1 load", [E(0x85,0,0,0,1), E(0x95,0,0,0,0)], 2, True),
    ("bswap imm8", [E(0xd7,0,0,0,8)], 1, False),
    ("bswap imm17", [E(0xd7,0,0,0,17)], 1, False),
    ("bswap imm-src", [E(0xd7,0,0,0,16)], 1, False),
    ("bswapreg 8", [E(0xdf,0,0,0,8)], 1, False),
    ("bswapreg 17", [E(0xdf,0,0,0,17)], 1, False),
    ("bswapreg 16", [E(0xb7,0,0,0,0x1234), E(0xdf,0,0,0,16),
                     E(0x95,0,0,0,0)], 3, True),
    ("jmp32 call", [E(0x86,0,0,0,1)], 1, False),
    ("exit dst3", [E(0x95,3,0,0,0)], 1, False),
    ("ja src3", [E(0xb7,0,0,0,7), E(0x0d,0,3,0,0), E(0x95,0,0,0,0)], 3, True),
    ("neg sx", [E(0xb7,0,0,0,5), E(0x8f,0,3,0,0), E(0x95,0,0,0,0)], 3, True),
    ("stw", [E(0x62,0,0,0,0)], 1, False),
    ("ldxdw small ctx", [E(0x79,0,1,0,0), E(0x95,0,0,0,0)], 2, True),
    ("ldxdw big ctx", [E(0x79,0,1,0,0), E(0x95,0,0,0,0)], 2, True),
    ("fallthrough escape", [E(0xb7,0,0,0,1), E(0x15,0,0,-1,0)], 2, False),
    ("backward ja loop", [E(0xb7,0,0,0,1), E(0x05,0,0,-1,0)], 2, True),
    ("ldxw exit A", [E(0x61,0,1,0,0), E(0x95,0,0,0,0)], 2, True),
]

BENIGN = {OK, 3, 5, 8, 2}          # OK, MEM, DIV0, FP, STEPS


def run_prog(ins, b):
    ctx, base, size, map_ = BATT[b]
    assert len(map_) == 1          # sentinel rule: helper index collapses
    return interp(ins, ctx[:size], base, list(map_))


def sweep_tables():
    h = 0xcbf29ce484222325
    for op in range(256):
        k = 1 if opcode_known(op) else 0
        d = 1 if aud_defined(op) else 0
        if k and not d:
            print(f"table mismatch: op {op:02x} known but undefined")
        h = fnv(h, op)
        h = fnv(h, k)
        h = fnv(h, d)
    return h


def sweep_flow():
    h = 0xcbf29ce484222325
    for op in range(256):
        if not opcode_known(op):
            continue
        is_call = (op & 7) in (5, 6) and (op & 0xf0) == 0x80
        for dst in range(11):
            for src in range(11):
                for imm in range(3 if is_call else 1):
                    for off in (-2, -1, 0, 1):
                        e = enc(op, dst, src, off, imm)
                        ar, aw = aud_reads(e), aud_writes(e)
                        a = aud_succ(e, 1)
                        h = fnv(h, op)
                        h = fnv(h, dst)
                        h = fnv(h, src)
                        h = fnv(h, imm)
                        h = fnv(h, off + 8)
                        h = fnv(h, ar)
                        h = fnv(h, aw)
                        h = fnv(h, len(a))
                        if a:
                            h = fnv(h, a[0])
                        if len(a) > 1:
                            h = fnv(h, a[1])
    return h


def sweep_small():
    h = 0xcbf29ce484222325
    for i in range(len(A2)):
        for j in range(len(A2)):
            ins = [A2[i][0], A2[j][0]]
            v = ic_program_check(ins)
            if v == OK:
                for b in range(4):
                    f, r, n = run_prog(ins, b)
                    assert f in BENIGN, (A2[i][1], A2[j][1], b, f)
                    h = fnv(h, f)
                    h = fnv(h, r)
                    h = fnv(h, n)
                assert run_prog(ins, 0) == run_prog(ins, 0)
            assert v in (OK, VALIDATE, ARGUMENT), (i, j, v)
            h = fnv(h, v)
    for i in range(len(C3)):
        for j in range(len(C3)):
            for k in range(len(C3)):
                ins = [C3[i][0], C3[j][0], C3[k][0]]
                v = ic_program_check(ins)
                if v == OK:
                    for b in range(4):
                        f, r, n = run_prog(ins, b)
                        assert f in BENIGN, (C3[i][1], C3[j][1], C3[k][1],
                                             b, f)
                        h = fnv(h, f)
                        h = fnv(h, r)
                        h = fnv(h, n)
                assert v in (OK, VALIDATE, ARGUMENT)
                h = fnv(h, v)
    return h


def sweep_flip():
    h = 0xcbf29ce484222325
    for p, prog in enumerate((F1, F2, F3)):
        for w in range(len(prog)):
            for bit in range(64):
                ins = list(prog)
                ins[w] ^= 1 << bit
                v = ic_program_check(ins)
                if v == OK:
                    f, r, _ = run_prog(ins, 0)
                    assert f in BENIGN, (p, w, bit, f)
                    h = fnv(h, f)
                    h = fnv(h, r)
                h = fnv(h, v)
                h = fnv(h, p)
                h = fnv(h, w * 64 + bit)
    return h


def sweep_adv():
    h = 0xcbf29ce484222325
    for i, (name, ins, cnt, accept) in enumerate(ADV):
        ins = ins[:cnt] if cnt else []
        v = ic_program_check(ins)
        assert (v == OK) == accept, (name, v, accept)
        if v == OK:
            b = {"ldxw exit C": 2, "ldxb oob": 2, "ldxb neg": 2,
                 "ldxdw small ctx": 2}.get(name, 0)
            f, r, n = run_prog(ins, b)
            assert f in BENIGN, (name, f)
            h = fnv(h, i)
            h = fnv(h, f)
            h = fnv(h, r)
            h = fnv(h, n)
        else:
            h = fnv(h, i)
            h = fnv(h, v)
            h = fnv(h, 0xdead)
            h = fnv(h, 0)
    return h


def main():
    ht, hf = sweep_tables(), sweep_flow()
    hs, hfl, ha = sweep_small(), sweep_flip(), sweep_adv()
    out = subprocess.run([f"{ROOT}/build/test_soundness"],
                         capture_output=True, text=True, timeout=120)
    m = re.search(r"DIGEST table=([0-9a-f]{16}) flow=([0-9a-f]{16}) "
                  r"small=([0-9a-f]{16}) flip=([0-9a-f]{16}) "
                  r"adv=([0-9a-f]{16})", out.stdout)
    if not m:
        print("oracle: no C digest found\n" + out.stdout)
        return 1
    mine = [ht, hf, hs, hfl, ha]
    theirs = [int(x, 16) for x in m.groups()]
    names = ["table", "flow", "small", "flip", "adv"]
    bad = 0
    for name, a, b in zip(names, mine, theirs):
        ok = a == b
        bad += not ok
        print(f"{name:6} {'MATCH' if ok else 'MISMATCH'} "
              f"py={a:016x} c={b:016x}")
    print("RESULT:", "ORACLE MATCH ✅" if not bad else "ORACLE DIVERGED ❌")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
