#!/usr/bin/env python3
"""E45 verifier-safety differential campaign. The verifier's promise is
narrow and checkable: a program that ic_program_check accepts may only
fail in the interpreter through classes the verifier never claimed to
preclude. Anything else is a hole.

Contract for every accepted program (fault bitmap over six fuzzed
contexts):
  allowed   : OK, STEPS, DIV0 (reg divisor), FP (r10 store), MEM (the
              verifier sees no ctx length, offsets are runtime-checked)
  forbidden : OPCODE, CALL, STORE — the verifier's opcode/helper tables
              must dominate the interpreter's
  PC        : only as a straight fall off the end (no exit-termination
              rule); a PC fault counts as a wild jump unless every PC
              run executed exactly cnt insns or the program contains a
              backward jump

Teeth: rebuild the harness against a loader.c with the jump-bounds
check removed (wild-jump violations must appear) or the store class
admitted (STORE violations must appear), rerun unchanged, restore.

  cd boardlab_repo && python3 tools/safety.py
"""
import random, struct, subprocess, sys

ROOT = __file__.rsplit("/tools/", 1)[0]
BIN = ROOT + "/build/test_safety"

OK, PC, STEPS, MEM, STORE, DIV0, OPCODE, CALL, FP = range(9)
ALLOWED = (1 << OK) | (1 << STEPS) | (1 << MEM) | (1 << DIV0) | (1 << FP)
FORBIDDEN = (1 << OPCODE) | (1 << CALL) | (1 << STORE)
PCBIT = 1 << PC


def enc(op, d, s, o, i):
    return ((op & 0xFF) | (((d & 0xF) | ((s & 0xF) << 4)) << 8)
            | ((o & 0xFFFF) & 0xFFFF) << 16 | ((i & 0xFFFFFFFF) << 32))


ALU_K = [0xb7, 0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87,
         0x97, 0xc7]
ALU_X = [0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, 0x8f, 0x9f,
         0xaf, 0xbf, 0xcf]
ALU32_K = [0x04, 0x0c, 0x14, 0x1c, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74,
           0xb4, 0xbc, 0xdc]
ALU32_X = [op | 8 for op in ALU32_K]
LDX = [0x61, 0x69, 0x71, 0x79]
ST = [0x62, 0x6a, 0x72, 0x7a, 0x63, 0x6b, 0x73, 0x7b]
JMP_K = [0x05, 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0xa5, 0xb5,
         0xc5, 0xd5]
JMP_X = [op | 8 for op in JMP_K if op != 0x05]
ENDIAN = [0xd7]

DSTS = list(range(11))
SRCS = list(range(11))
IMMS = [-1, 0, 1, 2, 3, 0x7FFFFFFF]
OFFS = [-3, -2, -1, 0, 1, 2, 3]
LDX_OFFS = [-2, 0, 1, 2, 30, 34, 40]
END_IMMS = [8, 16, 32, 64]


def rand_insn(rng):
    roll = rng.random()
    if roll < 0.30:
        return enc(rng.choice(ALU_K), rng.choice(DSTS), 0, 0,
                   rng.choice(IMMS))
    if roll < 0.45:
        return enc(rng.choice(ALU_X), rng.choice(DSTS), rng.choice(SRCS),
                   0, rng.choice(IMMS))
    if roll < 0.60:
        return enc(rng.choice(LDX), rng.choice(DSTS), rng.choice(SRCS),
                   rng.choice(LDX_OFFS), 0)
    if roll < 0.85:
        k = rng.random() < 0.5
        ops = JMP_K if k else JMP_X
        return enc(rng.choice(ops),
                   0 if k and rng.random() < 0.7 else rng.choice(DSTS),
                   rng.choice(SRCS), rng.choice(OFFS),
                   rng.choice([-1, 0, 1]))
    if roll < 0.92:
        return enc(rng.choice(ALU32_K + ALU32_X), rng.choice(DSTS),
                   rng.choice(SRCS), 0, rng.choice(IMMS))
    if roll < 0.96:
        return enc(rng.choice(ST), rng.choice(DSTS), rng.choice(SRCS),
                   rng.choice(LDX_OFFS), rng.choice(IMMS))
    if roll < 0.99:
        return enc(0x85, 0, 0, 0, rng.choice([0, 1, 2, 3]))
    return enc(rng.choice(ENDIAN), rng.choice(DSTS), 0, 0,
               rng.choice(END_IMMS))


def exhaustive_len1():
    out = []
    for op in ALU_K:
        for d in DSTS:
            for i in IMMS:
                out.append([enc(op, d, 0, 0, i)])
    for op in ALU_X:
        for d in DSTS:
            for s in SRCS:
                out.append([enc(op, d, s, 0, 0)])
    for op in LDX:
        for d in DSTS:
            for s in SRCS:
                for o in LDX_OFFS:
                    out.append([enc(op, d, s, o, 0)])
    for op in JMP_K:
        for d in (0, 10):
            for o in OFFS:
                for i in (-1, 0, 1):
                    out.append([enc(op, d, 0, o, i)])
    for op in JMP_X:
        for d in DSTS:
            for s in SRCS:
                for o in OFFS:
                    out.append([enc(op, d, s, o, 0)])
    for op in ST:
        for d in DSTS:
            for s in SRCS:
                out.append([enc(op, d, s, 0, 0)])
    for i in (0, 1, 2, 3):
        out.append([enc(0x85, 0, 0, 0, i)])
    out.append([enc(0x95, 0, 0, 0, 0)])
    for op in ALU32_K:
        for d in DSTS:
            for i in IMMS:
                out.append([enc(op, d, 0, 0, i)])
    for op in ENDIAN:
        for d in DSTS:
            for i in END_IMMS:
                out.append([enc(op, d, 0, 0, i)])
    return out


def structured(rng, n, lo, hi):
    """Acceptance-shaped programs. Dataflow is kept verifier-clean by
    construction: r0 is written first (conditional jumps read only r0),
    bodies only read what they wrote, LDX bases are the ctx register,
    and jumps live in the tail so joins never meet a half-written
    register file. Sprinkles rejection-adjacent shapes at a few
    percent so the reject paths stay exercised."""
    out = []
    for _ in range(n):
        L = rng.randint(lo, hi)
        prog = [enc(0xb7, 0, 0, 0, rng.choice(IMMS))]
        written = {0, 1}
        body = L - 2 if L >= 3 else 1
        for i in range(max(body, 0)):
            roll = rng.random()
            if roll < 0.04:                      # rejection-adjacent
                prog.append(enc(rng.choice(LDX), rng.choice(DSTS),
                                rng.choice([0, 2, 3, 10]),
                                rng.choice(LDX_OFFS), 0))
                continue
            if roll < 0.06:
                prog.append(enc(rng.choice(ST), rng.choice(DSTS),
                                rng.choice(SRCS), 0, 0))
                continue
            if roll < 0.08:
                prog.append(enc(rng.choice(ALU_K), 10, 0, 0,
                                rng.choice(IMMS)))
                continue
            if roll < 0.12:
                prog.append(enc(0x85, 0, 0, 0,
                                rng.choice([1, 2, 3])))
                written.add(0)
                continue
            if roll < 0.30:
                prog.append(enc(rng.choice(LDX), rng.choice(DSTS), 1,
                                rng.choice([0, 1, 2, 30, 34, 40]), 0))
                continue
            if roll < 0.40:                      # div by a reg
                s = rng.choice(sorted(written))
                prog.append(enc(rng.choice([0x3f, 0x9f, 0x37, 0x97]),
                                rng.choice(sorted(written - {10})),
                                s, 0, 0))
                continue
            d = rng.choice(sorted(written - {10}))
            if roll < 0.70:
                if rng.random() < 0.6:
                    prog.append(enc(rng.choice(ALU_K), d, 0, 0,
                                    rng.choice(IMMS)))
                else:
                    s = rng.choice(sorted(written))
                    prog.append(enc(rng.choice(ALU_X), d, s, 0, 0))
                written.add(d)
                continue
            prog.append(enc(0xd7, d, 0, 0, rng.choice([16, 32, 64])))
        while len(prog) < L - 1:
            prog.append(enc(0xb7, 0, 0, 0, 0))
        tail = rng.random()
        if tail < 0.45:
            prog.append(enc(0x95, 0, 0, 0, 0))          # exit
        elif tail < 0.60 and L >= 3:
            prog.append(enc(0x05, 0, 0, -rng.randint(1, L - 2), 0))
            prog.append(enc(0x95, 0, 0, 0, 0))          # loop, then exit
        elif tail < 0.75 and L >= 3:
            prog.append(enc(0x15, 0, 0, 1, rng.choice([-1, 0, 1])))
            prog.append(enc(0x95, 0, 0, 0, 0))          # skip exit: PC
        elif tail < 0.85:
            prog.append(enc(0x15, 0, 0, 0, rng.choice([-1, 0, 1])))
            prog.append(enc(0x95, 0, 0, 0, 0))          # fallthrough
        elif tail < 0.95:
            prog.append(enc(0x15, 0, 0, 2, rng.choice([-1, 0, 1])))
            prog.append(enc(0x95, 0, 0, 0, 0))          # past end: reject
        else:
            prog.append(enc(rng.choice(ST), 0, 1, 0, 0))
            prog.append(enc(0x95, 0, 0, 0, 0))          # store: reject
        out.append(prog)
    return out


def sampled(rng, n, lo, hi):
    out = []
    for _ in range(n):
        L = rng.randint(lo, hi)
        prog = [rand_insn(rng) for _ in range(L)]
        roll = rng.random()
        if roll < 0.30:
            prog[-1] = enc(0x95, 0, 0, 0, 0)
        elif roll < 0.50 and L >= 3:
            prog[L // 2] = enc(rng.choice(JMP_K), 0, 0, -2, 0)
        elif roll < 0.70 and L >= 2:
            prog[0] = enc(rng.choice(LDX), rng.choice(DSTS),
                          rng.choice(SRCS), rng.choice(LDX_OFFS), 0)
        elif roll < 0.80:
            prog[0] = enc(0x85, 0, 0, 0, rng.choice([1, 2]))
        out.append(prog)
    return out


POLICIES = []


def load_policies():
    import re
    def read(name):
        txt = open(f"{ROOT}/modules/policies/{name}").read()
        vals = re.findall(r"0x([0-9a-fA-F]{16})", txt)
        return [int(v, 16) for v in vals]
    for f in ("mavlink.h", "screening.h"):
        POLICIES.append(read(f))
    txt = open(f"{ROOT}/modules/examples/pass_all.c").read()
    POLICIES.append([int(v, 16) for v in
                     re.findall(r"0x([0-9a-fA-F]{16})", txt)])


def main():
    rng = random.Random(0xE45)
    progs = exhaustive_len1()
    progs += structured(rng, 12000, 2, 2)
    progs += structured(rng, 15000, 3, 3)
    progs += structured(rng, 12000, 4, 4)
    progs += structured(rng, 8000, 5, 5)
    progs += structured(rng, 6000, 6, 6)
    progs += sampled(rng, 10000, 2, 6)
    load_policies()
    progs += [p for p in POLICIES if p]

    lines = []
    for p in progs:
        lines.append(f"{len(p)} " +
                     " ".join(f"{w & ((1<<64)-1):x}" for w in p))
    r = subprocess.run([BIN], input="\n".join(lines) + "\n",
                       capture_output=True, text=True, timeout=1200)
    if r.returncode != 0:
        print("harness failed:", r.returncode, r.stderr[-300:])
        return 1
    out = r.stdout.splitlines()
    if len(out) != len(progs):
        print(f"line mismatch: {len(out)} out vs {len(progs)} progs")
        return 1

    stats = {"rejected": 0, "accepted": 0}
    faults = [0] * 9
    viol = []
    for prog, line in zip(progs, out):
        parts = line.split()
        if parts[0] != "V":
            viol.append(("proto", prog, line))
            continue
        verdict = int(parts[1])
        if verdict != 0:
            stats["rejected"] += 1
            continue
        stats["accepted"] += 1
        bm = int(parts[2])
        for f in range(9):
            if bm & (1 << f):
                faults[f] += 1
        bad = bm & FORBIDDEN
        if bm & PCBIT:
            pcmin, pcmax = int(parts[3]), int(parts[4])
            backward = any(
                ((w & 0x07) in (5, 6) and (w & 0xf0) != 0x90 and
                 (w & 0xf0) != 0x80 and
                 ((w >> 16) & 0xFFFF) >= 0x8000 and
                 ((w >> 16) & 0xFFFF) != 0xFFFF)
                for w in prog)
            if not (pcmax == len(prog) or backward):
                bad |= PCBIT
        if bad:
            names = [n for n, b in (("OPCODE", 1 << OPCODE),
                                    ("CALL", 1 << CALL),
                                    ("STORE", 1 << STORE),
                                    ("WILDJUMP", PCBIT)) if bad & b]
            viol.append((names, len(prog),
                         [hex(w) for w in prog], hex(bm)))

    print(f"programs: {len(progs)}  rejected: {stats['rejected']}  "
          f"accepted: {stats['accepted']}")
    names = "OK PC STEPS MEM STORE DIV0 OPCODE CALL FP".split()
    print("accepted-program faults:",
          " ".join(f"{n}={c}" for n, c in zip(names, faults)))
    if viol:
        print(f"VIOLATIONS: {len(viol)}")
        for v in viol[:6]:
            print("  ", v)
        print("RESULT: E45 SAFETY FAIL ❌")
        return 1
    print("RESULT: E45 SAFETY PASS ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
