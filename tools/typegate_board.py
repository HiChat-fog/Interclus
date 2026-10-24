"""E27 board drill: the boot loader's type gate must reject a program
that is otherwise well-formed but uses a scalar as an LDX base, and must
accept the same program with a context pointer as the base.

  cd tools && python3 typegate_board.py
"""
import sys, time
from inject_swarm import wlink, read_words

BASE = 0x20000100
PROG_AREA = 0x20003000
PROG_MAGIC = 0x474F5250
S_GATE, S_DONE, S_LOAD = 88, 56, 89


def enc(op, d, s, o, i):
    return ((op & 0xFF) | (((d & 0xF) | ((s & 0xF) << 4)) << 8)
            | ((o & 0xFFFF) << 16) | ((i & 0xFFFFFFFF) << 32))


BAD = [enc(0xB7, 2, 0, 0, 5),    # r2 = 5 (scalar)
       enc(0x71, 0, 2, 0, 0),    # r0 = *(u8 *)(r2 + 0): type reject
       enc(0x95, 0, 0, 0, 0)]
GOOD = [enc(0x71, 0, 1, 0, 0),   # r0 = *(u8 *)(r1 + 0): r1 is the ctx
        enc(0x95, 0, 0, 0, 0)]


def stage(insns):
    wlink("write-mem", hex(PROG_AREA), hex(PROG_MAGIC))
    wlink("write-mem", hex(PROG_AREA + 4), hex(len(insns)))
    for i, e in enumerate(insns):
        wlink("write-mem", hex(PROG_AREA + 8 + 8 * i), hex(e & 0xFFFFFFFF))
        wlink("write-mem", hex(PROG_AREA + 12 + 8 * i), hex(e >> 32))


def load_code(timeout=12):
    wlink("write-mem", hex(0x20003800), "0x0")
    wlink("write-mem", hex(0x20003A08), "0x0")
    wlink("write-mem", hex(BASE + 4 * S_LOAD), "0xFFFFFFFF")
    wlink("write-mem", hex(BASE + 4 * S_DONE), "0xFFFFFFFF")
    wlink("reset")
    t0 = time.time()
    while time.time() - t0 < timeout:
        w = read_words(BASE, 101)
        if (w.get(BASE + 4 * S_DONE) == 0x600DF00D and
                w.get(BASE + 4 * S_LOAD) != 0xFFFFFFFF):
            return w.get(BASE + 4 * S_LOAD)
        time.sleep(0.1)
    return None


def main():
    ok = True

    stage(BAD)
    load = load_code()
    print(f"1 scalar LDX base: LOAD={load} (want 4)")
    ok &= load == 4

    stage(GOOD)
    load = load_code()
    print(f"2 ctx LDX base:    LOAD={load} (want 1)")
    ok &= load == 1

    wlink("write-mem", hex(PROG_AREA), "0x0")
    load = load_code()
    print(f"3 builtin restored: LOAD={load} (want 0)")
    ok &= load == 0

    print("RESULT:", "TYPEGATE BOARD PASS ✅" if ok else "TYPEGATE BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
