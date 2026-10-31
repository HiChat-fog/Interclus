#!/usr/bin/env python3
"""E37 boundary audit: the canary module parks 31 register canaries plus
the stack pointer every round and ecalls. The drill then verifies, per
round, that (1) the TCB holds the complete evidence set, (2) no canary
leaked into M-mode RAM outside the TCB, (3) the registers the supervisor
restored into the module are exactly the ones it parked the round before
— never another lifetime's — and (4) a fuzzed module box cannot move the
supervisor off its verdicts.

  cd tools && python3 boundary_board.py
"""
import hashlib, struct, sys, time
from inject_swarm import wlink, read_words, build_swarm, MAILBOX_MAGIC
from pend import stage_native
from uart_frame import frame

BASE = 0x20000100
VU = 0x20001700
MAGIC = 0x54524156
COMP_STATE = 0x20000F40
TCB2 = COMP_STATE + 2 * 156 + 28  # comps[2].tcb (tcb at word 7)
SCRATCH = (0x20000F00, 0x20000F40)
BOX = 0x2000B000
S_DONE, S_GATE, S_HLOAD = 56, 88, 93
S_HALT = 102


def sw(i):
    return read_words(BASE + 4 * i, 1).get(BASE + 4 * i, 0) or 0


def wr32(a, v):
    wlink("write-mem", hex(a), hex(v & 0xffffffff))


def vw(i):
    return read_words(VU + 4 * i, 1).get(VU + 4 * i, 0) or 0


def vu_arm():
    for i in (1, 2, 4, 5):
        wr32(VU + 4 * i, 0)
    wr32(VU + 12, 1)
    wr32(VU, MAGIC)


def pump():
    tw, tr = vw(4), vw(5)
    if tw == tr:
        return b""
    w = read_words(VU + 0x420, 256)
    ring = b"".join(struct.pack("<I", w.get(VU + 0x420 + 4 * i, 0))
                     for i in range(256))
    n, start = tw - tr, tr & 1023
    out = (ring[start:] + ring[:start])[:n]
    wr32(VU + 20, tw)
    return out


def vsend(raw):
    raw += b"\0" * (-len(raw) % 4)
    wr = vw(1)
    if (wr & 1023) + len(raw) > 1024:
        gap = 1024 - (wr & 1023)
        for i in range(0, gap, 4):
            wr32(VU + 0x20 + ((wr + i) & 1023), 0)
        wr += gap
    for i in range(0, len(raw), 4):
        wr32(VU + 0x20 + ((wr + i) & 1023),
             struct.unpack_from("<I", raw, i)[0])
    wr32(VU + 4, wr + len(raw))


def swarm_frame(seed):
    pkts, _c, _v = build_swarm(8, seed)
    payload = struct.pack("<II", MAILBOX_MAGIC, 8) + b"".join(pkts)
    return frame(2, payload)


def wait_box(value, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        if read_words(BOX, 1).get(BOX, 0) == value:
            return True
        time.sleep(0.05)
    return False


def dump_ram():
    words = {}
    for a in range(0x20000000, 0x20010000, 0x4000):
        w = read_words(a, 4096)
        words.update(w)
    return words


def forensics():
    w = read_words(BASE, 104)
    idx = w.get(BASE + 4 * 40, 0)
    out = []
    for i in range(8):
        c = w.get(BASE + 4 * (41 + i * 2), 0)
        a = w.get(BASE + 4 * (42 + i * 2), 0)
        out.append((c, a))
    return idx, out[out.index((0xffffffff, 0xffffffff)) - 8:] \
        if (0xffffffff, 0xffffffff) in out else out


def whitelisted(a):
    return (COMP_STATE <= a < COMP_STATE + 624
            or SCRATCH[0] <= a < SCRATCH[1])


def sweep(round_idx, words):
    base = 0xE3700000 | (round_idx << 8)
    leaks = []
    for a, v in words.items():
        if whitelisted(a):
            continue
        if base < v <= base + 31:
            leaks.append((a, v - base))
    return leaks


def tcb_check(round_idx, words):
    base = 0xE3700000 | (round_idx << 8)
    bad = []
    for i in range(1, 32):
        got = words.get(TCB2 + 4 * i, 0)
        if got != base + i:
            bad.append((i, got))
    return bad


def boot():
    import subprocess
    r = subprocess.run(["wlink", "flash", "-e", "../build/fw_pmp.bin"],
                       capture_output=True, text=True, timeout=120)
    if "Flash done" not in r.stdout:
        print("   flash failed:", r.stdout[-160:])
        return False
    wr32(VU, 0)
    wr32(0x20003800, 0)
    wr32(0x20003A08, 0)
    wr32(BASE + 4 * S_DONE, 0xffffffff)
    wr32(BASE + 4 * S_HLOAD, 0xffffffff)
    wlink("reset")
    end = time.time() + 12
    while time.time() < end:
        if sw(S_DONE) == 0x600df00d and sw(S_GATE) == 0xc0de0000:
            return True
        time.sleep(0.1)
    return False


def main():
    canary = open("../build/canary.bin", "rb").read()
    ok = boot()
    print(f"0 boot: {ok}")
    vu_arm()

    stage_native(canary, slot=0)
    ok &= wait_box(1)
    time.sleep(0.2)
    print(f"1 install+round0: BOX0={read_words(BOX,1).get(BOX,0)} "
          f"HLOAD={sw(S_HLOAD)}")

    DIAG = 0x20004700
    fails = 0
    rounds = 4
    runs = read_words(DIAG, 1).get(DIAG, 0)
    for r in range(rounds + 1):
        if r > 0:
            ran = False
            for attempt in range(3):
                vsend(swarm_frame(7 + r))
                end = time.time() + 5
                while time.time() < end:
                    d = read_words(DIAG, 1).get(DIAG, 0)
                    if d > runs:
                        runs = d
                        ran = True
                        break
                    time.sleep(0.05)
                if ran:
                    break
                print(f"  round {r}: frame lost (attempt {attempt})")
            time.sleep(0.5)
            if read_words(BOX, 1).get(BOX, 0) != 1:
                print(f"  round {r}: ran={ran} but module skipped "
                      f"(box={read_words(BOX,1).get(BOX,0):#x})")
                idx, ring = forensics()
                print(f"    nslot={sw(97):#x} hrej={sw(94)} "
                      f"roll={sw(95)} halt={sw(102):#x} "
                      f"haltc={sw(103):#x} ri_idx={idx}")
                for c, a in ring[-6:]:
                    print(f"    ring: mcause={c:#x} mtval={a:#x}")
                print(f"    boxrec={[hex(x) for x in read_words(0x2000B010, 4).values()]}")
                fails += 1
                break
            time.sleep(0.2)
        words = dump_ram()
        bad = tcb_check(0, words)
        leaks = sweep(r, words)
        rec = [words.get(0x2000B010 + 4 * i, 0) for i in range(12)]
        fresh_bad = [i for i in range(12) if rec[i] != 0]
        print(f"  round {r}: tcb_bad={len(bad)} leaks={len(leaks)} "
              f"fresh_bad={len(fresh_bad)}")
        if bad:
            fails += 1
            print(f"    tcb: {bad[:4]}")
        if leaks:
            fails += 1
            print(f"    leaks: {leaks[:4]}")
        if fresh_bad:
            fails += 1
            print(f"    fresh: {[(i, hex(rec[i])) for i in fresh_bad[:4]]}")

    print("2 fuzz rounds")
    for f in range(2):
        wr32(BOX, 0xFFFFFFFF)
        wr32(BOX + 4, 0xDEADBEEF)
        wr32(BOX + 8, 0x0BADF00D)
        vsend(swarm_frame(40 + f))
        if not wait_box(1, timeout=8):
            print(f"  fuzz {f}: no round")
            fails += 1
            break
        time.sleep(0.2)
        words = dump_ram()
        bad = tcb_check(0, words)
        leaks = sweep(0, words)
        alive = (sw(S_DONE) == 0x600df00d, sw(S_GATE) == 0xc0de0000,
                 sw(S_HALT) == 0)
        print(f"  fuzz {f}: alive={alive} tcb_bad={len(bad)} "
              f"leaks={len(leaks)}")
        ok &= all(alive)
        if bad or leaks:
            fails += 1

    ok = ok and fails == 0
    print("RESULT:", "E37 BOUNDARY PASS ✅" if ok else "E37 BOUNDARY FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
