"""Board hot-swap drill: no reset between steps — the running service loop
must pick up each staged image from PROG_PEND within a heartbeat cycle.
  1. clean boot (built-in policy)          verdicts [1 1 0 2 3 4], HLOAD 0
  2. stage pass_all  -> promoted live      verdicts [1 1 0 1 1 1], HLOAD 1
  3. stage mov-to-r10 -> fault -> rollback verdicts [1 1 0 1 1 1], HLOAD 2, ROLL 1
Status words are addressed as STATUS_BASE + 4*word_index (S_* in
platform.h are word indices)."""
import struct, sys, time
from inject_swarm import wlink, read_words
from uart_frame import PASS_ALL, enc

PROG_PEND = 0x20003800            # PROG_AREA + 0x800 (board)
BASE = 0x20000100                 # STATUS
PEND_MAGIC = 0x444E4550
PEND_EBPF = 1
PEND_NATIVE = 2
BADRUN = [enc(0xB7, 10, 0, 0, 1)] # static-legal, interpreter faults FP at run

def stage(insns):
    # magic-last layout (platform.h PROG_PEND). Staged word-by-word via
    # write-mem: flash -a into RAM is lossy on this link (inject_swarm
    # carries a verify-fix loop for the same reason), and a lost or
    # reordered word here races the ~ms service-loop poller.
    wlink("write-mem", hex(PROG_PEND), hex(len(insns)))
    wlink("write-mem", hex(PROG_PEND + 4), hex(PEND_EBPF))
    for i, e in enumerate(insns):
        lo = e & 0xFFFFFFFF
        hi = (e >> 32) & 0xFFFFFFFF
        wlink("write-mem", hex(PROG_PEND + 8 + 8 * i), hex(lo))
        wlink("write-mem", hex(PROG_PEND + 8 + 8 * i + 4), hex(hi))
    wlink("write-mem", hex(PROG_PEND + 0x208), hex(PEND_MAGIC))

def stage_native(code, entry=0):
    # kind 2 image: [0]=len, [4]=kind, [8]=entry, code at +12, magic last
    blob = struct.pack("<III", len(code), PEND_NATIVE, entry) + code
    wlink("write-mem", hex(PROG_PEND), hex(len(code)))
    wlink("write-mem", hex(PROG_PEND + 4), hex(PEND_NATIVE))
    wlink("write-mem", hex(PROG_PEND + 8), hex(entry))
    for i in range(0, len(blob) - 12, 4):
        word = struct.unpack_from("<I", blob, 12 + i)[0]
        wlink("write-mem", hex(PROG_PEND + 12 + i), hex(word))
    wlink("write-mem", hex(PROG_PEND + 0x208), hex(PEND_MAGIC))

NATVAR = open("../build/native_variant.bin", "rb").read()
BADNAT = bytearray(NATVAR)
BADNAT[0:8] = struct.pack("<II", 0x00000297, 0x10028067)  # auipc; jalr +0x1000

def snap():
    w = read_words(BASE + 4 * 16, 6)     # S_CAIJUE..S_CAIJUE+5
    w.update(read_words(BASE + 4 * 88, 8))   # S_GATE..S_ROLL
    return (w, [w.get(BASE + 4 * (16 + i)) for i in range(6)],
            w.get(BASE + 4 * 88), w.get(BASE + 4 * 89),
            w.get(BASE + 4 * 93), w.get(BASE + 4 * 94), w.get(BASE + 4 * 95))

def wait_step(tag, pred, timeout=6):
    """poll for a state transition; the schedule round takes a few ms
    after each promotion, the fixed sleep raced it"""
    deadline = time.time() + timeout
    while True:
        w, v, gate, load, hl, hr, ro = snap()
        if pred(v, hl, hr, ro):
            break
        if time.time() > deadline:
            break
        time.sleep(0.3)
    print(f"{tag}: verdicts={v} GATE={hex(gate or 0)} LOAD={load} "
          f"HLOAD={hl} HREJ={hr} ROLL={ro}")
    return v, hl, hr, ro

def main():
    # self-cleaning start: no stale magic may drive the service loop while
    # we establish the built-in baseline
    wlink("write-mem", hex(0x20003000), "0x0")
    wlink("write-mem", hex(PROG_PEND), "0x0")
    wlink("write-mem", hex(PROG_PEND + 0x208), "0x0")
    for _ in range(3):
        wlink("reset"); time.sleep(2)
        _, _, gate, load, _, _, _ = snap()
        if gate == 0xC0DE0000 and load == 0:
            break
    v0, h0, _, r0 = wait_step("1 boot(builtin)",
                              lambda v, hl, hr, ro: hl == 0 and ro == 0)
    ok = v0 == [1, 1, 0, 2, 3, 4] and h0 == 0 and r0 == 0

    stage(PASS_ALL)
    v1, h1, _, r1 = wait_step("2 promote(pass_all)",
                              lambda v, hl, hr, ro: hl == 1)
    ok &= v1 == [1, 1, 0, 1, 1, 1] and h1 == 1 and r1 == 0

    stage(BADRUN)
    v2, h2, _, r2 = wait_step("3 fault+rollback",
                              lambda v, hl, hr, ro: ro == 1)
    # the verdict slots hold the FAULTED round's evidence (zeros) — the
    # rollback restored pass_all for the NEXT round, so prove it by
    # promoting once more and watching the verdicts come back
    ok &= v2 == [0, 0, 0, 0, 0, 0] and h2 == 2 and r2 == 1

    stage(PASS_ALL)
    v3, h3, _, r3 = wait_step("4 restored program runs",
                              lambda v, hl, hr, ro: hl == 3)
    ok &= v3 == [1, 1, 0, 1, 1, 1] and h3 == 3 and r3 == 1

    # native hot path: variant module (proof 0xC0DE0003) replaces the
    # built-in demo, then a fetch-fault image gets evicted + rolled back,
    # then the variant returns
    stage_native(NATVAR)
    v4, h4, _, r4 = wait_step("5 native variant live",
                              lambda v, hl, hr, ro: hl == 4)
    ok &= v4 == [1, 1, 0, 1, 1, 1] and h4 == 4 and r4 == 1
    w = read_words(BASE + 4 * 92, 1)[BASE + 4 * 92]
    ok &= w == 0xC0DE0003

    stage_native(BADNAT)
    v5, h5, _, r5 = wait_step("6 native fault+rollback",
                              lambda v, hl, hr, ro: ro == 2)
    ok &= v5 == [1, 1, 0, 1, 1, 1] and h5 == 5 and r5 == 2
    w = read_words(BASE + 4 * 92, 1)[BASE + 4 * 92]
    ok &= w == 0

    stage_native(NATVAR)
    v6, h6, _, r6 = wait_step("7 native variant back",
                              lambda v, hl, hr, ro: hl == 6)
    ok &= v6 == [1, 1, 0, 1, 1, 1] and h6 == 6 and r6 == 2
    w = read_words(BASE + 4 * 92, 1)[BASE + 4 * 92]
    ok &= w == 0xC0DE0003

    print("RESULT:", "HOT BOARD PASS ✅" if ok else "HOT BOARD FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
