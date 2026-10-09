"""Board hot-swap drill: no reset between steps — the running service loop
must pick up each staged image from PROG_PEND within a heartbeat cycle.
  1. clean boot (built-in policy)            verdicts [1 1 0 2 3 4], HLOAD 0
  2. stage pass_all  -> promoted live        verdicts [1 1 0 1 1 1], HLOAD 1
  3. stage mov-to-r10 -> fault -> rollback   verdicts zeros, HLOAD 2, ROLL 1
  4. stage pass_all again -> verdicts return HLOAD 3
  5. variant into slot 0 (remap drill)       HLOAD 4, NSLOT 0, NAT2 ...0003
  6. fetch-fault into slot 1 -> evicted,     HLOAD 5, ROLL 2, NAT2 0,
     boundary remapped to slot 0             NSLOT 0
  7. slot-1 variant revives slot 1           HLOAD 6, NSLOT 1, NAT2 ...0003
  8. fetch-fault into slot 0 -> evicted,     HLOAD 7, ROLL 3, NAT2 0,
     boundary remapped to slot 1             NSLOT 1
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
# static-legal, interpreter faults FP at run (register gate demands the
# well-formed tail)
BADRUN = [enc(0xB7, 10, 0, 0, 1), enc(0xB7, 0, 0, 0, 1), enc(0x95, 0, 0, 0, 0)]

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

def stage_native(code, entry=0, slot=0):
    # kind 2 image: [0]=len, [4]=kind, [8]=entry, [12]=slot, code at +16
    blob = struct.pack("<IIII", len(code), PEND_NATIVE, entry, slot) + code
    wlink("write-mem", hex(PROG_PEND), hex(len(code)))
    wlink("write-mem", hex(PROG_PEND + 4), hex(PEND_NATIVE))
    wlink("write-mem", hex(PROG_PEND + 8), hex(entry))
    wlink("write-mem", hex(PROG_PEND + 12), hex(slot))
    for i in range(0, len(blob) - 16, 4):
        word = struct.unpack_from("<I", blob, 16 + i)[0]
        wlink("write-mem", hex(PROG_PEND + 16 + i), hex(word))
    wlink("write-mem", hex(PROG_PEND + 0x208), hex(PEND_MAGIC))

NATVAR = open("../build/native_variant.bin", "rb").read()       # slot 0
NATVAR_S1 = open("../build/native_variant_s1.bin", "rb").read() # slot 1
BADNAT = bytearray(NATVAR)
BADNAT[0:8] = struct.pack("<II", 0x00000297, 0x10028067)  # auipc; jalr +0x1000

S_NAT2, S_REMAP, S_NSLOT = 92, 96, 97

def snap():
    w = read_words(BASE + 4 * 16, 6)     # S_CAIJUE..S_CAIJUE+5
    w.update(read_words(BASE + 4 * 88, 8))   # S_GATE..S_ROLL
    w.update(read_words(BASE + 4 * S_REMAP, 2))  # S_REMAP, S_NSLOT
    w.update(read_words(BASE + 4 * S_NAT2, 1))
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

    # native slot table: variant into slot 0 (the install remaps the exec
    # window and runs the remap drill), then a fetch-fault image into
    # slot 1 gets evicted with the boundary remapping back, then slot 1
    # is revived with its own good variant, then slot 0 is poisoned too
    stage_native(NATVAR)
    v4, h4, _, r4 = wait_step("5 native variant slot0",
                              lambda v, hl, hr, ro: hl == 4)
    w = snap()[0]
    ok &= v4 == [1, 1, 0, 1, 1, 1] and h4 == 4 and r4 == 1
    ok &= w.get(BASE + 4 * S_NSLOT) == 0 and w.get(BASE + 4 * S_NAT2) == 0xC0DE0003
    ok &= 0 < (w.get(BASE + 4 * S_REMAP) or 0) < 10000

    stage_native(BADNAT, slot=1)
    v5, h5, _, r5 = wait_step("6 native fault+remap",
                              lambda v, hl, hr, ro: ro == 2)
    w = snap()[0]
    ok &= h5 == 5 and r5 == 2
    ok &= w.get(BASE + 4 * S_NSLOT) == 0 and w.get(BASE + 4 * S_NAT2) == 0

    stage_native(NATVAR_S1, slot=1)
    v6, h6, _, r6 = wait_step("7 slot1 variant live",
                              lambda v, hl, hr, ro: hl == 6)
    w = snap()[0]
    ok &= v6 == [1, 1, 0, 1, 1, 1] and h6 == 6
    ok &= w.get(BASE + 4 * S_NSLOT) == 1 and w.get(BASE + 4 * S_NAT2) == 0xC0DE0003

    stage_native(BADNAT, slot=0)
    v7, h7, _, r7 = wait_step("8 slot0 fault+remap",
                              lambda v, hl, hr, ro: ro == 3)
    w = snap()[0]
    ok &= h7 == 7 and r7 == 3
    ok &= w.get(BASE + 4 * S_NSLOT) == 1 and w.get(BASE + 4 * S_NAT2) == 0

    print("RESULT:", "HOT BOARD PASS ✅" if ok else "HOT BOARD FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
