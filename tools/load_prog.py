"""Load an eBPF program into the running board through the boot-time load
path (PROG_AREA in RAM), then read back the verdict slots.

  python3 tools/load_prog.py          # pass-all program replaces the filter
  python3 tools/load_prog.py --bad    # oversized count falls back, S_LOAD=2
"""
import struct, sys, time
from inject_swarm import wlink, read_words

PROG_AREA = 0x20003000
PROG_MAGIC = 0x474F5250
STATUS = 0x20000100
S_CAIJUE, S_LOAD = 16, 89

def enc(op, d, s, o, i):
    return ((op & 0xFF) | (((d & 0xF) | ((s & 0xF) << 4)) << 8)
            | ((o & 0xFFFF) << 16) | ((i & 0xFFFFFFFF) << 32))

PASS_ALL = [
    enc(0x71, 0, 1, 0, 0),          # r0 = ctx[0] (start byte)
    enc(0xB7, 1, 0, 0, 0xFD),       # r1 = 0xFD
    enc(0x1D, 0, 1, 2, 0),          # equal -> skip the reject path
    enc(0xB7, 0, 0, 0, 0),          # reject: r0 = 0
    enc(0x95, 0, 0, 0, 0),          # exit
    enc(0xB7, 0, 0, 0, 1),          # accept: r0 = 1
    enc(0x95, 0, 0, 0, 0),          # exit
]

def run(blob):
    open("swarm_chunk.bin", "wb").write(blob)
    wlink("flash", "-a", hex(PROG_AREA), "swarm_chunk.bin")
    wlink("reset")
    time.sleep(2)
    w = read_words(STATUS, 96)
    verdicts = [w.get(STATUS + 4 * (S_CAIJUE + i)) for i in range(6)]
    return verdicts, w.get(STATUS + 4 * S_LOAD)

def main():
    if "--bad" in sys.argv:
        blob = struct.pack("<II", PROG_MAGIC, 200)   # count over the cap
        want, wantload = [1, 1, 0, 2, 3, 4], 2
        name = "oversized program falls back"
    else:
        blob = (struct.pack("<II", PROG_MAGIC, len(PASS_ALL))
                + b"".join(struct.pack("<Q", e) for e in PASS_ALL))
        want, wantload = [1, 1, 0, 1, 1, 1], 1
        name = "pass-all via runtime load"
    verdicts, load = run(blob)
    ok = verdicts == want and load == wantload
    print(f"{name}: load={load} verdicts={verdicts}")
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
