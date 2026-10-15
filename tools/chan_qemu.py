#!/usr/bin/env python3
"""Drive the runtime-channel acceptance (fw_chan.elf) under QEMU: spawn
the firmware, feed five console frames on stdin, and expect one verdict
line. Exercises the boot window (type 1), a runtime data frame (type 2),
a runtime program install (type 1), a corrupted frame (dropped), and an
illegal program (rejected by the gates):

  python3 tools/chan_qemu.py          # == CHAN PASS ==, exit 0
"""
import hashlib, struct, subprocess, sys, threading, time
from uart_frame import frame, prog_payload, enc, PASS_ALL
from inject_swarm import build_swarm, MAILBOX_MAGIC

def signed(ftype, body):
    """append the SHA-256 trailer the trust gate expects"""
    d = hashlib.sha256(body).digest()
    return frame(ftype, body + d)

def signed_prog():
    """type-1 frame whose digest covers the PEND layout the gate
    verifies: [cnt][kind][insns] — the PROG header is transport-only"""
    img = struct.pack("<II", len(PASS_ALL), 1)
    img += b"".join(struct.pack("<Q", e) for e in PASS_ALL)
    img += img[:0]  # keep the trailer split below simple
    inner = struct.pack("<II", len(PASS_ALL), 1) + \
        b"".join(struct.pack("<Q", e) for e in PASS_ALL)
    d = hashlib.sha256(inner).digest()
    payload = struct.pack("<II", 0x474F5250, len(PASS_ALL)) + \
        b"".join(struct.pack("<Q", e) for e in PASS_ALL) + d
    return frame(1, payload)

FW = "build/fw_chan.elf"
BADSTAT = [0xdeadbeefdeadbeef]           # illegal opcode: the gates say no

def swarm_payload(n=24, seed=7):
    """N=24 mirrors 3 alerts at seed 7 — a nonzero signal the C mirror
    must reproduce exactly."""
    pkts, _cells, _verdicts = build_swarm(n, seed)
    return struct.pack("<II", MAILBOX_MAGIC, n) + b"".join(pkts)

def main():
    d = bytearray(frame(2, swarm_payload()))
    d[6 + 20] ^= 0xFF        # flip a wire byte after framing: the checksum
    frames = [               # now lies, the assembler must drop the frame
        signed_prog(),                             # A: boot window
        frame(2, swarm_payload()),                 # B: runtime data
        signed_prog(),                             # C: runtime install
        bytes(d),                                  # D: corrupt, dropped
        frame(1,                                  # E: unpinned digest
              struct.pack("<II", 0x474F5250, 1)
              + struct.pack("<Q", BADSTAT[0])
              + hashlib.sha256(                   # valid trailer over a
                  struct.pack("<II", 1, 1)        # body the pins reject
                  + struct.pack("<Q", BADSTAT[0])).digest()),
    ]
    p = subprocess.Popen(
        ["qemu-system-riscv32", "-M", "virt", "-bios", "none",
         "-kernel", FW, "-display", "none", "-serial", "stdio",
         "-monitor", "none"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    log_lines = []
    reports = [0]
    verdict = [None]

    def watch():
        # the single reader: everything the firmware prints lands here;
        # the feeder syncs on round reports, the main loop judges
        while True:
            line = p.stdout.readline()
            if not line:
                break
            log_lines.append(line.decode("utf-8", "replace"))
            if b"verdicts:" in line:
                reports[0] += 1
            if b"== CHAN PASS ==" in line:
                verdict[0] = 0
            elif b"== CHAN FAIL ==" in line:
                verdict[0] = 1

    threading.Thread(target=watch, daemon=True).start()

    def feed():
        # A rides the boot window; frames B..E each wait until the
        # round count advances past the previous frame's round
        waits = [0, 1, 2, 3, 3]   # B after r1, C after r2, D and E
        for k, f in enumerate(frames):  # after r3 (state2 drains both)
            while k and reports[0] < waits[k]:
                if p.poll() is not None or verdict[0] is not None:
                    return
                time.sleep(0.05)
            try:
                p.stdin.write(f)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                return
        try:
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    threading.Thread(target=feed, daemon=True).start()

    deadline = time.time() + 150
    while time.time() < deadline and verdict[0] is None:
        if p.poll() is not None:
            break
        time.sleep(0.1)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
    time.sleep(0.3)
    if verdict[0] is None:
        print("".join(log_lines))
        print("timeout: no verdict line")
        return 2
    print("".join(log_lines[-10:]))
    print("RESULT:", "PASS ✅" if verdict[0] == 0 else "FAIL ❌")
    return verdict[0]

if __name__ == "__main__":
    sys.exit(main())
