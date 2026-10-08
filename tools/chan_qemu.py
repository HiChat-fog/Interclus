#!/usr/bin/env python3
"""Drive the runtime-channel acceptance (fw_chan.elf) under QEMU: spawn
the firmware, feed five console frames on stdin, and expect one verdict
line. Exercises the boot window (type 1), a runtime data frame (type 2),
a runtime program install (type 1), a corrupted frame (dropped), and an
illegal program (rejected by the gates):

  python3 tools/chan_qemu.py          # == CHAN PASS ==, exit 0
"""
import struct, subprocess, sys, threading, time
from uart_frame import frame, prog_payload, enc, PASS_ALL
from inject_swarm import build_swarm, MAILBOX_MAGIC

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
        frame(1, prog_payload()),                  # A: boot window
        frame(2, swarm_payload()),                 # B: runtime data
        frame(1, prog_payload()),                  # C: runtime install
        bytes(d),                                  # D: corrupt, dropped
        frame(1, struct.pack("<II", 0x474F5250, 1)
              + struct.pack("<Q", BADSTAT[0])),    # E: illegal opcode
    ]
    p = subprocess.Popen(
        ["qemu-system-riscv32", "-M", "virt", "-bios", "none",
         "-kernel", FW, "-display", "none", "-serial", "stdio",
         "-monitor", "none"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    def feed():
        for f in frames:
            try:
                p.stdin.write(f)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                return
            time.sleep(0.15)
        try:
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    threading.Thread(target=feed, daemon=True).start()

    log, verdict, deadline = [], None, time.time() + 60
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        text = line.decode("utf-8", "replace")
        log.append(text)
        if "== CHAN PASS ==" in text:
            verdict = 0
            break
        if "== CHAN FAIL ==" in text:
            verdict = 1
            break
    if verdict is None:
        p.kill()
        print("".join(log))
        print("timeout: no verdict line")
        return 2
    tail = "".join(log[-12:])
    print(tail)
    print("RESULT:", "PASS ✅" if verdict == 0 else "FAIL ❌")
    return verdict

if __name__ == "__main__":
    sys.exit(main())
