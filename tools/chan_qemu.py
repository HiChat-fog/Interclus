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
        frame(0xD, b"\x00"),                     # F: status window query
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
    status_seen = [None]
    buf = bytearray()

    def watch():
        # byte-stream reader: binary status replies are carved out of
        # the stream first (their payload can contain newlines), then
        # the remaining text is split into lines for report syncing
        while True:
            try:
                chunk = p.stdout.read1(4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                i = buf.find(b"\x7e\x7e")
                if i < 0 or len(buf) < i + 5:
                    break
                ln = struct.unpack_from("<H", buf, i + 3)[0]
                if ln > 600:
                    del buf[:i + 1]
                    continue
                if len(buf) < i + 5 + ln + 1:
                    break
                body = buf[i + 2:i + 5 + ln]
                if ((sum(body) + buf[i + 5 + ln]) & 0xFF) == 0 and \
                        body[0] == 0x0D:
                    n = min(106, (ln - 4) // 4)
                    status_seen[0] = [struct.unpack_from(
                        "<I", body, 7 + 4 * k)[0] for k in range(n)]
                    del buf[:i + 5 + ln + 1]
                elif buf[i + 5 + ln] != 0 and ((sum(body) +
                                                buf[i + 5 + ln]) & 0xFF):
                    del buf[:i + 1]
                else:
                    del buf[:i + 5 + ln + 1]
            while True:
                j = buf.find(b"\n")
                if j < 0:
                    break
                line = bytes(buf[:j + 1])
                del buf[:j + 1]
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
        waits = [0, 1, 2, 3, 3, 3]  # B/C/D/E/F: round-synced
        for k, f in enumerate(frames):
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
    print("reports seen:", reports[0], "lines:", len(log_lines))
    if verdict[0] is None:
        print("".join(log_lines))
        print("timeout: no verdict line")
        return 2
    print("".join(log_lines[-10:]))
    ok = verdict[0] == 0
    if status_seen[0] is None:
        print("status: no reply frame")
        ok = False
    else:
        gate = status_seen[0][88]
        print(f"status: n={len(status_seen[0])} w0={status_seen[0][0]:#x} "
              f"w1={status_seen[0][1]:#x} w88={gate:#x} "
              f"w16={status_seen[0][16]:#x}")
        ok = ok and gate == 0xC0DE0000
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
