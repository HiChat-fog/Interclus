#!/usr/bin/env python3
"""Drive the telemetry acceptance (fw_tele.elf): the firmware installs a
fetch-fault native image at state 0, the round evicts it and emits the
evidence frame; the operator re-arm frame is sent while the firmware
drains the channel (the eviction lands about a second after boot, so the
frame goes out at ~0.2 s and the firmware picks it up in its drain
window). Decodes binary frames (0xF evidence, 0xE ack) from the console
stream.

  python3 tools/tele_qemu.py    # == TELE PASS ==, exit 0
"""
import struct, subprocess, sys, threading, time

FW = "build/fw_tele.elf"
TELE, REARM = 0xF, 0xE

def frame(ftype, payload=b""):
    body = bytes([ftype]) + struct.pack("<H", len(payload)) + payload
    return b"\x7E\x7E" + body + bytes([(-sum(body)) & 0xFF])

def main():
    p = subprocess.Popen(
        ["qemu-system-riscv32", "-M", "virt", "-bios", "none",
         "-kernel", FW, "-display", "none", "-serial", "stdio",
         "-monitor", "none"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    teles, acks = [], []
    buf = bytearray()
    done = threading.Event()

    def pump():
        while not done.is_set():
            try:
                chunk = p.stdout.read1(4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                i = buf.find(b"\x7E\x7E")
                if i < 0 or len(buf) < i + 5:
                    break
                ln = struct.unpack_from("<H", buf, i + 3)[0]
                if len(buf) < i + 5 + ln + 1:
                    break
                body = buf[i + 2:i + 5 + ln]      # type..payload
                csum = buf[i + 5 + ln]
                if ln <= 64 and ((sum(body) + csum) & 0xFF) == 0:
                    t = body[0]
                    payload = bytes(body[3:])
                    if t == TELE:
                        teles.append(payload)
                    elif t == REARM:
                        acks.append(payload)
                    del buf[:i + 5 + ln + 1]
                else:
                    del buf[:i + 1]

    threading.Thread(target=pump, daemon=True).start()
    time.sleep(0.2)
    try:
        p.stdin.write(frame(REARM, struct.pack("<I", 0)))
        p.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    try:
        rc = p.wait(timeout=45)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = 1
    done.set()

    print(f"telemetry frames: {len(teles)}  acks: {len(acks)}")
    if teles:
        t = teles[0]
        mcause = int.from_bytes(t[4:8], "little")
        mtval = int.from_bytes(t[8:12], "little")
        print(f"tele: idx={t[0]} comp={t[1]} slot={t[2]} "
              f"mcause={mcause:#x} mtval={mtval:#x}")
    ok = rc == 0 and len(teles) >= 1 and len(acks) >= 1
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
