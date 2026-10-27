#!/usr/bin/env python3
"""QEMU end-to-end reliable-update fault drill."""
import hashlib, os, re, select, struct, subprocess, sys, time
from uart_frame import frame, PASS_ALL
from update_frame import begin, chunks, commit, abort

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW = os.path.join(ROOT, "build", "fw_update.elf")
QEMU = ["qemu-system-riscv32", "-M", "virt", "-bios", "none",
        "-display", "none", "-serial", "stdio", "-monitor", "none"]


def parse(buf):
    out = []
    while True:
        i = buf.find(b"\x7e\x7e")
        if i < 0 or len(buf) < i + 5:
            break
        n = buf[i + 3] | (buf[i + 4] << 8)
        if len(buf) < i + 5 + n + 1:
            break
        body = buf[i + 2:i + 5 + n]
        c = buf[i + 5 + n]
        del buf[:i + 5 + n + 1]
        if ((sum(body) + c) & 255) == 0:
            out.append(bytes(body[3:]))
    return out


def ebpf_image():
    body = struct.pack("<II", len(PASS_ALL), 1)
    body += b"".join(struct.pack("<Q", x) for x in PASS_ALL)
    return body + hashlib.sha256(body).digest()


def native_image():
    code = open(os.path.join(ROOT, "build", "native_variant_qemu.bin"),
                "rb").read()
    body = struct.pack("<IIII", len(code), 2, 0, 0) + code
    return body + hashlib.sha256(body).digest()


def main():
    p = subprocess.Popen(QEMU + ["-kernel", FW], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0)
    buf, raw, replies = bytearray(), bytearray(), []

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([p.stdout], [], [], 0.02)
            if not r:
                continue
            chunk = os.read(p.stdout.fileno(), 4096)
            if not chunk:
                return
            buf.extend(chunk)
            raw.extend(chunk)

    def send(x):
        p.stdin.write(frame(4, x))
        p.stdin.flush()

    def wait_reply(timeout=3.0):
        deadline = time.time() + timeout
        while True:
            replies.extend(parse(buf))
            if replies:
                return replies.pop(0)
            left = deadline - time.time()
            if left <= 0:
                return None
            pump(min(0.02, left))

    def drain():
        pump(0.3)
        replies.extend(parse(buf))
        replies.clear()

    end = time.time() + 5
    while time.time() < end and b"UPDATE READY" not in raw:
        pump(0.05)
    ok = b"UPDATE READY" in raw
    pump(0.9)      # banner precedes boot_main; its fuzz loop eats the wire

    def begin_ack(tid, image, tries=6):
        for _ in range(tries):
            send(begin(tid, image))
            r = wait_reply(0.6)
            if r and r[0] == 0x80:
                return r
        return None

    tid, img = 0xE3401001, ebpf_image()
    r0 = begin_ack(tid, img)
    cs = list(chunks(tid, img, 32))
    send(cs[1]); r1 = wait_reply()
    send(cs[0]); r2 = wait_reply()
    send(cs[0]); r3 = wait_reply()
    bad = bytearray(cs[1]); bad[10] ^= 1
    send(bad); r4 = wait_reply()
    send(commit(tid)); r5 = wait_reply()
    for c in cs[1:]:
        send(c); wait_reply()
    send(commit(tid)); r6 = wait_reply()
    send(commit(tid)); r7 = wait_reply()
    ok &= all(x is not None for x in (r0, r1, r2, r3, r4, r5, r6, r7))
    codes = [x[0] if x else None for x in (r0, r1, r2, r3, r4, r5, r6, r7)]
    details = [x[7] if x else None for x in (r0, r1, r2, r3, r4, r5, r6, r7)]
    print("codes:", codes)
    print("details:", details)
    # begin ACK, out-of-order NACK(3), data ACK, duplicate ACK,
    # CRC NACK(2), missing COMMIT NACK(3), STAGED, final ACCEPT
    ok &= codes[:6] == [0x80, 0x81, 0x80, 0x80, 0x81, 0x81]
    ok &= details[1] == 3 and details[4] == 2 and details[5] == 3
    ok &= codes[6:] == [0x82, 0x83]

    # ABORT discards the half-built image; the same id may start clean.
    drain()
    tid = 0xE3401002
    cs2 = list(chunks(tid, img, 32))
    a0 = begin_ack(tid, img)
    send(cs2[0]); a1 = wait_reply()
    send(abort(tid)); a2 = wait_reply()
    send(cs2[0]); a3 = wait_reply()
    send(begin(tid, img)); a4 = wait_reply()
    send(abort(tid)); a5 = wait_reply()
    acodes = [x[0] if x else None for x in (a0, a1, a2, a3, a4, a5)]
    adetails = [x[7] if x else None for x in (a0, a1, a2, a3, a4, a5)]
    print("abort codes:", acodes)
    print("abort details:", adetails)
    ok &= acodes == [0x80, 0x80, 0x85, 0x81, 0x80, 0x85]
    ok &= adetails[3] == 7          # no active transaction after ABORT

    drain()
    from update_client import Client

    def recv():
        r = wait_reply(0.4)
        if r is None:
            return None
        return (r[0], int.from_bytes(r[1:5], "little"),
                int.from_bytes(r[5:7], "little"), r[7])

    def clean_send(x):
        send(x)

    cli = Client(clean_send, recv)
    ok &= cli.transfer(0xE3402001, img)
    print(f"clean client: accepted={cli.codes[-1] == 0x83} "
          f"sends={cli.sends} resends={cli.resends}")

    cli = Client(clean_send, recv)
    ok &= cli.transfer(0xE3402002, native_image())
    print(f"native client: accepted={cli.codes[-1] == 0x83} "
          f"sends={cli.sends} resends={cli.resends}")
    ok &= cli.resends == 0

    def lossy_send(drop):
        seen = set()

        def wrapped(x):
            if x[0] == 2:
                seq = int.from_bytes(x[5:7], "little")
                if seq in drop and seq not in seen:
                    seen.add(seq)          # first transmission is lost
                    return
            send(x)
        return wrapped

    for tid, drop in ((0xE3402003, {0}), (0xE3402004, {1, 2})):
        cli = Client(lossy_send(drop), recv)
        accepted = cli.transfer(tid, img)
        print(f"lossy {sorted(drop)}: accepted={accepted} "
              f"sends={cli.sends} resends={cli.resends}")
        ok &= accepted and cli.resends >= len(drop)

    pump(0.4)
    accepted = [int(x) for x in re.findall(rb"ACCEPTED h=(\d+)", bytes(raw))]
    print("installs:", accepted)
    ok &= accepted == [1, 2, 3, 4, 5]
    ok &= b"REJECTED" not in bytes(raw)

    p.kill(); p.wait()
    # A reset at any point before COMMIT is a discard: a fresh service
    # starts clean and accepts a new transfer id.
    q = subprocess.Popen(QEMU + ["-kernel", FW], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0)
    ready, end = b"", time.time() + 5
    while time.time() < end and b"UPDATE READY" not in ready:
        r, _, _ = select.select([q.stdout], [], [], 0.1)
        if r:
            chunk = os.read(q.stdout.fileno(), 256)
            if not chunk:
                break
            ready += chunk
    q.kill(); q.wait()
    ok &= b"UPDATE READY" in ready
    print("reset restart:", ready.decode("latin1").strip())
    print("RESULT:", "UPDATE QEMU PASS ✅" if ok else "UPDATE QEMU FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
