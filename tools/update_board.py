#!/usr/bin/env python3
"""E34 board drill over VUART: stop-and-wait update with loss-shaped
faults, duplicate ACKs, ordered commit, and reset abort semantics."""
import struct, sys, time
from inject_swarm import wlink, read_words
from uart_frame import frame, PASS_ALL
from update_frame import begin, chunks, commit, abort

VU = 0x20001700
BASE = 0x20000100
MAGIC = 0x54524156
S_HLOAD, S_HREJ, S_DONE, S_GATE = 93, 94, 56, 88


def wr32(a, v):
    wlink("write-mem", hex(a), hex(v & 0xffffffff))


def vw(i):
    return read_words(VU + 4 * i, 1).get(VU + 4 * i, 0) or 0


def sw(i):
    return read_words(BASE + 4 * i, 1).get(BASE + 4 * i, 0) or 0


def arm():
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


def send(raw):
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


def replies(timeout=3):
    end, out = time.time() + timeout, []
    buf = bytearray()
    while time.time() < end:
        buf.extend(pump())
        while True:
            i = buf.find(b"\x7e\x7e")
            if i < 0 or len(buf) < i + 5:
                break
            ln = buf[i + 3] | (buf[i + 4] << 8)
            if len(buf) < i + 5 + ln + 1:
                break
            body = buf[i + 2:i + 5 + ln]
            c = buf[i + 5 + ln]
            del buf[:i + 5 + ln + 1]
            if ((sum(body) + c) & 255) == 0:
                out.append(bytes(body[3:]))
        if out:
            return out
        time.sleep(.03)
    return out


def wait_boot(timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        if sw(S_DONE) == 0x600df00d and sw(S_GATE) == 0xc0de0000:
            return True
        time.sleep(.1)
    return False


def boot():
    wr32(VU, 0)
    wr32(0x20003800, 0)
    wr32(0x20003A08, 0)
    wr32(BASE + 4 * S_DONE, 0xffffffff)
    wr32(BASE + 4 * S_HLOAD, 0xffffffff)
    wlink("reset")
    return wait_boot()


def main():
    ok = boot()
    arm()
    image = struct.pack("<II", len(PASS_ALL), 1)
    image += b"".join(struct.pack("<Q", x) for x in PASS_ALL)
    image += __import__("hashlib").sha256(image).digest()
    tid = 0xE3400001
    hload0, hrej0 = sw(S_HLOAD), sw(S_HREJ)
    print(f"0 boot: {ok} HLOAD={hload0} HREJ={hrej0}")

    send(frame(4, begin(tid, image)))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x80
    print(f"1 begin ACK: {r[-1][0] if r else None:#x}")

    cs = list(chunks(tid, image, 32))
    send(frame(4, cs[1]))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x81 and r[-1][7] == 3
    print(f"2 out-of-order NACK: detail={r[-1][7] if r else None}")

    send(frame(4, cs[0]))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x80 and r[-1][5] == 1
    send(frame(4, cs[0]))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x80 and r[-1][5] == 1
    print(f"3 correct+duplicate ACK: seq={r[-1][5] if r else None}")

    bad = bytearray(cs[1]); bad[10] ^= 1
    send(frame(4, bytes(bad)))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x81 and r[-1][7] == 2
    print(f"4 CRC NACK: detail={r[-1][7] if r else None}")

    send(frame(4, commit(tid)))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x81 and r[-1][7] == 3
    print(f"5 missing COMMIT NACK: detail={r[-1][7] if r else None}")

    for c in cs[1:]:
        send(frame(4, c))
        r = replies()
        ok = ok and bool(r) and r[-1][0] == 0x80
    send(frame(4, commit(tid)))
    r = replies()
    staged = any(x[0] == 0x82 for x in r)
    verdict = next((x[0] for x in r if x[0] in (0x83, 0x84)), None)
    ok = ok and staged
    print(f"6 complete STAGED: {staged}")
    end = time.time() + 6
    while verdict is None and time.time() < end:
        r = replies(.4)
        verdict = next((x[0] for x in r if x[0] in (0x83, 0x84)), None)
    ok = ok and verdict == 0x83 and sw(S_HLOAD) == hload0 + 1
    shown = f"{verdict:#x}" if verdict is not None else "none"
    print(f"7 gate ACCEPT: code={shown} HLOAD={sw(S_HLOAD)}")

    tid2 = 0xE3400002
    cs2 = list(chunks(tid2, image, 32))
    send(frame(4, begin(tid2, image)))
    r = replies()
    abort_ok = bool(r) and r[-1][0] == 0x80
    send(frame(4, cs2[0]))
    replies()
    send(frame(4, abort(tid2)))
    r = replies()
    abort_ok = abort_ok and bool(r) and r[-1][0] == 0x85
    send(frame(4, cs2[0]))
    r = replies()
    abort_ok = abort_ok and bool(r) and r[-1][0] == 0x81 and r[-1][7] == 7
    send(frame(4, begin(tid2, image)))
    r = replies()
    abort_ok = abort_ok and bool(r) and r[-1][0] == 0x80
    send(frame(4, abort(tid2)))
    r = replies()
    abort_ok = abort_ok and bool(r) and r[-1][0] == 0x85
    ok = ok and abort_ok
    print(f"8 abort: {abort_ok} HLOAD={sw(S_HLOAD)}")

    # a reset in the middle of a transfer must leave no half image and no
    # poisoned id: the device boots clean and the same id may start over
    send(frame(4, begin(tid2, image)))
    replies()
    send(frame(4, cs2[0]))
    replies()
    wlink("reset")
    ok = ok and wait_boot()
    ok = ok and sw(S_HLOAD) == 0
    print(f"9 reset abort: HLOAD after reset={sw(S_HLOAD)}")

    send(frame(4, begin(tid2, image)))
    r = replies()
    ok = ok and bool(r) and r[-1][0] == 0x80
    for c in cs2:
        send(frame(4, c))
        r = replies()
        ok = ok and bool(r) and r[-1][0] == 0x80
    send(frame(4, commit(tid2)))
    r = replies()
    staged = any(x[0] == 0x82 for x in r)
    verdict = next((x[0] for x in r if x[0] in (0x83, 0x84)), None)
    ok = ok and staged
    end = time.time() + 6
    while verdict is None and time.time() < end:
        r = replies(.4)
        verdict = next((x[0] for x in r if x[0] in (0x83, 0x84)), None)
    ok = ok and verdict == 0x83 and sw(S_HLOAD) == 1
    shown = f"{verdict:#x}" if verdict is not None else "none"
    print(f"10 replay after reset: code={shown} HLOAD={sw(S_HLOAD)}")

    # the retrying client itself, over the real wire, with the first
    # transmission of one chunk dropped
    from update_client import Client

    pending = []

    def recv_reply(timeout=0.6):
        if not pending:
            pending.extend(replies(timeout))
        if not pending:
            return None
        got = pending.pop(0)
        return (got[0], int.from_bytes(got[1:5], "little"),
                int.from_bytes(got[5:7], "little"), got[7])

    dropped = set()

    def lossy_send(raw):
        if raw[0] == 2:
            seq = int.from_bytes(raw[5:7], "little")
            if seq == 0 and not dropped:
                dropped.add(seq)
                return
        send(frame(4, raw))

    cli = Client(lossy_send, recv_reply)
    accepted = cli.transfer(0xE3400003, image)
    ok = ok and accepted and cli.resends >= 1 and sw(S_HLOAD) == 2
    print(f"11 retry client: accepted={accepted} resends={cli.resends} "
          f"HLOAD={sw(S_HLOAD)}")

    print("RESULT:", "UPDATE BOARD PASS ✅" if ok else "UPDATE BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
