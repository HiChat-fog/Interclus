"""E32 board drill: the runtime channel with the debugger as the wire.
Frames go in through the VUART rx ring, prints and replies come back
through the tx tap. Beats mirror chan_qemu: a runtime data commit, a
signed program install, a corrupt frame (dropped), an unpinned digest
(rejected by the trust gate), an operator re-arm, and a status window
query whose 106-word reply is decoded from the tap — no PA9/PA10 needed.

  cd tools && python3 chan_board.py
"""
import hashlib, struct, sys, time
from inject_swarm import wlink, read_words, build_swarm, MAILBOX_MAGIC
from uart_frame import frame, PASS_ALL
from pend import PROG_PEND

VU = 0x20001700
VU_MAGIC = 0x54524156
BASE = 0x20000100
S_CAIJUE, S_DONE, S_GATE = 16, 56, 88
S_CHONGTU, S_HLOAD, S_HREJ, S_REARM = 84, 93, 94, 98
TAP = bytearray()

def wr32(addr, val):
    wlink("write-mem", hex(addr), hex(val & 0xFFFFFFFF))

def vu_word(i):
    return read_words(VU + 4 * i, 1).get(VU + 4 * i, 0) or 0

def st_word(i):
    return read_words(BASE + 4 * i, 1).get(BASE + 4 * i, 0) or 0

def fresh_boot(timeout=12):
    wr32(VU, 0)                      # no stale virtual wire at boot
    wlink("write-mem", hex(PROG_PEND), "0x0")
    wlink("write-mem", hex(PROG_PEND + 0x240), "0x0")
    wr32(BASE + 4 * S_DONE, 0xFFFFFFFF)
    wr32(BASE + 4 * S_HLOAD, 0xFFFFFFFF)
    wlink("reset")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if (st_word(S_DONE) == 0x600DF00D and
                st_word(S_HLOAD) == 0 and st_word(S_GATE) == 0xC0DE0000):
            return True
        time.sleep(0.1)
    return False

def vu_arm():
    for i in (1, 2, 4, 5):
        wr32(VU + 4 * i, 0)
    wr32(VU + 12, 1)                 # tx ring tap on
    wr32(VU, VU_MAGIC)

def vsend(data):
    data = data + b"\x00" * (-len(data) % 4)
    while 1024 - (vu_word(1) - vu_word(2)) < len(data):
        time.sleep(0.02)
    wr_ = vu_word(1)
    if (wr_ & 1023) + len(data) > 1024:
        gap = 1024 - (wr_ & 1023)
        for i in range(0, gap, 4):
            wr32(VU + 0x20 + ((wr_ + i) & 1023), 0)
        wr_ += gap
    for i in range(0, len(data), 4):
        wr32(VU + 0x20 + ((wr_ + i) & 1023),
             struct.unpack_from("<I", data, i)[0])
    wr32(VU + 4, wr_ + len(data))    # publish: wr lands last

def pump():
    tw, tr = vu_word(4), vu_word(5)
    if tw != tr:
        w = read_words(VU + 0x420, 256)
        ring = bytearray()
        for i in range(1024):
            ring += struct.pack("<I", w.get(VU + 0x420 + 4 * i, 0))
        n = tw - tr
        start = tr & 1023
        TAP.extend((ring[start:] + ring[:max(0, start + n - 1024)])[:n])
        wr32(VU + 4 * 5, tw)

def carve(ftype):
    """binary frames of ftype out of the tap stream; their payload can
    hold newlines, so carve before any line-based reading"""
    out = []
    i = TAP.find(b"\x7E\x7E")
    while i >= 0 and len(TAP) >= i + 5:
        ln = TAP[i + 3] | (TAP[i + 4] << 8)
        if ln > 460:
            i = TAP.find(b"\x7E\x7E", i + 1)
            continue
        if len(TAP) < i + 5 + ln + 1:
            break
        body = TAP[i + 2:i + 5 + ln]
        if ((sum(body) + TAP[i + 5 + ln]) & 0xFF) == 0 and body[0] == ftype:
            out.append(bytes(body[3:]))
        i = TAP.find(b"\x7E\x7E", i + 5 + ln + 1)
    return out

def signed_prog():
    inner = struct.pack("<II", len(PASS_ALL), 1) + \
        b"".join(struct.pack("<Q", e) for e in PASS_ALL)
    payload = struct.pack("<II", 0x474F5250, len(PASS_ALL)) + \
        b"".join(struct.pack("<Q", e) for e in PASS_ALL) + \
        hashlib.sha256(inner).digest()
    return frame(1, payload)

def swarm_payload(n=8, seed=7):
    pkts, _c, _v = build_swarm(n, seed)
    return struct.pack("<II", MAILBOX_MAGIC, n) + b"".join(pkts)

def wait_st(pred, timeout=6):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.05)
    return False

def main():
    ok = fresh_boot()
    print(f"0 boot: {'ok' if ok else 'TIMEOUT'}")
    vu_arm()

    vsend(frame(2, swarm_payload()))
    ok &= wait_st(lambda: st_word(S_CHONGTU) == 8)
    pump()
    print(f"1 data commit: n={st_word(S_CHONGTU)} "
          f"verdicts-line={'verdicts' in TAP.decode('latin1')}")
    ok &= st_word(S_CHONGTU) == 8 and "verdicts" in TAP.decode("latin1")

    base_load = st_word(S_HLOAD)
    vsend(signed_prog())
    ok &= wait_st(lambda: st_word(S_HLOAD) == base_load + 1)
    ok &= wait_st(lambda: [st_word(S_CAIJUE + i) for i in range(6)] ==
                  [1, 1, 0, 1, 1, 1])
    print(f"2 program install: HLOAD={st_word(S_HLOAD)} "
          f"verdicts={[st_word(S_CAIJUE + i) for i in range(6)]}")

    d = bytearray(frame(2, swarm_payload()))
    d[6 + 20] ^= 0xFF
    vsend(bytes(d))
    time.sleep(1.0)
    print(f"3 corrupt frame: HLOAD={st_word(S_HLOAD)} "
          f"HREJ={st_word(S_HREJ)} (both unchanged)")
    ok &= st_word(S_HLOAD) == base_load + 1 and st_word(S_HREJ) == 0

    body = struct.pack("<II", 1, 1) + struct.pack("<Q", 0xdeadbeefdeadbeef)
    vsend(frame(1, struct.pack("<II", 0x474F5250, 1) +
                struct.pack("<Q", 0xdeadbeefdeadbeef) +
                hashlib.sha256(body).digest()))
    ok &= wait_st(lambda: st_word(S_HREJ) == 1)
    print(f"4 unpinned digest: HREJ={st_word(S_HREJ)}")

    vsend(frame(0xE, struct.pack("<I", 0)))
    ok &= wait_st(lambda: st_word(S_REARM) == 1)
    pump()
    rearm = carve(0xE)
    print(f"5 operator re-arm: REARM={st_word(S_REARM)} echo={len(rearm)}")
    ok &= st_word(S_REARM) == 1 and len(rearm) == 1

    vsend(frame(0xD, b"\x00"))
    ok &= wait_st(lambda: (pump() or True) and len(carve(0xD)) >= 1)
    replies = carve(0xD)
    words = []
    if replies:
        p = replies[-1]
        words = [struct.unpack_from("<I", p, 4 + 4 * k)[0]
                 for k in range(min(106, (len(p) - 4) // 4))]
    ref = [st_word(k) for k in range(106)]
    same = len(words) == 106 and all(
        words[k] == ref[k] for k in range(106) if k != 3)
    if len(words) == 106:
        print(f"6 status window: n={len(words)} w0={words[0]:#x} "
              f"w1={words[1]:#x} w88={words[88]:#x} match={same}")
    else:
        print(f"6 status window: n={len(words)} (match={same})")
    ok &= same and words[0] == 0xDEADBEEF and words[1] == 0xC0DE0008 and \
        words[88] == 0xC0DE0000

    wr32(VU, 0)
    wlink("reset")
    print("RESULT:", "CHAN BOARD PASS ✅" if ok else "CHAN BOARD FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
