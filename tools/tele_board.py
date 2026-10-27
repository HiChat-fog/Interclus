"""Board telemetry drill (E24) over the debugger's virtual UART: a
poisoned native image is evicted, the evidence frame is read from the
TX ring, and the operator re-arm frame enters through the RX ring. No
USB-TTL adapter on PA9/PA10 is needed.

  cd tools && python3 tele_board.py
"""
import struct, sys, time
from inject_swarm import wlink, read_words
from pend import stage_native

BASE = 0x20000100
S_NAT2, S_REARM, S_NSLOT = 92, 98, 97
TELE, REARM = 0xF, 0xE
VU, MAGIC = 0x20001700, 0x54524156


def wr32(a, v):
    wlink("write-mem", hex(a), hex(v & 0xffffffff))


def vw(i):
    return read_words(VU + 4 * i, 1).get(VU + 4 * i, 0) or 0


def tap_on():
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


def send_frame(raw):
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


def wire_frame(ftype, payload):
    body = bytes([ftype]) + struct.pack("<H", len(payload)) + payload
    return b"\x7E\x7E" + body + bytes([(-sum(body)) & 0xFF])


def main():
    natvar = open("../build/native_variant.bin", "rb").read()
    trap = open("../build/native_trap.bin", "rb").read()
    ok = True
    tap_on()
    base_slot = read_words(BASE + 4 * S_NSLOT, 1).get(BASE + 4 * S_NSLOT, 0)
    rearm0 = read_words(BASE + 4 * S_REARM, 1).get(BASE + 4 * S_REARM, 0) or 0

    # 1. poison slot 0, wait for the eviction + telemetry (frames may
    # straddle pump() boundaries)
    stage_native(trap, slot=0)
    teles = []
    buf = bytearray()
    t0 = time.time()
    while time.time() - t0 < 8 and not teles:
        buf.extend(pump())
        i = buf.find(b"\x7E\x7E")
        while i >= 0 and len(buf) >= i + 5:
            ln = buf[i + 3] | (buf[i + 4] << 8)
            if ln > 64:
                del buf[:i + 1]
                i = buf.find(b"\x7E\x7E")
                continue
            if len(buf) < i + 5 + ln + 1:
                break
            body = buf[i + 2:i + 5 + ln]
            if ((sum(body) + buf[i + 5 + ln]) & 0xFF) == 0 and body[0] == 0x0F:
                teles.append(bytes(body[3:]))
            del buf[:i + 5 + ln + 1]
            i = buf.find(b"\x7E\x7E")
        time.sleep(.03)
    w = read_words(BASE, 100)
    nat2 = w.get(BASE + 4 * S_NAT2)
    nslot = w.get(BASE + 4 * S_NSLOT)
    print(f"1 poison+evict: teles={len(teles)} NAT2={hex(nat2 or 0)} "
          f"NSLOT={hex(nslot or 0)}")
    if teles:
        t = teles[0]
        print(f"   tele: comp={t[1]} slot={t[2]} "
              f"mcause={int.from_bytes(t[4:8],'little'):#x} "
              f"mtval={int.from_bytes(t[8:12],'little'):#x}")
    # a live slot 1 was the last-known-good: the boundary remaps to it
    want_slot = 1 if base_slot == 1 else 0xFFFFFFFF
    ok &= len(teles) == 1 and (nat2 or 0) == 0 and (nslot or 0) == want_slot

    # 2. operator re-arm + trusted image, proof returns
    send_frame(wire_frame(REARM, struct.pack("<I", 0)))
    stage_native(natvar, slot=0)
    time.sleep(4)
    w = read_words(BASE, 100)
    nat2 = w.get(BASE + 4 * S_NAT2)
    rearm = w.get(BASE + 4 * S_REARM)
    nslot = w.get(BASE + 4 * S_NSLOT)
    print(f"2 re-arm+trust: NAT2={hex(nat2 or 0)} REARM={rearm} "
          f"NSLOT={nslot}")
    ok &= (nat2 or 0) == 0xC0DE0003 and (rearm or 0) == rearm0 + 1 \
        and nslot == 0

    print("RESULT:", "TELE BOARD PASS ✅" if ok else "TELE BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
