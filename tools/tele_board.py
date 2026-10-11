"""Board telemetry drill (E24): a poisoned native image is evicted and
the evidence frame flows out of PA9; the operator re-arm frame revives
the slot with a trusted image, proof returns. The wire half needs a
USB-TTL adapter on PA9/PA10 — /dev/ttyACM0 is the WCH-Link's own CDC and
carries nothing of the board's UART. Verification goes through wlink.

  cd tools && python3 tele_board.py /dev/ttyUSB0
"""
import struct, sys, time
from inject_swarm import wlink, read_words
from uart_frame import enc

BASE = 0x20000100
PROG_PEND = 0x20003800
PEND_MAGIC = 0x444E4550
S_NAT2, S_REARM, S_NSLOT = 92, 98, 97
TELE, REARM = 0xF, 0xE

def stage_native(code, entry=0, slot=0):
    blob = struct.pack("<IIII", len(code), 2, entry, slot) + code
    wlink("write-mem", hex(PROG_PEND), hex(len(code)))
    wlink("write-mem", hex(PROG_PEND + 4), "0x2")
    wlink("write-mem", hex(PROG_PEND + 8), hex(entry))
    wlink("write-mem", hex(PROG_PEND + 12), hex(slot))
    for i in range(0, len(blob) - 16, 4):
        wlink("write-mem", hex(PROG_PEND + 16 + i),
              hex(struct.unpack_from("<I", blob, 16 + i)[0]))
    wlink("write-mem", hex(PROG_PEND + 0x208), hex(PEND_MAGIC))

def wire_frame(ftype, payload):
    body = bytes([ftype]) + struct.pack("<H", len(payload)) + payload
    return b"\x7E\x7E" + body + bytes([(-sum(body)) & 0xFF])

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    import serial
    ser = serial.Serial(port, 115200, timeout=0.2)
    natvar = open("../build/native_variant.bin", "rb").read()
    badnat = bytearray(natvar)
    badnat[0:8] = struct.pack("<II", 0x00000297, 0x10028067)
    ok = True

    # 1. poison slot 0, wait for the eviction + telemetry (streaming
    # parser: frames may straddle read() chunk boundaries)
    stage_native(bytes(badnat), slot=0)
    teles = []
    buf = bytearray()
    t0 = time.time()
    while time.time() - t0 < 8 and not teles:
        buf.extend(ser.read(256))
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
    ok &= len(teles) == 1 and (nat2 or 0) == 0 and (nslot or 0) == 0xFFFFFFFF

    # 2. operator re-arm + trusted image, proof returns
    ser.write(wire_frame(REARM, struct.pack("<I", 0)))
    ser.flush()
    stage_native(natvar, slot=0)
    time.sleep(4)
    w = read_words(BASE, 100)
    nat2 = w.get(BASE + 4 * S_NAT2)
    rearm = w.get(BASE + 4 * S_REARM)
    nslot = w.get(BASE + 4 * S_NSLOT)
    print(f"2 re-arm+trust: NAT2={hex(nat2 or 0)} REARM={rearm} "
          f"NSLOT={nslot}")
    ok &= (nat2 or 0) == 0xC0DE0003 and (rearm or 0) == 1 and nslot == 0

    print("RESULT:", "TELE BOARD PASS ✅" if ok else "TELE BOARD FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
