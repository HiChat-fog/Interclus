"""Board drill for the runtime channel (E21): send live frames over the
console wire (USART1 PA9/PA10, needs a USB-TTL adapter) and verify the
effect through the debugger. wlink keeps only its flash/verify role.

  python3 tools/uart_data.py            # data frame: 24-packet swarm, live
  python3 tools/uart_data.py 48         # any size up to 64
  python3 tools/uart_data.py --prog     # runtime install of pass_all

Data frames commit between rounds; the board re-runs the schedule and
S_CHONGTU_N/S_LAIYUAN/S_JINGBAO must match the host mirror. A round eats
serial bytes (no FIFO, no flow control), so a frame can be lost mid-run —
the sender retries on timeout and the checksum keeps partial garbage from
ever committing. Requires pyserial for the wire and wlink for verification.
"""
import struct, sys, time
from inject_swarm import (wlink, read_words, build_swarm, MAILBOX_MAGIC,
                          MAILBOX)
from uart_frame import frame, prog_payload

STATUS = 0x20000100
S_CAIJUE, S_JINGBAO, S_CHONGTU_N, S_LAIYUAN = 16, 83, 84, 85
S_HLOAD, S_HREJ = 93, 94
BAUD = 115200

def c_mirror(blob):
    """The firmware's mirror: screening over the committed packets."""
    n = struct.unpack_from("<I", blob, 4)[0]
    m = [0] * 64
    alerts = 0
    for i in range(n):
        lat, lon = struct.unpack_from("<ii", blob, 8 + 42 * i + 10)
        c = ((lat >> 26) & 7) * 8 + ((lon >> 26) & 7)
        m[c] += 1
        if m[c] > 3 or m[(c - 1) & 63] > 3 or m[(c + 1) & 63] > 3:
            alerts += 1
    return alerts

def send_retry(ser, wire, tries=3):
    for k in range(tries):
        ser.reset_input_buffer()
        ser.write(wire)
        ser.flush()
        time.sleep(1.5)          # commit + one full schedule round
        w = read_words(STATUS, 96)
        if any(v is not None for v in w.values()):
            return w
        print(f"  read failed, retry {k + 1}/{tries}")
    return None

def data_mode(port, n, seed):
    import serial
    pkts, _cells, _v = build_swarm(n, seed)
    blob = struct.pack("<II", MAILBOX_MAGIC, n) + b"".join(pkts)
    want_alerts = c_mirror(blob)
    ser = serial.Serial(port, BAUD, timeout=1)
    print(f"data frame: N={n} seed={seed} expect alerts={want_alerts}")
    w = send_retry(ser, frame(2, blob))
    ser.close()
    if not w:
        print("RESULT: FAIL ❌ (no STATUS reads)")
        return 1
    confn, src, alerts = (w.get(STATUS + 4 * S_CHONGTU_N),
                          w.get(STATUS + 4 * S_LAIYUAN),
                          w.get(STATUS + 4 * S_JINGBAO))
    ok = confn == n and src == 1 and alerts == want_alerts
    print(f"board CONFN={confn} source={src} alerts={alerts}")
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

def prog_mode(port):
    import serial
    ser = serial.Serial(port, BAUD, timeout=1)
    before = read_words(STATUS, 96).get(STATUS + 4 * S_HLOAD)
    print("program frame: pass_all at runtime")
    w = send_retry(ser, frame(1, prog_payload()))
    ser.close()
    if not w:
        print("RESULT: FAIL ❌ (no STATUS reads)")
        return 1
    hload = w.get(STATUS + 4 * S_HLOAD)
    verdicts = [w.get(STATUS + 4 * (S_CAIJUE + i)) for i in range(6)]
    ok = hload == (before or 0) + 1 and verdicts == [1, 1, 0, 1, 1, 1]
    print(f"S_HLOAD {before} -> {hload}  verdicts={verdicts}")
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

def main():
    port = sys.argv[sys.argv.index("--port") + 1] if "--port" in sys.argv \
        else "/dev/ttyUSB0"
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 7
    try:
        import serial  # noqa: F401
    except ImportError:
        print("pyserial missing: pip install pyserial")
        return 2
    if "--prog" in sys.argv:
        return prog_mode(port)
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 24
    return data_mode(port, min(n, 64), seed)

if __name__ == "__main__":
    sys.exit(main())
