#!/usr/bin/env python3
"""Console frame builders plus the boot-time emitter. Frame: sync(7E 7E),
type(1), len16 LE, payload, sum8 — the checksum byte brings the sum of
type..payload to zero. Frame types: 1 = eBPF program (PROG layout, the
boot window takes exactly one), 2 = mailbox image (runtime data frame),
3 = native PEND image (runtime module install). The default emission
mirrors modules/examples/pass_all.c; --corrupt flips one payload byte so
the receiver must reject the frame."""
import struct, sys

def enc(op, d, s, o, i):
    return ((op & 0xFF) | (((d & 0xF) | ((s & 0xF) << 4)) << 8)
            | ((o & 0xFFFF) << 16) | ((i & 0xFFFFFFFF) << 32))

PASS_ALL = [
    enc(0x71, 0, 1, 0, 0),          # r0 = ctx[0] (start byte)
    enc(0xB7, 1, 0, 0, 0xFD),       # r1 = 0xFD
    enc(0x1D, 0, 1, 2, 0),          # equal -> skip the reject path
    enc(0xB7, 0, 0, 0, 0),          # reject: r0 = 0
    enc(0x95, 0, 0, 0, 0),          # exit
    enc(0xB7, 0, 0, 0, 1),          # accept: r0 = 1
    enc(0x95, 0, 0, 0, 0),          # exit
]

def frame(ftype, payload):
    body = bytes([ftype]) + struct.pack("<H", len(payload)) + payload
    return b"\x7E\x7E" + body + bytes([(-sum(body)) & 0xFF])

def prog_payload(insns=PASS_ALL):
    return (struct.pack("<II", 0x474F5250, len(insns))
            + b"".join(struct.pack("<Q", e) for e in insns))

def main():
    payload = prog_payload()
    if "--corrupt" in sys.argv:
        payload = payload[:16] + bytes([payload[16] ^ 0xFF]) + payload[17:]
    sys.stdout.buffer.write(frame(1, payload))

if __name__ == "__main__":
    main()
