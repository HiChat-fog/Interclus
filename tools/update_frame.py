#!/usr/bin/env python3
"""Reliable update transport helpers. The image is the exact PEND body:
header + payload + pinned SHA-256 trailer. Frames use stop-and-wait
sequence numbers; the device ACK reports the next expected chunk."""
import hashlib, struct

BEGIN, DATA, COMMIT, ABORT = 1, 2, 3, 4
ACK, NACK, STAGED, ACCEPT, REJECT = 0x80, 0x81, 0x82, 0x83, 0x84


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc >> 1) ^ 0xA001) if crc & 1 else crc >> 1
    return crc


def _crc(body):
    c = crc16(body)
    return body + struct.pack("<H", c)


def begin(tid, image):
    return _crc(bytes([BEGIN]) + struct.pack("<IH", tid, len(image)) +
                hashlib.sha256(image).digest())


def chunks(tid, image, size=64):
    for seq, off in enumerate(range(0, len(image), size)):
        data = image[off:off + size]
        yield _crc(bytes([DATA]) + struct.pack("<IHHB", tid, seq, off,
                                                len(data)) + data)


def commit(tid):
    return _crc(bytes([COMMIT]) + struct.pack("<I", tid))


def abort(tid):
    return _crc(bytes([ABORT]) + struct.pack("<I", tid))


def pass_all_image(pass_all):
    body = struct.pack("<II", len(pass_all), 1)
    body += b"".join(struct.pack("<Q", x) for x in pass_all)
    return body + hashlib.sha256(body).digest()


def iter_chunks(tid, image, size=64):
    """Yield bounded chunks and enforce the wire's stop-and-wait shape."""
    if not image or len(image) > 480 or not 1 <= size <= 64:
        raise ValueError("image/chunk size outside update limits")
    yield from chunks(tid, image, size)


def decode_reply(payload):
    """Decode [code,id,next_seq,detail,crc16] and reject bad replies."""
    if len(payload) != 10 or crc16(payload[:-2]) != struct.unpack_from("<H", payload, 8)[0]:
        return None
    return struct.unpack("<BIHB", payload[:8])
