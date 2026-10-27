"""Stage a signed PEND image: header, payload, SHA-256 trailer, magic last.
The digest must be pinned in modules/trusted_digests.h (E26). Words are
written with a verify-fix loop: this link delays or drops single writes,
and a word landing after the magic makes the gate hash half-written
bytes."""
import hashlib, struct
from inject_swarm import wlink, read_words

PROG_PEND = 0x20003800
MAGIC = 0x444E4550


def _write_words(base, data):
    data = data + b"\0" * (-len(data) % 4)
    full = {base + i: struct.unpack_from("<I", data, i)[0]
            for i in range(0, len(data), 4)}
    bad = full
    for _ in range(4):
        for a, w in bad.items():
            wlink("write-mem", hex(a), hex(w))
        cur = read_words(base, len(full))
        bad = {a: w for a, w in full.items() if cur.get(a) != w}
        if not bad:
            return
    raise RuntimeError(f"stage verify failed at {base:#x}")


def _stage(body):
    wlink("write-mem", hex(PROG_PEND + 0x208), "0x0")
    _write_words(PROG_PEND, body + hashlib.sha256(body).digest())
    wlink("write-mem", hex(PROG_PEND + 0x208), hex(MAGIC))


def stage_ebpf(insns):
    _stage(struct.pack("<II", len(insns), 1) +
           b"".join(struct.pack("<Q", e) for e in insns))


def stage_native(code, entry=0, slot=0):
    _stage(struct.pack("<IIII", len(code), 2, entry, slot) + code)
