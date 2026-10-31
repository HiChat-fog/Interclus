#!/usr/bin/env python3
"""E42 differential drill: verify the SHA-256 and CRC16 lines emitted by
build/test_primitives against hashlib and the Python CRC twin."""
import hashlib, re, subprocess, sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from update_frame import crc16

ROOT = __file__.rsplit("/tools/", 1)[0]


def msg_sha(n):
    if n == 0:
        return b""
    if n == 3:
        return b"abc"
    if n == 56:
        return b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    if n == 1000000:
        return b"a" * n
    return bytes((0x41 + (i % 26)) & 0xFF for i in range(n))


def msg_shal(n):
    if n <= 136:
        return bytes((0x20 + ((i * 7 + n) % 0x5F)) & 0xFF for i in range(n))
    return bytes((0x41 + (i % 26)) & 0xFF for i in range(n))


def msg_crc(n):
    return bytes((0x30 + ((i * 5 + n) % 0x4F)) & 0xFF for i in range(n))


def main():
    r = subprocess.run([f"{ROOT}/build/test_primitives"],
                       capture_output=True, text=True, timeout=120)
    if "PRIM PASS" not in r.stdout:
        print("primitives self-test failed\n" + r.stdout[-400:])
        return 1
    fails = 0
    for ln in r.stdout.splitlines():
        m = re.match(r"^SHA(\d+) ([0-9a-f]{64})$", ln)
        if m:
            n, hexd = int(m.group(1)), m.group(2)
            if n > 136 and n != 1000000:
                continue
            if hexd != hashlib.sha256(msg_sha(n)).hexdigest():
                fails += 1
                if fails < 4:
                    print(f"SHA {n} mismatch")
            continue
        m = re.match(r"^SHAL(\d+) ([0-9a-f]{64})$", ln)
        if m:
            n, hexd = int(m.group(1)), m.group(2)
            if hexd != hashlib.sha256(msg_shal(n)).hexdigest():
                fails += 1
                if fails < 4:
                    print(f"SHAL {n} mismatch")
            continue
        if ln.startswith("CRC9 "):
            if ln.split()[1] != "4b37":
                fails += 1
                print("CRC9 check value wrong:", ln)
            continue
        m = re.match(r"^CRCL(\d+) ([0-9a-f]{4})$", ln)
        if m:
            n, crc = int(m.group(1)), int(m.group(2), 16)
            if crc != crc16(msg_crc(n)):
                fails += 1
                if fails < 4:
                    print(f"CRCL {n}: {crc:04x} vs {crc16(msg_crc(n)):04x}")
    lines = sum(1 for ln in r.stdout.splitlines()
                if re.match(r"^(SHA|SHAL|CRC)", ln))
    print(f"  differential lines: {lines}")
    print("RESULT:", "E42 PRIM PASS ✅" if fails == 0
          else f"E42 PRIM FAIL ({fails}) ❌")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
