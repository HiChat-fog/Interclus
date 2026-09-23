import struct, subprocess, time, re, sys, random
W = "wlink"
MAILBOX = 0x20002000
MAILBOX_MAGIC = 0x5741524D
S_SCREEN = 0x20000200
S_COUNT = 0x20000250
S_SOURCE = 0x20000254
S_ALERTS = 0x2000024C
def wlink(*args, timeout=60):
    return subprocess.run([W, *args], capture_output=True, text=True, timeout=timeout)
def make_gpi(lat, lon, seq):
    hdr = bytes([0xFD, 30, 0, 0, seq & 0xFF, 2, 3, 0x21, 0, 0])
    payload = struct.pack("<7iH", lat, lon, 50000, 100, 0, 0, 0, 0xFFFF)
    return hdr + payload + b"\xAB\xCD"
def grid_cell(lat, lon):
    return ((lat >> 26) & 7) * 8 + ((lon >> 26) & 7)
def mirror(cells):
    m = [0] * 64
    out = []
    for c in cells:
        m[c] += 1
        left = m[(c - 1) & 63]
        right = m[(c + 1) & 63]
        out.append(5 if (m[c] > 3 or left > 3 or right > 3) else 1)
    return out
def read_words(addr, n):
    out = wlink("dump", hex(addr), str(n * 4), "-q").stdout
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    words = {}
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]{8}):\s+((?:[0-9a-fA-F]{2}\s+)+)", line)
        if m:
            base = int(m.group(1), 16)
            b = bytes.fromhex(m.group(2).replace(" ", ""))
            for k in range(len(b) // 4):
                words[base + 4 * k] = struct.unpack("<I", b[4 * k:4 * k + 4])[0]
    return words
def main():
    N = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 32
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 7
    N = min(N, 64)
    rng = random.Random(seed)
    hotspots = [(20, 20), (60, 70), (80, 30)]
    drones = []
    for i in range(N):
        if i < N * 2 // 3:
            hx, hy = hotspots[i % 3]
            x = min(99, max(0, hx + rng.randint(-3, 3)))
            y = min(99, max(0, hy + rng.randint(-3, 3)))
        else:
            x, y = rng.randint(0, 99), rng.randint(0, 99)
        drones.append((x, y))
    pkts, cells = [], []
    for i, (x, y) in enumerate(drones):
        lat, lon = x * 10_000_000, y * 10_000_000
        pkts.append(make_gpi(lat, lon, i))
        cells.append(grid_cell(lat, lon))
    expected = mirror(cells)
    alerts = sum(1 for e in expected if e == 5)
    blob = struct.pack("<II", MAILBOX_MAGIC, N) + b"".join(pkts)
    CHUNK = 2048
    for i in range(0, len(blob), CHUNK):
        chunk = blob[i:i + CHUNK]
        open("swarm_chunk.bin", "wb").write(chunk)
        wlink("flash", "-a", hex(MAILBOX + i), "swarm_chunk.bin")
    for round_ in range(3):
        cur = read_words(MAILBOX, (len(blob) + 3) // 4)
        bad = [(MAILBOX + k * 4, v) for k, v in enumerate(cur)
               if k * 4 + 4 <= len(blob) and v != struct.unpack_from("<I", blob, k * 4)[0]]
        tail = len(blob) - (len(blob) // 4) * 4
        if bad:
            for addr, _ in bad:
                off = addr - MAILBOX
                wlink("write-mem", hex(addr),
                      hex(struct.unpack_from("<I", blob, off)[0]))
            wlink("reset")
            time.sleep(1)
        else:
            break
    wlink("reset")
    time.sleep(2)
    w = read_words(S_SCREEN, 8)
    w.update(read_words(0x20000240, 6))
    confn, src, alertn = w[S_COUNT], w[S_SOURCE], w[S_ALERTS]
    got = [w.get(S_SCREEN + 4 * i) for i in range(8)]
    ok = (confn == N) and (alertn == alerts) and (got == expected[:8])
    print(f"swarm N={N} (seed={seed})  host alerts={alerts}  board alerts={alertn}")
    print(f"board first-8 verdicts: {got}")
    print(f"host first-8 verdicts: {expected[:8]}")
    print("RESULT:", "MATCH ✅" if ok else "MISMATCH ❌")
    return 0 if ok else 1
if __name__ == "__main__":
    sys.exit(main())
