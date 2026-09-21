import struct, subprocess, time, re, sys, random
W = "wlink"
YOUXIANG = 0x20002000
MO_SHU = 0x5741524D
S_BAN_CAIJUE = 0x20000200
S_CHONGTU_N = 0x20000250
S_LAIYUAN   = 0x20000254
S_JINGBAO = 0x2000024C
def wlink(*args, timeout=60):
    return subprocess.run([W, *args], capture_output=True, text=True, timeout=timeout)
def zuo_gpi(lat, lon, seq):
    hdr = bytes([0xFD, 30, 0, 0, seq & 0xFF, 2, 3, 0x21, 0, 0])
    payload = struct.pack("<7iH", lat, lon, 50000, 100, 0, 0, 0, 0xFFFF)
    return hdr + payload + b"\xAB\xCD"
def gezi_hao(lat, lon):
    return ((lat >> 26) & 7) * 8 + ((lon >> 26) & 7)
def jingxiang(gezi):
    m = [0] * 64
    out = []
    for c in gezi:
        m[c] += 1
        left = m[(c - 1) & 63]
        right = m[(c + 1) & 63]
        out.append(5 if (m[c] > 3 or left > 3 or right > 3) else 1)
    return out
def du_zi(addr, n):
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
    rezhu = [(20, 20), (60, 70), (80, 30)]
    wurenji = []
    for i in range(N):
        if i < N * 2 // 3:
            hx, hy = rezhu[i % 3]
            x = min(99, max(0, hx + rng.randint(-3, 3)))
            y = min(99, max(0, hy + rng.randint(-3, 3)))
        else:
            x, y = rng.randint(0, 99), rng.randint(0, 99)
        wurenji.append((x, y))
    bao, gezi = [], []
    for i, (x, y) in enumerate(wurenji):
        lat, lon = x * 10_000_000, y * 10_000_000
        bao.append(zuo_gpi(lat, lon, i))
        gezi.append(gezi_hao(lat, lon))
    qiwang = jingxiang(gezi)
    alerts = sum(1 for e in qiwang if e == 5)
    kuai = struct.pack("<II", MO_SHU, N) + b"".join(bao)
    CHUNK = 2048
    for i in range(0, len(kuai), CHUNK):
        chunk = kuai[i:i + CHUNK]
        open("swarm_chunk.bin", "wb").write(chunk)
        wlink("flash", "-a", hex(YOUXIANG + i), "swarm_chunk.bin")
    for round_ in range(3):
        cur = du_zi(YOUXIANG, (len(kuai) + 3) // 4)
        bad = [(YOUXIANG + k * 4, v) for k, v in enumerate(cur)
               if k * 4 + 4 <= len(kuai) and v != struct.unpack_from("<I", kuai, k * 4)[0]]
        tail = len(kuai) - (len(kuai) // 4) * 4
        if bad:
            for addr, _ in bad:
                off = addr - YOUXIANG
                wlink("write-mem", hex(addr),
                      hex(struct.unpack_from("<I", kuai, off)[0]))
            wlink("reset")
            time.sleep(1)
        else:
            break
    wlink("reset")
    time.sleep(2)
    w = du_zi(S_BAN_CAIJUE, 8)
    w.update(du_zi(0x20000240, 6))
    confn, src, alertn = w[S_CHONGTU_N], w[S_LAIYUAN], w[S_JINGBAO]
    got = [w.get(S_BAN_CAIJUE + 4 * i) for i in range(8)]
    ok = (confn == N) and (alertn == alerts) and (got == qiwang[:8])
    print(f"swarm N={N} (seed={seed})  host alerts={alerts}  board alerts={alertn}")
    print(f"board first-8 verdicts: {got}")
    print(f"host first-8 verdicts: {qiwang[:8]}")
    print("RESULT:", "MATCH ✅" if ok else "MISMATCH ❌")
    return 0 if ok else 1
if __name__ == "__main__":
    sys.exit(main())
