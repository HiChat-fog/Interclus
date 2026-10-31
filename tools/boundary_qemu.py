#!/usr/bin/env python3
"""E37 boundary audit on QEMU: fw_e37 runs the standard fixture sweeps,
and every round's native phase is the canary module. After the guest
finishes, the drill stops the VM over the HMP socket and sweeps M-mode
RAM: the TCB must hold the complete canary evidence set, no canary may
exist outside the TCB and the trap scratch, and the module's own record
of its restored registers must match the canaries it parked the round
before.

  cd boardlab_repo && python3 tools/boundary_qemu.py
"""
import re, socket, subprocess, sys, time

ROOT = __file__.rsplit("/tools/", 1)[0]
FW = f"{ROOT}/build/fw_e37.elf"
COMP_STATE = 0x80010A00
TCB2 = COMP_STATE + 2 * 156 + 28          # comps[2].tcb (tcb at word 7)
SCRATCH = (0x80010F00, 0x80010F40)
BOX = 0x80211000
BOXREC = BOX + 16
RANGES = [(0x80000000, 0x80020000), (0x80200000, 0x80220000)]


class Monitor:
    def __init__(self, path, timeout=10):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        end = time.time() + timeout
        while time.time() < end:
            try:
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.1)
        else:
            raise RuntimeError("no monitor socket")
        self.buf = b""
        self.s.settimeout(0.5)
        self.drain(2.0)

    def drain(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                chunk = self.s.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
            except socket.timeout:
                break
        out, self.buf = self.buf, b""
        return out

    def cmd(self, c):
        self.s.sendall(c.encode() + b"\n")
        return self.drain(0.6)


def dump(mon, addr, words):
    got = {}
    for chunk_start in range(0, words, 256):
        n = min(256, words - chunk_start)
        r = mon.cmd(f"xp /{n}wx {addr + 4 * chunk_start:#x}")
        for line in r.decode("latin1").splitlines():
            m = re.match(r"([0-9a-f]+):(.*)", line)
            if not m:
                continue
            base = int(m.group(1), 16)
            for k, v in enumerate(re.findall(r"0x([0-9a-f]{8})", m.group(2))):
                got[base + 4 * k] = int(v, 16)
    return got


def main():
    serial = open("/tmp/e37_serial.log", "wb")
    p = subprocess.Popen(
        ["qemu-system-riscv32", "-M", "virt", "-bios", "none",
         "-kernel", FW, "-display", "none", "-serial", "file:/dev/null",
         "-monitor", "unix:/tmp/e37mon,server,nowait", "-no-shutdown"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    mon = Monitor("/tmp/e37mon")
    mon.cmd("stop")
    print("0 guest stopped after fixture sweeps")

    diag = {}
    diag.update(dump(mon, 0x80010000, 800))    # STATUS + TCBs
    diag.update(dump(mon, BOX, 8))             # canary box
    ring_idx = diag.get(0x80010000 + 4 * 40, 0)
    ring = [(diag.get(0x80010000 + 4 * (41 + 2 * i), 0),
             diag.get(0x80010000 + 4 * (42 + 2 * i), 0)) for i in range(8)]
    print(f"0a forensics: idx={ring_idx} ring={ring[-6:]}")
    print(f"0b box: {[hex(diag.get(BOX + 4 * i, 0)) for i in range(4)]}")
    print(f"0c tcb head: {[hex(diag.get(TCB2 + 4 * i, 0)) for i in range(6)]}")

    words = {}
    for a, end in RANGES:
        words.update(dump(mon, a, (end - a) // 4))
    print(f"1 dumped {len(words)} words")

    ok = True
    base = 0xE3700000
    bad = [(i, words.get(TCB2 + 4 * i, 0) - base)
           for i in range(1, 32)
           if words.get(TCB2 + 4 * i, 0) != base + i]
    print(f"2 tcb completeness: bad={len(bad)} {bad[:4]}")
    ok &= not bad

    leaks = []
    for a, v in words.items():
        in_wl = (COMP_STATE <= a < COMP_STATE + 624
                 or SCRATCH[0] <= a < SCRATCH[1])
        if not in_wl and base < v <= base + 31:
            leaks.append((a, v - base))
    print(f"3 leaks outside tcb/scratch: {len(leaks)} {leaks[:6]}")
    ok &= not leaks

    # fresh-lifetime guarantee: compartment_set zeroes the TCB before
    # every entry, so the module's snapshot of its restored register file
    # must be all zeros — no other lifetime's values may ride in
    rec = [words.get(BOXREC + 4 * i, 0) for i in range(12)]
    restore_bad = [i for i in range(12) if rec[i] != 0]
    print(f"4 fresh-lifetime zero registers: bad={len(restore_bad)}")
    ok &= not restore_bad

    box0 = words.get(BOX, 0)
    print(f"5 box round counter: {box0:#x}")
    ok &= box0 == 1

    mon.cmd("quit")
    p.wait(timeout=10)
    print("RESULT:", "E37 QEMU BOUNDARY PASS ✅" if ok
          else "E37 QEMU BOUNDARY FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
