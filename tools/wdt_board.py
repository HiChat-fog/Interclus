"""E31 board drill: a signed but slow program (legal self-loop) makes the
monitor compartment overrun its time budget; the timer kills it, the
fail-stop marker lands, nobody feeds the dog, and the IWDG reboots the
device into a clean measured boot with the evidence words intact.

  cd tools && python3 wdt_board.py
"""
import sys, time
from inject_swarm import wlink, read_words
from pend import stage_ebpf, PROG_PEND

BASE = 0x20000100
S_DONE, S_GATE, S_HLOAD = 56, 88, 93
S_HALT, S_HALTC = 102, 103
HALT_MAGIC = 0x48414C54

def snap():
    w = read_words(BASE, S_HALTC + 1)
    return {k: (w.get(BASE + 4 * k) or 0) for k in
            (S_DONE, S_GATE, S_HLOAD, S_HALT, S_HALTC)}


def wait_for(pred, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = snap()
        if pred(s):
            return s, time.time() - t0
        time.sleep(0.05)
    return snap(), time.time() - t0


def fresh_boot(timeout=12):
    wlink("write-mem", hex(PROG_PEND), "0x0")
    wlink("write-mem", hex(PROG_PEND + 0x240), "0x0")
    wlink("write-mem", hex(BASE + 4 * S_DONE), "0xFFFFFFFF")
    wlink("write-mem", hex(BASE + 4 * S_HLOAD), "0xFFFFFFFF")
    wlink("reset")
    s, _ = wait_for(lambda s: s[S_DONE] == 0x600DF00D and
                    s[S_HLOAD] == 0 and s[S_GATE] == 0xC0DE0000, timeout)
    return s


def main():
    ok = True

    s = fresh_boot()
    print(f"0 boot: GATE={s[S_GATE]:#x} DONE={s[S_DONE]:#x} "
          f"HALT={s[S_HALT]:#x}")
    ok &= s[S_GATE] == 0xC0DE0000 and s[S_DONE] == 0x600DF00D
    wlink("write-mem", hex(BASE + 4 * S_HALT), "0x0")
    wlink("write-mem", hex(BASE + 4 * S_HALTC), "0x0")
    wlink("write-mem", hex(BASE + 4 * S_DONE), "0xFFFFFFFF")

    stage_ebpf([0x05 | ((-1 & 0xFFFF) << 16)])
    s, dt = wait_for(lambda s: s[S_HALT] == HALT_MAGIC, 6)
    print(f"1 slowspin killed, fail-stop: HALT={s[S_HALT]:#x} "
          f"HALTC={s[S_HALTC]:#x} in {dt:.2f}s")
    ok &= s[S_HALT] == HALT_MAGIC and s[S_HALTC] == 0x0100000C

    s, dt = wait_for(lambda s: s[S_DONE] == 0x600DF00D, 15)
    print(f"2 watchdog reboot: DONE={s[S_DONE]:#x} GATE={s[S_GATE]:#x} "
          f"HLOAD={s[S_HLOAD]} in {dt:.2f}s")
    ok &= s[S_DONE] == 0x600DF00D and s[S_GATE] == 0xC0DE0000
    ok &= s[S_HLOAD] == 0 and 2.0 < dt < 15.0
    ok &= s[S_HALT] == HALT_MAGIC and s[S_HALTC] == 0x0100000C
    w = read_words(BASE + 4 * 16, 6)
    v = [w.get(BASE + 4 * (16 + i), 0) for i in range(6)]
    print(f"3 recovered: verdicts={v}")
    ok &= v == [1, 1, 0, 2, 3, 4]

    print("RESULT:", "WDT BOARD PASS ✅" if ok else "WDT BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
