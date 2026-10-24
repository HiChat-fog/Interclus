"""E28 board drill: a signed native module that never yields must be
killed by the time budget, evicted like a faulting one, and the schedule
must remap to the other slot.

  cd tools && python3 budget_board.py
"""
import sys, time
from inject_swarm import wlink, read_words
from pend import stage_native, PROG_PEND

BASE = 0x20000100
S_DONE, S_GATE, S_NAT2 = 56, 88, 92
S_HLOAD, S_ROLL, S_NSLOT, S_PREEMPT = 93, 95, 97, 100
S_TXABORT = 101

def snap():
    w = read_words(BASE, S_TXABORT + 1)
    return {k: (w.get(BASE + 4 * k) or 0) for k in
            (S_DONE, S_GATE, S_NAT2, S_HLOAD, S_ROLL, S_NSLOT, S_PREEMPT)}


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
    wlink("write-mem", hex(PROG_PEND + 0x208), "0x0")
    wlink("write-mem", hex(BASE + 4 * S_DONE), "0xFFFFFFFF")
    wlink("write-mem", hex(BASE + 4 * S_HLOAD), "0xFFFFFFFF")
    wlink("reset")
    s, _ = wait_for(lambda s: s[S_DONE] == 0x600DF00D and
                    s[S_HLOAD] == 0 and s[S_GATE] == 0xC0DE0000, timeout)
    t1 = read_words(BASE + 12, 1).get(BASE + 12, 0)
    t2 = t1
    deadline = time.time() + 3
    while t2 == t1 and time.time() < deadline:
        time.sleep(0.2)
        t2 = read_words(BASE + 12, 1).get(BASE + 12, 0)
    return s


def main():
    spin = open("../build/native_spin_s1.bin", "rb").read()
    ok = True

    s = fresh_boot()
    print(f"0 boot: GATE={s[S_GATE]:#x} DONE={s[S_DONE]:#x} "
          f"ROLL={s[S_ROLL]} HLOAD={s[S_HLOAD]}")
    ok &= s[S_GATE] == 0xC0DE0000 and s[S_DONE] == 0x600DF00D
    base_roll, base_pre = s[S_ROLL], s[S_PREEMPT]

    stage_native(spin, slot=1)
    s, dt = wait_for(lambda s: s[S_PREEMPT] > base_pre, 5)
    print(f"1 spin killed: PREEMPT={s[S_PREEMPT]} NAT2={s[S_NAT2]:#x} "
          f"ROLL={s[S_ROLL]} NSLOT={s[S_NSLOT]} in {dt:.2f}s")
    ok &= s[S_PREEMPT] == base_pre + 1 and dt < 5.0
    ok &= s[S_ROLL] == base_roll + 1 and s[S_NSLOT] == 0

    wlink("reset")
    print("RESULT:", "BUDGET BOARD PASS ✅" if ok else "BUDGET BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
