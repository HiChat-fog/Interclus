"""E30 board drill: clear TE so the transmitter never drains again (TXE
stays 0 after one write), then make a native module fault. The telemetry
send must abandon within its tick budget (S_TXABORT) and the eviction must
still complete (S_ROLL). The service loop then parks in its own blocking
verdict print, as designed; restoring TE releases it.

  cd tools && python3 stall_board.py
"""
import sys, time
from inject_swarm import wlink, read_words
from pend import stage_native, PROG_PEND

BASE = 0x20000100
USART1_CTLR1 = 0x4001380C
TE_ON, TE_OFF = 0x200C, 0x2004
S_DONE, S_GATE, S_NAT2 = 56, 88, 92
S_HLOAD, S_ROLL, S_NSLOT, S_PREEMPT, S_TXABORT = 93, 95, 97, 100, 101
S_WORDS = S_TXABORT + 1

def snap():
    w = read_words(BASE, S_WORDS)
    return {k: (w.get(BASE + 4 * k) or 0) for k in
            (S_DONE, S_GATE, S_NAT2, S_HLOAD, S_ROLL, S_NSLOT, S_PREEMPT,
             S_TXABORT)}


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
    s, dt = wait_for(lambda s: s[S_DONE] == 0x600DF00D and
                     s[S_HLOAD] == 0 and s[S_GATE] == 0xC0DE0000, timeout)
    # DONE is set before the verdict print; STATUS[3] moving means the
    # service loop has taken over and the console is idle again
    t1 = read_words(BASE + 12, 1).get(BASE + 12, 0)
    t2 = t1
    deadline = time.time() + 3
    while t2 == t1 and time.time() < deadline:
        time.sleep(0.2)
        t2 = read_words(BASE + 12, 1).get(BASE + 12, 0)
    return s


def main():
    trap = open("../build/native_trap_s1.bin", "rb").read()
    ok = True

    s = fresh_boot()
    print(f"0 boot: GATE={s[S_GATE]:#x} DONE={s[S_DONE]:#x} "
          f"ROLL={s[S_ROLL]} HLOAD={s[S_HLOAD]}")
    ok &= s[S_GATE] == 0xC0DE0000 and s[S_DONE] == 0x600DF00D
    base_roll, base_abort = s[S_ROLL], s[S_TXABORT]

    wlink("write-mem", hex(USART1_CTLR1), hex(TE_OFF))
    print(f"1 TE off: CTLR1={read_words(USART1_CTLR1, 1).get(USART1_CTLR1, 0):#x}")

    stage_native(trap, slot=1)
    s, dt = wait_for(lambda s: s[S_TXABORT] > base_abort, 5)
    print(f"2 fault with TX dead: TXABORT={s[S_TXABORT]} "
          f"ROLL={s[S_ROLL]} NSLOT={s[S_NSLOT]} PREEMPT={s[S_PREEMPT]} "
          f"in {dt:.2f}s")
    ok &= s[S_TXABORT] == base_abort + 1 and s[S_ROLL] == base_roll + 1
    ok &= s[S_NSLOT] == 0 and s[S_PREEMPT] == 0 and dt < 2.0

    wlink("write-mem", hex(USART1_CTLR1), hex(TE_ON))
    time.sleep(1.0)
    a = read_words(BASE + 12, 1).get(BASE + 12, 0)
    time.sleep(0.5)
    b = read_words(BASE + 12, 1).get(BASE + 12, 0)
    print(f"3 TE restored, service loop: {a} -> {b}")
    ok &= b != a

    wlink("reset")
    print("RESULT:", "STALL BOARD PASS ✅" if ok else "STALL BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
