#!/usr/bin/env python3
"""E36 board run: flash the standalone containment-audit firmware, wait
for the result block, and report. The board audit covers the two
RAM-backed native slots (the flash-backed monitor/attacker text windows
cannot host the injected probe — that half is QEMU-only).

  cd tools && python3 pmpa_board.py
"""
import subprocess, sys, time
from inject_swarm import read_words

RES = 0x20003400
DONE = 0xE36D0001
PAGES = 1048576


def wlink(*args):
    return subprocess.run(["wlink", *args], capture_output=True, text=True,
                          timeout=120)


def main():
    print("0 flash")
    r = wlink("flash", "-e", "../build/fw_pmpab.bin")
    if "Flash done" not in r.stdout:
        print("   flash failed:", r.stdout[-200:], r.stderr[-200:])
        return 1
    wlink("reset")
    # the result block is RAM and survives reset: clear the magic or the
    # poll instantly reads the previous run's stale verdict
    wlink("write-mem", hex(RES), "0x0")
    print("1 sweep running (full 4 GiB x load/store/fetch x 2 configs)")
    end = time.time() + 600
    while time.time() < end:
        w = read_words(RES, 1).get(RES, 0)
        if w == DONE:
            break
        time.sleep(2)
    else:
        print("2 TIMEOUT: no result block")
        return 1
    w = read_words(RES, 2 + 12)
    lemma = w.get(RES + 4, 0)
    cfgw = w.get(RES + 44, 0)
    print(f"2 done: lemma={lemma} cfgw={cfgw:#010x}")
    ok = lemma == 0
    for c in range(2):
        base = RES + 8 + c * 16
        mism = w.get(base, -1)
        pages = w.get(base + 4, -1)
        page = w.get(base + 8, -1)
        kind = w.get(base + 12, -1)
        print(f"   cfg{c}: mism={mism} pages={pages} first={page:#x}/{kind}")
        ok &= mism == 0 and pages == PAGES
    print("RESULT:", "E36 BOARD PASS ✅" if ok else "E36 BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
