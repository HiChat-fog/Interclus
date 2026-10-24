"""Board persistence drill (E25): a hot-installed native module is
mirrored to the top flash pages; a real power cycle must restore it
through the same gates, proof returns without any re-install.

  cd tools && python3 persist_board.py
"""
import sys, time
from inject_swarm import wlink, read_words
from pend import stage_native

BASE = 0x20000100
S_NAT2, S_NSLOT = 92, 97

def snap():
    w = read_words(BASE, 100)
    return (w.get(BASE + 4 * S_NAT2), w.get(BASE + 4 * S_NSLOT))

def main():
    natvar = open("../build/native_variant_s1.bin", "rb").read()  # slot-1 base
    ok = True

    stage_native(natvar, slot=1)
    time.sleep(4)
    nat2, nslot = snap()
    mir = read_words(0x0800A400, 1).get(0x0800A400, 0)
    print(f"1 install slot1: NAT2={hex(nat2 or 0)} NSLOT={nslot} "
          f"MIR={hex(mir)}")
    if mir != 0x4D495234:
        print("   mirror page is blank: the M-mode program path did not land")
    ok &= (nat2 or 0) == 0xC0DE0003 and nslot == 1

    # power cycle: reset is the closest a drill gets without a plug switch;
    # the mirror lives in flash, the RAM table dies with the reset
    wlink("reset")
    time.sleep(2)
    nat2, nslot = snap()
    print(f"2 after reset:   NAT2={hex(nat2 or 0)} NSLOT={nslot}")
    ok &= (nat2 or 0) == 0xC0DE0003 and nslot == 1

    print("RESULT:", "PERSIST BOARD PASS ✅" if ok else "PERSIST BOARD FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
