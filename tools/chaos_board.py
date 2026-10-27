"""E33 board drill: the PMP boundary under random fire. The pinned chaos
module derives a probe address from a seed staged in its SRAM window —
odd steps stay inside (legal), even steps hit a uniform address in the
RAM or flash map. Every lifetime must end contained: evicted (a probe
outside the windows trapped) or clean (all probes landed inside, proof
word 0xC0DE00C5). Anything else — a hang, a reboot, corrupted state —
is the failure this drill hunts.

  cd tools && python3 chaos_board.py [rounds]
"""
import sys, time
from inject_swarm import wlink, read_words
from pend import stage_native, PROG_PEND

BASE = 0x20000100
S_DONE, S_GATE, S_NAT2 = 56, 88, 92
S_HLOAD, S_ROLL, S_NSLOT, S_HALT = 93, 95, 97, 102
CHAOS_SRAM = 0x2000D000
CHAOS_PROOF = 0xC0DE00C5

def wr32(addr, val):
    wlink("write-mem", hex(addr), hex(val & 0xFFFFFFFF))

def st_word(i):
    return read_words(BASE + 4 * i, 1).get(BASE + 4 * i, 0) or 0

def fresh_boot(timeout=12):
    wr32(0x20001000, 0)
    wlink("write-mem", hex(PROG_PEND), "0x0")
    wlink("write-mem", hex(PROG_PEND + 0x208), "0x0")
    wr32(BASE + 4 * S_DONE, 0xFFFFFFFF)
    wr32(BASE + 4 * S_HLOAD, 0xFFFFFFFF)
    wlink("reset")
    t0 = time.time()
    while time.time() - t0 < timeout:
        if (st_word(S_DONE) == 0x600DF00D and
                st_word(S_HLOAD) == 0 and st_word(S_GATE) == 0xC0DE0000):
            return True
        time.sleep(0.1)
    return False


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 48
    chaos = open("../build/native_chaos_s1.bin", "rb").read()
    ok = fresh_boot()
    print(f"0 boot: {'ok' if ok else 'TIMEOUT'} "
          f"fuzz acc/rej = {st_word(104)}/{st_word(105)}")
    ok &= (st_word(104) + st_word(105)) == 2048
    ok &= st_word(104) < 2048 // 4        # random junk passes rarely

    wr32(BASE + 4 * S_HALT, 0)
    base_roll = st_word(S_ROLL)
    evicted = clean = 0
    for k in range(rounds):
        wr32(CHAOS_SRAM, 0x9E3779B1 * (k + 1) & 0xFFFFFFFF)
        outcome = None
        # a word can land after the magic: a reject with no promotion is
        # transport jitter, not a gate verdict — restage and try again
        for attempt in range(3):
            base_load, base_hrej = st_word(S_HLOAD), st_word(94)
            stage_native(chaos, slot=1)
            t0 = time.time()
            while time.time() - t0 < 6:
                if st_word(S_HLOAD) == base_load + 1:
                    roll, nat2 = st_word(S_ROLL), st_word(S_NAT2)
                    if roll > base_roll:
                        outcome = "evicted"
                        base_roll = roll
                        break
                    if nat2 == CHAOS_PROOF:
                        outcome = "clean"
                        break
                if st_word(94) > base_hrej:
                    break               # rejected: restage below
                time.sleep(0.05)
            if outcome:
                break
        if outcome == "evicted":
            evicted += 1
        elif outcome == "clean":
            clean += 1
        else:
            print(f"  round {k}: NO OUTCOME (HLOAD={st_word(S_HLOAD)} "
                  f"ROLL={st_word(S_ROLL)} NAT2={st_word(S_NAT2):#x} "
                  f"HALT={st_word(S_HALT):#x})")
            ok = False
            break
        if st_word(S_HALT) != 0 or st_word(S_GATE) != 0xC0DE0000:
            print(f"  round {k}: state corrupted HALT={st_word(S_HALT):#x}")
            ok = False
            break

    print(f"1 chaos: {rounds} seeds -> evicted={evicted} clean={clean}")
    ok &= (evicted + clean) == rounds and evicted > 0

    wlink("reset")
    print("RESULT:", "CHAOS BOARD PASS ✅" if ok else "CHAOS BOARD FAIL ❌")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
