import sys, time
from inject_swarm import wlink, read_words

RES = 0x20001900   # .meas_res island on the board (qemu: 0x80010D00)
NAMES = [
    "cyc_overhead", "pmp_arm_full_0", "pmp_arm_skip_0",
    "pmp_arm_full_1", "pmp_arm_skip_1",
    "check_n8", "check_n16", "check_n32", "check_n64",
    "slice_same", "slice_cross", "slice_evict",
    "sanity_rdcycle50k", "sanity_mcycle50k", "sanity_stk50k",
]

def main():
    wlink("reset")
    time.sleep(2)
    w = read_words(RES, len(NAMES))
    missing = [n for i, n in enumerate(NAMES) if RES + 4 * i not in w]
    if missing:
        print("missing words:", missing)
        return 1
    for i, n in enumerate(NAMES):
        print(f"{n}={w[RES + 4 * i]}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
