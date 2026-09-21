# pmp-ebpf-demo

[![ci](https://github.com/HiChat-fog/pmp-ebpf-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/HiChat-fog/pmp-ebpf-demo/actions/workflows/ci.yml)

eBPF interpreter running unprivileged inside RISC-V PMP compartments on a
CH32V307 (RV32IMAFC). Supervisor (M-mode) arms PMP, schedules compartments,
and recovers after faults: every faulting access is logged with `mcause` and
`mtval`, then skipped or redirected, and the monitor keeps running.

Things you can learn from this repo:

- PMP compartmentalization on a real MCU: NAPOT regions, deny-all filler,
  measured vendor quirks (only 4 usable entries, unmatched-allow, mtvec traps)
- an eBPF subset interpreter with full 64-bit semantics on a 32-bit core
- an adversarial probe that attacks the isolation and gets caught, with
  address-precise forensics

## Layout

- `ebpf/` - eBPF subset interpreter, policies, host tests
- `pmp/` - supervisor, monitor, attacker probe, trap handler, linker script, PMP semantics probe
- `tools/inject_swarm.py` - swarm injection + host-side mirror check
- `reference/fw_pmp.bin` - firmware image used for recorded results
- `build.sh` - build everything

## Build

    ./build.sh

Output: `build/fw_pmp.bin`, `build/pmp_probe.bin`

## Run in QEMU (no hardware)

    clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax \
          -msmall-data-limit=0 -ffreestanding -O2 -c qemu/smoke.c -o qemu/smoke.o
    ld.lld -flavor gnu -T qemu/smoke.ld -nostdlib -o qemu/smoke.elf qemu/smoke.o
    qemu-system-riscv32 -M virt -bios none -kernel qemu/smoke.elf -nographic

Expected output:

    qemu-pmp-smoke
    faults=1 mtval=80102000
    SMOKE PASS

Same architecture as the board firmware: a U-mode worker boxed by PMP, an
OOB write caught by the deny-all entry, a trap handler that logs `mtval` and
skips the faulting store, then a yield back to M-mode.

## PMP semantics probe

    wlink flash -e build/pmp_probe.bin

Results land in SRAM: CSR read-backs and fault log at 0x20000100, U-mode markers at 0x20001000 (`wlink dump 0x20000100 400`). The last stage ends hung by design (misaligned-mtvec trap test); reflash `build/fw_pmp.bin` afterwards.

## Host tests

    cd ebpf
    gcc -fsanitize=address,undefined -I. test_host.c ebpf_mini.c helpers_rv32.c -o t
    ./t

19 test cases must pass.

## Run on board

Hardware: CH32V307VCT6 board + WCH-LinkE debugger. Flash with wlink, then:

    wlink flash -e build/fw_pmp.bin
    python3 tools/inject_swarm.py 32 --seed 7

Expected output:

    swarm N=32 (seed=7)  host alerts=4  board alerts=4
    RESULT: MATCH ✅

Try other sizes (8 to 64, the full mailbox capacity) and seeds.

## Toolchain

clang 18 (riscv32), rust-lld or lld, riscv64-unknown-elf-objcopy, wlink

## Roadmap

- full pipeline under QEMU (swarm in -> screening -> forensics out), CI without hardware
- UART data path to replace the debugger mailbox
- more example policies

## License

MIT
