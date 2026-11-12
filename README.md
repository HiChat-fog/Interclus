# Interclus

[![ci](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml/badge.svg)](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

English | [简体中文](README.zh-CN.md)

> *An eBPF interpreter enclosed by RISC-V PMP.*

An eBPF interpreter running unprivileged inside RISC-V PMP compartments on a
CH32V307 (RV32IMAFC, no MMU). A machine-mode supervisor arms boundaries,
schedules compartments, and turns a compartment's first illegal access into
evidence: `mcause` and `mtval` into the forensics ring, the register frame
into the TCB, then eviction. The schedule continues without it.

Compartments are table-driven. Each owns a virtual region table (VRT); the
four PMP entries are its cache. Two rows stay pinned (sram, text), one slot
swaps in any other covered row on first fault and retries the instruction, one
no-permission entry denies the rest. Faults outside the table or without the
right permission keep the evidence path.

## Quick start (no hardware)

```bash
bash qemu/build_qemu.sh
qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic
```

Eight swarm sizes (N=8..64) run the board's four-phase schedule: eBPF
filtering, grid screening, a native-C reference filter, the attack spectrum.

```text
verdicts: 1 1 0 2 3 4
alerts:  board=4 mirror=4
attack:  n=5 mtval: 0x80200200 0x80200080 0x80200200 0x80100000 0x80100000
integrity: verdicts=1 checksum=1 own=1 native=1 proof=1 sv=1 nat2=1 swaps=1
== SWEEP 8/8 MATCH ==
```

Alert counts across the sweep are 0, 0, 3, 4, 10, 15, 19, 26; the board
reproduces them. `swaps=1` is the map row filling once during screening.

## Compartment engine

| Entry | Role |
| --- | --- |
| 0 | pinned sram row, R/W |
| 1 | pinned text row, R/X |
| 2 | swap-in slot, one NAPOT write per fill |
| 3 | no-permission filler, always armed |

Arming writes the two pinned rows and a cfg word assembled at mount. The trap
entry classifies a load, store or fetch fault: a VRT hit with the operation
granted programs `pmpaddr2`, fences, writes `pmpcfg0` with the pinned bytes,
fences, returns to the same `mepc`. Everything else goes to the evidence path.
Native slots are separate domains.

The eBPF map sits outside the monitor box on its own VRT row; the verifier
takes helper permissions from it (helper 1: R, helper 2: W) and the boot gate
rejects a policy that disagrees.

| Path | QEMU instructions | CH32V307 STK ticks |
| --- | --- | --- |
| arm a compartment | 26 | 5-6 |
| swap-in, load | 88 | 45 |
| swap-in, store | 91 | 45-46 |
| swap-in, fetch | 103 | 48-49 |

One tick is 8 HCLK cycles; the swap-in rows are end to end.

## Layout

```text
core/          contract, eBPF interpreter, helpers, trap capture, platform map
core/pmp/      virtual region table, swap-in engine, V4F port
modules/       supervisor, monitor, attacker, policies
qemu/          QEMU target, evidence report, swap-in drill
tests/         host tests: interpreter, engine, verifier
tools/         swarm injection, program loader, board audits
docs/          architecture figure
reference/     firmware image for recorded results
```

## Verification

| Gate | Where | Covers |
| --- | --- | --- |
| host | interpreter, engine, verifier suites on x86-64 | verdicts and instruction counts bit-exact, engine invariants, region/range/loop gates |
| QEMU | full schedule, CI | sweep, load, hot swap, channel, telemetry, persistence, trust, budget, swap-in drill |
| board | CH32V307 + WCH-LinkE | the recorded numbers from silicon |

```bash
gcc -O2 -ffreestanding -o t tests/test_host.c core/ebpf.c core/helpers.c core/frame.c && ./t
gcc -O2 -ffreestanding -o p tests/test_pmp.c core/pmp/icp.c && ./p
gcc -O2 -ffreestanding -o v tests/test_verifier.c core/loader.c && ./v
qemu-system-riscv32 -M virt -bios none -kernel build/fw_fill.elf -nographic
```

The swap-in drill covers three operations with a timing bill, a 200-swap thrash
between two overflow rows, and the violation cases.

### On the board

```bash
./build.sh
wlink flash -e build/fw_pmp.bin
python3 tools/inject_swarm.py 32 --seed 7    # host alerts=4  board alerts=4
python3 tools/pmpa_board.py                  # PMP containment sweep
```

### Load and channel

A `PROG` image, a console frame, or a runtime frame all pass the same gates.
`build/pmp_probe.bin` dumps CSR read-backs and a fault log to SRAM; its last
stage hangs by design, reflash `build/fw_pmp.bin` afterwards.

```bash
python3 tools/load_prog.py
python3 tools/uart_frame.py | qemu-system-riscv32 -M virt -bios none -kernel build/fw_urx.elf -display none -serial stdio -monitor none
python3 tools/chan_qemu.py
python3 tools/uart_data.py 24
```

## Roadmap

- [x] Runtime channel: data, eBPF, native module frames
- [x] Compartments: time-multiplexed PMP boxes
- [x] VRT engine: pinned rows, one swap-in slot, fault-time fill
- [x] Region-aware verifier and map row
- [ ] Other PMP-capable RISC-V MCUs

## Toolchain

| Use | Needs |
| --- | --- |
| host tests | gcc or clang |
| board | clang riscv32, lld, `riscv64-unknown-elf-objcopy`, `wlink` |
| QEMU | clang riscv32, lld, `qemu-system-riscv32` |

## License

MIT
