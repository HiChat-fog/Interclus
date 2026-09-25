# Interclus

[![ci](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml/badge.svg)](https://github.com/HiChat-fog/Interclus/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

English | [简体中文](README.zh-CN.md)

> *An eBPF interpreter enclosed by RISC-V PMP.*

![architecture](docs/architecture.png)

An eBPF interpreter running unprivileged inside RISC-V PMP compartments on a
CH32V307 (RV32IMAFC, no MMU). A machine-mode supervisor arms the boundaries,
schedules the compartments, and closes a capture-forensics-recovery loop:
every faulting access is logged with `mcause` and `mtval`, then skipped or
redirected, and the monitor keeps running.

## Quick start (no hardware)

The full capacity sweep runs under QEMU:

```bash
bash qemu/build_qemu.sh
qemu-system-riscv32 -M virt -bios none -kernel build/fw_qemu.elf -nographic
```

Eight swarm sizes (N=8..64) go through the same four-phase schedule as the
board: eBPF filtering, grid screening, a native-C reference filter, and the
five-step attack spectrum. Each pass prints its evidence:

```text
verdicts: 1 1 0 2 3 4
insns:    15 12 5 12 13 15
alerts:  board=4 mirror=4
attack:  n=5 mtval: 0x80200200 0x80200080 0x80200200 0x80100000 0x80100000
integrity: verdicts=1 checksum=1 own=1 native=1 proof=1 sv=1
== MATCH ==

...

== SWEEP 8/8 MATCH ==
```

The alert counts across the sweep are 0, 0, 3, 4, 10, 15, 19, 26, and the
board reproduces them exactly.

## What you can learn here

| Topic | What it shows |
| --- | --- |
| PMP on a real MCU | NAPOT regions, a deny-all filler entry, measured vendor quirks: four usable entries, unmatched-allow, misaligned `mtvec` breaks trap delivery |
| 64-bit eBPF on a 32-bit core | a subset interpreter in portable C99, bit-exact on x86-64 and RV32 |
| Adversarial probe | attacks the isolation, including a forged-stack-pointer try at the trap handler, gets caught, forensics precise to the address |
| One firmware, two targets | real silicon and QEMU from one source, via `core/platform.h` |
| Boot-time loading | external bytecode passes the gates, replaces the compiled-in policy |

## Layout

```text
core/                 contract.h, eBPF interpreter, helpers, trap capture, platform map
modules/              supervisor, monitor, attacker probe, policies
descriptions/         YAML compartment descriptions, generated C
qemu/                 QEMU target: boot, fixture mailboxes, evidence report
tests/                host tests
tools/                swarm injection, program loader, host mirror check
docs/                 architecture figure
reference/            firmware image used for recorded results
build.sh              board firmware
qemu/build_qemu.sh    QEMU firmware
```

## Verification

Three gates guard one codebase: the interpreter, the supervisor, and the
monitor are the same C99 sources everywhere.

| Gate | Where | What it proves |
| --- | --- | --- |
| host tests | 66 cases on x86-64 | verdicts and instruction counts are bit-exact |
| QEMU pipeline | full four-phase schedule, green in CI | every recorded experiment reproduces without hardware |
| board | CH32V307 + WCH-LinkE | the recorded numbers come from real silicon |

### Host tests

```bash
gcc -fsanitize=address,undefined -ffreestanding -o t tests/test_host.c core/ebpf.c core/helpers.c
./t
```

### On the board

Hardware: CH32V307VCT6 board + WCH-LinkE debugger.

```bash
./build.sh                            # -> build/fw_pmp.bin
wlink flash -e build/fw_pmp.bin
python3 tools/inject_swarm.py 32 --seed 7
```

```text
swarm N=32 (seed=7)  host alerts=4  board alerts=4
RESULT: MATCH ✅
```

Sizes from 8 to 64 (the full mailbox capacity) and other seeds all work.

### Load a program at boot

At boot the supervisor checks a program area for a `PROG` header followed by
raw bytecode. The bytes pass the descriptor gate and a static preflight
before they land in the monitor's slot; anything rejected falls back to the
built-in policy, with the reason recorded in STATUS.

```bash
python3 tools/load_prog.py          # board, WCH-LinkE attached: verdicts flip
python3 tools/load_prog.py --bad    # oversized count: fallback, reason code
qemu-system-riscv32 -M virt -bios none -kernel build/fw_load.elf -nographic
```

The QEMU variant runs the same load path end to end and prints
`== LOAD PASS ==`.

The same load also works over the console: a frame (sync, type, length,
payload, checksum) pushed during the boot window lands in the program
area and faces the same gates. A corrupted frame is dropped before the
gates ever see it.

    python3 tools/uart_frame.py | qemu-system-riscv32 -M virt -bios none -kernel build/fw_urx.elf -display none -serial stdio -monitor none

## PMP semantics probe

A dedicated probe firmware measures the core's PMP behavior and dumps raw
evidence to SRAM:

```bash
wlink flash -e build/pmp_probe.bin
wlink dump 0x20000100 400     # CSR read-backs, fault log, U-mode markers
```

The last stage ends hung by design (misaligned-`mtvec` trap test); reflash
`build/fw_pmp.bin` afterwards.

## Roadmap

- [ ] UART data path to replace the debugger mailbox
- [ ] Native module loading: time-multiplexed PMP compartments
- [ ] Support for other PMP-capable RISC-V MCUs

## Toolchain

| Use | Needs |
| --- | --- |
| host tests | gcc (or clang) |
| board firmware | clang with riscv32 target, `lld` or rust-lld, `riscv64-unknown-elf-objcopy`, `wlink` |
| QEMU firmware | clang with riscv32 target, `lld` or rust-lld, `qemu-system-riscv32` |
| injection / loader tools | python3 |

## License

MIT
