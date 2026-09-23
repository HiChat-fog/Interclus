#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2 -DQEMU_TARGET"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
$CC -c ../qemu/main_qemu.c -o main_qemu.o
$CC -c ../qemu/report.c -o report.o
$CC -c ../modules/supervisor.c -o main_pmp.o
$CC -c ../modules/monitor.c -o monitor.o
$CC -O0 -c ../modules/attacker.c -o attacker.o
$CC -c ../core/trap.S -o trap_pmp.o
$CC -c ../core/loader.c -o loader.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_qemu.elf \
    main_qemu.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o
echo "build/fw_qemu.elf"
