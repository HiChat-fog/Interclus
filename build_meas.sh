#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"

# QEMU variant first (qemu.ld patterns are object-name based: keep basenames)
$CC -DQEMU_TARGET -c ../modules/measure.c -o measure.o
$CC -DQEMU_TARGET -c ../core/trap.S -o trap_pmp.o
$CC -DQEMU_TARGET -c ../core/loader.c -o loader.o
$CC -DQEMU_TARGET -c ../core/uart.c -o uart.o
$CC -DQEMU_TARGET -c ../core/compartment.c -o compartment.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_meas_qemu.elf \
    measure.o trap_pmp.o loader.o uart.o compartment.o

# board variant (fresh compile: platform.h values differ per target)
$CC -c ../modules/measure.c -o measure.o
$CC -c ../core/trap.S -o trap_pmp.o
$CC -c ../core/loader.c -o loader.o
$CC -c ../core/uart.c -o uart.o
$CC -c ../core/compartment.c -o compartment.o
$CC -c ../startup.S -o startup.o
$LLD -flavor gnu -T ../modules/board.ld -nostdlib -o fw_meas.elf \
    startup.o measure.o trap_pmp.o loader.o uart.o compartment.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text fw_meas.elf fw_meas.bin
echo "build/fw_meas_qemu.elf build/fw_meas.bin"
