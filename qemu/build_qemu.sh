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
$CC -c ../core/uart.c -o uart.o
$CC -c ../core/compartment.c -o compartment.o
$CC -c ../modules/examples/native_demo.c -o native_demo.o -DNAT_SRAM_BASE=0x80211000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80210000 \
    -nostdlib -o native_demo.elf native_demo.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_demo.elf native_demo.bin
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_demo.bin native_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_qemu.elf \
    main_qemu.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o compartment.o native_blob.o
$CC -c ../qemu/load_test.c -o load_test.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_load.elf \
    load_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o compartment.o native_blob.o
$CC -DPROG_FROM_UART -c ../qemu/load_test.c -o load_urx.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_urx.elf \
    load_urx.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o compartment.o native_blob.o
echo "build/fw_qemu.elf build/fw_load.elf build/fw_urx.elf"
