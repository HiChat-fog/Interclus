#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
# 对象文件须以 monitor.o / attacker.o 基名参与链接（链接脚本按文件名分配舱室段）
$CC -c ../startup.S -o startup.o
$CC -c ../core/trap.S -o trap_pmp.o
$CC -c ../modules/supervisor.c -o main_pmp.o
$CC -c ../modules/monitor.c -o monitor.o
$CC -O0 -c ../modules/attacker.c -o attacker.o   # attacker stays -O0 (matches the published image)
$LLD -flavor gnu -T ../modules/board.ld -nostdlib -o fw_pmp.elf \
    startup.o main_pmp.o monitor.o attacker.o trap_pmp.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text --only-section=.monitor_text --only-section=.attacker_text fw_pmp.elf fw_pmp.bin
$CC -c ../modules/pmp_probe.c -o pmp_probe.o
$LLD -flavor gnu -T ../modules/probe.ld -nostdlib -o pmp_probe.elf pmp_probe.o
riscv64-unknown-elf-objcopy -O binary pmp_probe.elf pmp_probe.bin
echo "build/fw_pmp.bin build/pmp_probe.bin"
