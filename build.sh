#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
# 对象文件须以 monitor.o / attacker.o 基名参与链接（链接脚本按文件名分配舱室段）
$CC -c ../startup.S -o startup.o
$CC -c ../qemu/pmp_audit.c -o pmp_audit_b.o
$CC -c ../core/compartment.c -o compartment_b.o
$CC -c ../core/uart.c -o uart_b.o
$CC -c ../core/frame.c -o frame_b.o
$LLD -flavor gnu -T ../modules/pmpab.ld -nostdlib -o fw_pmpab.elf \
    startup.o pmp_audit_b.o compartment_b.o uart_b.o frame_b.o
riscv64-unknown-elf-objcopy -O binary --only-section=.init --only-section=.text --only-section=.rodata fw_pmpab.elf fw_pmpab.bin
$CC -c ../core/trap.S -o trap_pmp.o
$CC -Oz -c ../core/loader.c -o loader.o
$CC -Os -c ../core/uart.c -o uart.o
$CC -c ../core/frame.c -o frame.o
$CC -c ../core/flash.c -o flash.o
$CC -c ../core/sha256.c -o sha256.o
$CC -Oz -c ../core/update.c -o update.o
$CC -c ../core/compartment.c -o compartment.o
$CC -c ../modules/monitor.c -o monitor.o
$CC -O0 -c ../modules/attacker.c -o attacker.o   # attacker stays -O0 (matches the published image)
$CC -c ../modules/examples/native_demo.c -o native_demo.o -DNAT_SRAM_BASE=0x2000B000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_demo.elf native_demo.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_demo.elf native_demo.bin
$CC -c ../modules/examples/native_variant.c -o native_variant.o -DNAT_SRAM_BASE=0x2000B000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_variant.elf native_variant.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant.elf native_variant.bin
$CC -c ../modules/examples/native_variant.c -o native_variant_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_variant_s1.elf native_variant_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant_s1.elf native_variant_s1.bin
$CC -c ../modules/examples/native_trap.c -o native_trap.o -DNAT_SRAM_BASE=0x2000B000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_trap.elf native_trap.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap.elf native_trap.bin
$CC -c ../modules/examples/native_trap.c -o native_trap_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_trap_s1.elf native_trap_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap_s1.elf native_trap_s1.bin
$CC -c ../modules/examples/native_spin.c -o native_spin_s1.o -DNAT_SRAM_BASE=0x2000D000
$CC -c ../modules/examples/native_chaos.c -o native_chaos_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_chaos_s1.elf native_chaos_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_chaos_s1.elf native_chaos_s1.bin
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_spin_s1.elf native_spin_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_spin_s1.elf native_spin_s1.bin
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_demo.bin native_blob.o
python3 ../tools/sign_module.py --emit-header >/dev/null
$CC -Os -c ../modules/supervisor.c -o main_pmp.o
$LLD -flavor gnu -T ../modules/board.ld -nostdlib -o fw_pmp.elf \
    startup.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text --only-section=.monitor_text --only-section=.attacker_text --only-section=.native_blob fw_pmp.elf fw_pmp.bin
$CC -c ../modules/pmp_probe.c -o pmp_probe.o
$LLD -flavor gnu -T ../modules/probe.ld -nostdlib -o pmp_probe.elf pmp_probe.o
riscv64-unknown-elf-objcopy -O binary pmp_probe.elf pmp_probe.bin
echo "build/fw_pmp.bin build/pmp_probe.bin"
