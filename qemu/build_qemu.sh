#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2 -DQEMU_TARGET"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
$CC -c ../qemu/main_qemu.c -o main_qemu.o
$CC -c ../qemu/report.c -o report.o
$CC -c ../modules/monitor.c -o monitor.o
$CC -O0 -c ../modules/attacker.c -o attacker.o
$CC -c ../core/trap.S -o trap_pmp.o
$CC -c ../core/loader.c -o loader.o
$CC -c ../core/uart.c -o uart.o
$CC -c ../core/frame.c -o frame.o
$CC -c ../core/flash.c -o flash.o
$CC -c ../core/sha256.c -o sha256.o
$CC -c ../core/update.c -o update.o
$CC -c ../core/compartment.c -o compartment.o
$CC -c ../modules/examples/native_demo.c -o native_demo.o -DNAT_SRAM_BASE=0x80211000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80210000 \
    -nostdlib -o native_demo.elf native_demo.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_demo.elf native_demo.bin
$CC -c ../modules/examples/native_variant.c -o native_variant.o -DNAT_SRAM_BASE=0x80211000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80210000 \
    -nostdlib -o native_variant.elf native_variant.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant.elf native_variant_qemu.bin
$CC -c ../modules/examples/native_variant.c -o native_variant_s1.o -DNAT_SRAM_BASE=0x80213000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80212000 \
    -nostdlib -o native_variant_s1.elf native_variant_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant_s1.elf native_variant_s1_qemu.bin
$CC -c ../modules/examples/native_trap.c -o native_trap.o -DNAT_SRAM_BASE=0x80211000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80210000 \
    -nostdlib -o native_trap.elf native_trap.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap.elf native_trap_qemu.bin
$CC -c ../modules/examples/native_trap.c -o native_trap_s1.o -DNAT_SRAM_BASE=0x80213000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80212000 \
    -nostdlib -o native_trap_s1.elf native_trap_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap_s1.elf native_trap_s1_qemu.bin
$CC -c ../modules/examples/native_spin.c -o native_spin_s1.o -DNAT_SRAM_BASE=0x80213000
$LLD -flavor gnu -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x80212000 \
    -nostdlib -o native_spin_s1.elf native_spin_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_spin_s1.elf native_spin_s1_qemu.bin
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_demo.bin native_blob.o
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_variant_qemu.bin native_variant_qemu_blob.o
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_variant_s1_qemu.bin native_variant_s1_qemu_blob.o
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_trap_qemu.bin native_trap_qemu_blob.o
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_trap_s1_qemu.bin native_trap_s1_qemu_blob.o
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_spin_s1_qemu.bin native_spin_s1_qemu_blob.o
$CC -Os -c ../modules/supervisor.c -o main_pmp.o
python3 ../tools/sign_module.py --emit-header >/dev/null
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_qemu.elf \
    main_qemu.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
$CC -c ../qemu/load_test.c -o load_test.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_load.elf \
    load_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
$CC -DPROG_FROM_UART -c ../qemu/load_test.c -o load_urx.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_urx.elf \
    load_urx.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
$CC -c ../qemu/hot_test.c -o hot_test.o
$CC -c ../qemu/chan_test.c -o chan_test.o
$CC -c ../qemu/tele_test.c -o tele_test.o
$CC -c ../qemu/persist_test.c -o persist_test.o
$CC -c ../qemu/trust_test.c -o trust_test.o
$CC -c ../qemu/budget_test.c -o budget_test.o
$CC -c ../qemu/update_test.c -o update_test.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_hot.elf \
    hot_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o native_variant_qemu_blob.o native_variant_s1_qemu_blob.o native_trap_s1_qemu_blob.o native_trap_qemu_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_chan.elf \
    chan_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_tele.elf \
    tele_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o native_variant_qemu_blob.o native_variant_s1_qemu_blob.o native_trap_s1_qemu_blob.o native_trap_qemu_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_persist.elf \
    persist_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o native_variant_s1_qemu_blob.o native_trap_s1_qemu_blob.o native_trap_qemu_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_trust.elf \
    trust_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o native_variant_qemu_blob.o native_trap_qemu_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_budget.elf \
    budget_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o native_spin_s1_qemu_blob.o
$LLD -flavor gnu -T ../qemu/qemu.ld -nostdlib -o fw_update.elf \
    update_test.o report.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o native_blob.o
echo "build/fw_qemu.elf build/fw_load.elf build/fw_urx.elf build/fw_hot.elf build/fw_chan.elf build/fw_tele.elf build/fw_persist.elf build/fw_trust.elf build/fw_budget.elf build/fw_update.elf"
