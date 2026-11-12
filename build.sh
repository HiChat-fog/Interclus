#!/usr/bin/env bash
set -e
REPO="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$REPO/build"
cd "$REPO/build"
CC="clang --target=riscv32 -march=rv32imafc -mabi=ilp32 -mno-relax -msmall-data-limit=0 -ffreestanding -O2"
LLD="${LLD:-$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld}"
LLDFLAGS="-flavor gnu"
case "$(basename "$LLD")" in ld.lld) LLDFLAGS= ;; esac
# Object files must link with monitor.o / attacker.o basenames (linker assigns compartments by filename).
$CC -c ../startup.S -o startup.o
$CC -c ../qemu/pmp_audit.c -o pmp_audit_b.o
$CC -c ../core/compartment.c -o compartment_b.o
$CC -Os -c ../core/pmp/icp.c -o pmp_icp_b.o
$CC -Os -c ../core/pmp/icp_port.c -o pmp_port_b.o
$CC -c ../core/uart.c -o uart_b.o
$CC -c ../core/frame.c -o frame_b.o
$LLD $LLDFLAGS -T ../modules/pmpab.ld -nostdlib -o fw_pmpab.elf \
    startup.o pmp_audit_b.o compartment_b.o pmp_icp_b.o pmp_port_b.o uart_b.o frame_b.o
riscv64-unknown-elf-objcopy -O binary --only-section=.init --only-section=.text --only-section=.rodata fw_pmpab.elf fw_pmpab.bin
$CC -c ../core/trap.S -o trap_pmp.o
$CC -Oz -c ../core/loader.c -o loader.o
$CC -Os -c ../core/uart.c -o uart.o
$CC -c ../core/frame.c -o frame.o
$CC -c ../core/flash.c -o flash.o
$CC -Os -c ../core/sha256.c -o sha256.o
$CC -Oz -c ../core/update.c -o update.o
$CC -c ../core/compartment.c -o compartment.o
$CC -Os -c ../core/pmp/icp.c -o pmp_icp.o
$CC -Os -c ../core/pmp/icp_port.c -o pmp_port.o
$CC -c ../modules/monitor.c -o monitor.o
$CC -O0 -c ../modules/attacker.c -o attacker.o   # attacker stays -O0 (matches the published image)
$CC -c ../modules/examples/native_demo.c -o native_demo.o -DNAT_SRAM_BASE=0x2000B000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_demo.elf native_demo.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_demo.elf native_demo.bin
$CC -c ../modules/examples/native_variant.c -o native_variant.o -DNAT_SRAM_BASE=0x2000B000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_variant.elf native_variant.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant.elf native_variant.bin
$CC -c ../modules/examples/native_variant.c -o native_variant_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_variant_s1.elf native_variant_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_variant_s1.elf native_variant_s1.bin
$CC -c ../modules/examples/native_trap.c -o native_trap.o -DNAT_SRAM_BASE=0x2000B000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o native_trap.elf native_trap.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap.elf native_trap.bin
$CC -c ../modules/examples/native_trap.c -o native_trap_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_trap_s1.elf native_trap_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_trap_s1.elf native_trap_s1.bin
$CC -c ../modules/examples/native_spin.c -o native_spin_s1.o -DNAT_SRAM_BASE=0x2000D000
$CC -c ../modules/examples/canary_mod.c -o canary_mod.o -DNAT_SRAM_BASE=0x2000B000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000A000 \
    -nostdlib -o canary.elf canary_mod.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text canary.elf canary.bin
$CC -c ../modules/examples/native_chaos.c -o native_chaos_s1.o -DNAT_SRAM_BASE=0x2000D000
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_chaos_s1.elf native_chaos_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_chaos_s1.elf native_chaos_s1.bin
$LLD $LLDFLAGS -T ../modules/native.ld --defsym NAT_TEXT_BASE=0x2000C000 \
    -nostdlib -o native_spin_s1.elf native_spin_s1.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text native_spin_s1.elf native_spin_s1.bin
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv \
    --rename-section .data=.native_blob,alloc,load,readonly,contents \
    native_demo.bin native_blob.o
python3 ../tools/sign_module.py --emit-header >/dev/null
$CC -Os -c ../modules/supervisor.c -o main_pmp.o
$LLD $LLDFLAGS -T ../modules/board.ld -nostdlib -o fw_pmp.elf \
    startup.o main_pmp.o monitor.o attacker.o trap_pmp.o loader.o uart.o frame.o flash.o sha256.o update.o compartment.o pmp_icp.o pmp_port.o native_blob.o
riscv64-unknown-elf-objcopy -O binary --only-section=.text --only-section=.monitor_text \
    --only-section=.attacker_text --only-section=.native_blob --only-section=.vfy_text \
    fw_pmp.elf fw_pmp.bin
$CC -c ../modules/pmp_probe.c -o pmp_probe.o
$LLD $LLDFLAGS -T ../modules/probe.ld -nostdlib -o pmp_probe.elf pmp_probe.o
riscv64-unknown-elf-objcopy -O binary pmp_probe.elf pmp_probe.bin
$CC -c ../qemu/fill_test.c -o fill_test.o
$CC -c ../core/pmp/icp.c -o fill_icp.o
$CC -c ../core/pmp/icp_port.c -o fill_port.o
$CC -c ../core/uart.c -o fill_uart.o
$CC -c ../core/frame.c -o fill_frame.o
$CC -c ../core/trap.S -o fill_trap.o
$LLD $LLDFLAGS -T ../modules/fill_board.ld -nostdlib -o fw_fill_board.elf \
    fill_test.o fill_icp.o fill_port.o fill_trap.o fill_uart.o fill_frame.o
riscv64-unknown-elf-objcopy -O binary --only-section .text \
    --only-section .probe_text --only-section .probe_far \
    fw_fill_board.elf fw_fill_board.bin

echo "build/fw_pmp.bin build/pmp_probe.bin build/fw_fill_board.bin"
