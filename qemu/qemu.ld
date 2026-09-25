OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M
}

SECTIONS {
  .text 0x80000000 : {
    KEEP(*(.text.startup))
    main_qemu.o(.text .text.*)
    load_test.o(.text .text.*)
    load_urx.o(.text .text.*)
    compartment.o(.text .text.*)
    report.o(.text .text.*)
    uart.o(.text .text.*)
    main_pmp.o(.text .text.*)
    trap_pmp.o(.text .text.*)
    main_qemu.o(.rodata .rodata.*)
    load_test.o(.rodata .rodata.*)
    load_urx.o(.rodata .rodata.*)
    compartment.o(.rodata .rodata.*)
    report.o(.rodata .rodata.*)
    uart.o(.rodata .rodata.*)
    main_pmp.o(.rodata .rodata.*)
    trap_pmp.o(.rodata .rodata.*)
    . = ALIGN(4);
  } > RAM

  .data : {
    main_qemu.o(.data .data.*)
    load_test.o(.data .data.*)
    load_urx.o(.data .data.*)
    compartment.o(.data .data.*)
    report.o(.data .data.*)
    uart.o(.data .data.*)
    main_pmp.o(.data .data.*)
    trap_pmp.o(.data .data.*)
    . = ALIGN(4);
  } > RAM

  .bss : {
    main_qemu.o(.bss .bss.* COMMON)
    load_test.o(.bss .bss.* COMMON)
    load_urx.o(.bss .bss.* COMMON)
    compartment.o(.bss .bss.* COMMON)
    report.o(.bss .bss.* COMMON)
    uart.o(.bss .bss.* COMMON)
    main_pmp.o(.bss .bss.* COMMON)
    trap_pmp.o(.bss .bss.* COMMON)
    . = ALIGN(4);
  } > RAM

  .mailbox 0x80011000 : { KEEP(*(.mailbox)) } > RAM

  .monitor_text 0x80100000 : {
    monitor.o(.text .text.* .monitor.text)
    monitor.o(.rodata .rodata.*)
  } > RAM

  .attacker_text 0x80102000 : {
    attacker.o(.text .text.* .attacker.text)
    attacker.o(.rodata .rodata.*)
  } > RAM

  .native_blob : { KEEP(*(.native_blob)) } > RAM

  .monitor_ram 0x80200000 (NOLOAD) : {
    monitor.o(.data .data.* .bss .bss.* .sbss .sdata)
  } > RAM

  .attacker_ram 0x80208000 (NOLOAD) : {
    attacker.o(.data .data.* .bss .bss.* .sbss .sdata)
  } > RAM

  .comp_state 0x80010A00 (NOLOAD) : {
    __comp_start = .;
    KEEP(*(.comp_state))
    . = ALIGN(4);
    __comp_end = .;
  } > RAM
  .trap_scratch 0x80010F00 (NOLOAD) : { KEEP(*(.trap_scratch)) } > RAM
}

_sup_stack_top = 0x8000F000;
_mon_stack_top = 0x80201F00;
_atk_stack_top = 0x80209F00;
