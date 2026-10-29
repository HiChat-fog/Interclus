OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M
}

SECTIONS {
  .text 0x80000000 : {
    KEEP(*(.text.startup))
    pmp_audit.o(.text .text.*)
    main_qemu.o(.text .text.*)
    load_test.o(.text .text.*)
    load_urx.o(.text .text.*)
    hot_test.o(.text .text.*)
    measure.o(.text .text.*)
    compartment.o(.text .text.*)
    report.o(.text .text.*)
    uart.o(.text .text.*)
    frame.o(.text .text.*)
    chan_test.o(.text .text.*)
    tele_test.o(.text .text.*)
    persist_test.o(.text .text.*)
    trust_test.o(.text .text.*)
    budget_test.o(.text .text.*)
    flash.o(.text .text.*)
    sha256.o(.text .text.*)
    main_pmp.o(.text .text.*)
    trap_pmp.o(.text .text.*)
    pmp_audit.o(.rodata .rodata.*)
    main_qemu.o(.rodata .rodata.*)
    load_test.o(.rodata .rodata.*)
    load_urx.o(.rodata .rodata.*)
    hot_test.o(.rodata .rodata.*)
    measure.o(.rodata .rodata.*)
    compartment.o(.rodata .rodata.*)
    report.o(.rodata .rodata.*)
    uart.o(.rodata .rodata.*)
    frame.o(.rodata .rodata.*)
    chan_test.o(.rodata .rodata.*)
    tele_test.o(.rodata .rodata.*)
    persist_test.o(.rodata .rodata.*)
    trust_test.o(.rodata .rodata.*)
    budget_test.o(.rodata .rodata.*)
    flash.o(.rodata .rodata.*)
    sha256.o(.rodata .rodata.*)
    main_pmp.o(.rodata .rodata.*)
    trap_pmp.o(.rodata .rodata.*)
    . = ALIGN(4);
  } > RAM

  .data : {
    pmp_audit.o(.data .data.* .sdata .sbss)
    compartment.o(.data .data.* .sdata .sbss)
    main_qemu.o(.data .data.*)
    load_test.o(.data .data.*)
    load_urx.o(.data .data.*)
    hot_test.o(.data .data.*)
    measure.o(.data .data.*)
    compartment.o(.data .data.*)
    report.o(.data .data.*)
    uart.o(.data .data.*)
    frame.o(.data .data.*)
    chan_test.o(.data .data.*)
    tele_test.o(.data .data.*)
    persist_test.o(.data .data.*)
    trust_test.o(.data .data.*)
    budget_test.o(.data .data.*)
    flash.o(.data .data.*)
    sha256.o(.data .data.*)
    main_pmp.o(.data .data.*)
    trap_pmp.o(.data .data.*)
    . = ALIGN(4);
  } > RAM

  .bss : {
    pmp_audit.o(.bss .bss.* .sbss .sdata COMMON)
    compartment.o(.bss .bss.* .sbss .sdata COMMON)
    main_qemu.o(.bss .bss.* COMMON)
    load_test.o(.bss .bss.* COMMON)
    load_urx.o(.bss .bss.* COMMON)
    hot_test.o(.bss .bss.* COMMON)
    measure.o(.bss .bss.* COMMON)
    compartment.o(.bss .bss.* COMMON)
    report.o(.bss .bss.* COMMON)
    uart.o(.bss .bss.* COMMON)
    frame.o(.bss .bss.* COMMON)
    chan_test.o(.bss .bss.* COMMON)
    tele_test.o(.bss .bss.* COMMON)
    persist_test.o(.bss .bss.* COMMON)
    trust_test.o(.bss .bss.* COMMON)
    budget_test.o(.bss .bss.* COMMON)
    flash.o(.bss .bss.* COMMON)
    sha256.o(.bss .bss.* COMMON)
    main_pmp.o(.bss .bss.* COMMON)
    trap_pmp.o(.bss .bss.* COMMON)
    . = ALIGN(4);
  } > RAM

  /* NOLOAD islands first, strictly ascending: .bss ends below 0x80010400,
   * and any address descent here makes lld wrap a segment memsz past 4 GiB,
   * which QEMU refuses to load (E15/E18) */
  .comp_state 0x80010A00 (NOLOAD) : {
    __comp_start = .;
    KEEP(*(.comp_state))
    . = ALIGN(4);
    __comp_end = .;
  }
  .meas_res 0x80010D00 (NOLOAD) : { KEEP(*(.meas_res)) } > RAM
  .trap_scratch 0x80010F00 (NOLOAD) : { KEEP(*(.trap_scratch)) } > RAM

  .mailbox 0x80011000 : { KEEP(*(.mailbox)) } > RAM

  /* runtime channel staging (E21): after the mailbox, before the monitor
   * window; islands stay strictly ascending (E15/E18) */
  .chan_stage 0x80012000 (NOLOAD) : { KEEP(*(.chan_stage)) } > RAM

  .monitor_text 0x80100000 : {
    monitor.o(.text .text.* .monitor.text)
    monitor.o(.rodata .rodata.*)
  } > RAM

  .attacker_text 0x80102000 : {
    attacker.o(.text .text.* .attacker.text)
    attacker.o(.rodata .rodata.*)
  } > RAM

  .native_blob 0x80103000 : { KEEP(*(.native_blob)) } > RAM

  .monitor_ram 0x80200000 (NOLOAD) : {
    monitor.o(.data .data.* .bss .bss.* .sbss .sdata)
  } > RAM

  .attacker_ram 0x80208000 (NOLOAD) : {
    attacker.o(.data .data.* .bss .bss.* .sbss .sdata)
  } > RAM

  /* native slot 1 (E22): RAM window 2, exec via the shared PMP pair */
  .nat2_ram 0x80213000 (NOLOAD) : { KEEP(*(.nat2_ram)) }

  /* E25: RAM-backed flash mirror for the QEMU target */
  .mir_ram 0x80214000 (NOLOAD) : { KEEP(*(.mir_ram)) }
}

_sup_stack_top = 0x8000F000;
_mon_stack_top = 0x80201F00;
_atk_stack_top = 0x80209F00;
