OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 4M
}

SECTIONS {
  .text 0x80000000 : {
    KEEP(*(.text.startup))
    *(.text .text.*)
    . = ALIGN(4);
  } > RAM

  .rodata : { *(.rodata .rodata.*) } > RAM
  .data   : { *(.data .data.*) } > RAM
  .bss    : { *(.bss .bss.* COMMON) } > RAM

  .worker 0x80100000 : {
    KEEP(*(.worker.text))
    KEEP(*(.worker.data))
    *(.worker*)
    . = ALIGN(4);
  } > RAM
}

_stack_top = 0x80400000;
