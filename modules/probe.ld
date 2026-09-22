OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 480K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS {
  .text 0x08000000 : {
    KEEP(*(.text.startup))
    *(.text .text.*)
    . = ALIGN(4);
  } > FLASH

  .rodata : { *(.rodata .rodata.*) } > FLASH
  .data   : { *(.data .data.*) } > RAM
  .bss    : { *(.bss .bss.* COMMON) } > RAM
}

_stack_top = 0x20003F00;
