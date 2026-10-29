/* standalone E36 containment-audit firmware for the board: one .text in
 * flash, data/bss at the bottom of SRAM, the result block well above the
 * stack. The supervisor windows are irrelevant here — this image only
 * borrows the compartment API to arm PMP pairs. */
OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 252K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .text 0x08000000 : {
    KEEP(*(.init))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH
  .data : { *(.data .data.* .sdata .sbss) } > RAM
  .bss : {
    __bss_start = .;
    *(.bss .bss.* .sbss .sdata COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM
  .comp_state 0x20000100 (NOLOAD) : {
    KEEP(*(.comp_state))
    . = ALIGN(4);
  }
  __comp_start = 0;
  __comp_end = 0;
  _stack_top = 0x20003000;
  _sup_stack_top = 0x20003000;
}
