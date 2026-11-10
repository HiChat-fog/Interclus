OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 252K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .text 0x08000000 : {
    KEEP(*(.text.startup))
    fill_test.o(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH
  .probe_text 0x08003000 : { fill_test.o(.probe.text .probe.text.*) } > FLASH
  .probe_far 0x08003400 : { fill_test.o(.probe.far) } > FLASH
  .data : { fill_test.o(.data .data.* .sdata .sbss) } > RAM
  .bss : {
    __bss_start = .;
    fill_test.o(.bss .bss.* COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM
  .pmp_state 0x200011B0 (NOLOAD) : {
    __pmp_start = .;
    KEEP(*(.pmp_state))
    . = ALIGN(4);
    __pmp_end = .;
  }
  ASSERT(__pmp_end <= 0x20001700, "pmp state overruns the VUART")
}
_sup_stack_top = 0x20003F00;
