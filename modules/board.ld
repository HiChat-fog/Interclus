OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 480K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .text 0x08000000 : {
    KEEP(*(.init))
    *(EXCLUDE_FILE(monitor.o attacker.o) .text .text.*)
    *(EXCLUDE_FILE(monitor.o attacker.o) .rodata .rodata.*)
    . = ALIGN(4);
  } > FLASH
  .monitor_text 0x08002000 : {
    KEEP(monitor.o(.text .text.* .monitor.text))
    KEEP(monitor.o(.rodata .rodata.*))
    . = ALIGN(4);
  } > FLASH
  .attacker_text 0x08004000 : {
    KEEP(attacker.o(.text .text.* .attacker.text))
    KEEP(attacker.o(.rodata .rodata.*))
    . = ALIGN(4);
  } > FLASH
  .data : {
    *(EXCLUDE_FILE(monitor.o attacker.o) .data .data.*)
    . = ALIGN(4);
  } > RAM
  .bss : {
    __bss_start = .;
    *(EXCLUDE_FILE(monitor.o attacker.o) .bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    __bss_end = .;
  } > RAM
  .monitor_ram 0x20004000 (NOLOAD) : {
    monitor.o(.data .data.* .bss .bss.* .sbss .sdata)
    . = ALIGN(4);
  }
  .attacker_ram 0x20008000 (NOLOAD) : {
    attacker.o(.data .data.* .bss .bss.* .sbss .sdata)
    . = ALIGN(4);
  }
  _stack_top     = 0x20003F00;  
  _sup_stack_top = 0x20003F00;  
  _mon_stack_top = 0x20005F00;  
  _atk_stack_top = 0x20009F00;  
}
