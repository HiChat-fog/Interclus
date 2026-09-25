OUTPUT_ARCH(riscv)
ENTRY(native_entry)
SECTIONS {
  . = NAT_TEXT_BASE;
  .text : { *(.text .text.*) }
}
