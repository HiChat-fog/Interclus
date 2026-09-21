#include <stdint.h>
#define UART0 ((volatile uint8_t *)0x10000000u)
void main(void) {
    UART0[0] = 'X';
    for (;;) { __asm__ volatile ("wfi"); }
}
__asm__(".globl _start\n_start: j main\n");
