#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"

void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
int chan_poll(uart_frame_rx *rx);
int hot_update_finalize(void);
void uart_puts(const char *s);
void qemu_exit(int code);

void sweep_next(void) {
    uart_frame_rx rx = {0, 0, 0, 0, 0};
    for (;;) {
        int ev = chan_poll(&rx);
        hot_swap();
        {
            int verdict = hot_update_finalize();
            if (verdict) {
                uart_puts(verdict > 0 ? "\nACCEPTED h=" : "\nREJECTED h=");
                uart_putdec(STATUS[S_HLOAD]);
                uart_puts("\n");
                if (verdict > 0) hot_round();
            }
        }
        if (ev == 1) supervisor_reset();
    }
}

__attribute__((section(".text.startup")))
void boot(void) {
    uart_puts("== UPDATE READY ==\n");
    supervisor_reset();
    boot_main();
    for (;;) { __asm__ volatile ("wfi"); }
}

__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j boot\n"
);
