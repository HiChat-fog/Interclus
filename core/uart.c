/* uart.c: 8N1 console. QEMU's virt 16550 works unconfigured; the CH32V307
 * USART1 runs from the ROM PLL clock (PCLK2 = HCLK = 120 MHz, see
 * boardlab/CLOCK_FINDINGS.md). Absolute-value writes only: RCC reads on
 * this silicon are not trustworthy (CLOCK_FINDINGS 3). */

#include <stdint.h>
#include "uart.h"
#include "platform.h"

#ifdef QEMU_TARGET

#define UART_TX ((volatile uint8_t *)0x10000000u)
#define UART_LSR ((volatile uint8_t *)0x10000005u)
#define LSR_DR   (1u << 0)

void uart_init(void) { }
void uart_putc(char c) { UART_TX[0] = (uint8_t)c; }
int uart_getc(void) {
    if (!(*UART_LSR & LSR_DR)) return -1;
    return (int)UART_TX[0];
}

#else

#define RCC_APB2PCENR (*(volatile uint32_t *)0x40021018u)
#define GPIOA_CFGHR   (*(volatile uint32_t *)0x40010804u)
#define USART1_STATR  (*(volatile uint32_t *)0x40013800u)
#define USART1_DATAR  (*(volatile uint32_t *)0x40013804u)
#define USART1_BRR    (*(volatile uint32_t *)0x40013808u)
#define USART1_CTLR1  (*(volatile uint32_t *)0x4001380Cu)

#define UART_PCLK  120000000u
#define UART_BAUD  115200u
#define STATR_TXE  (1u << 7)
#define STATR_RXNE (1u << 5)

void uart_init(void) {
    RCC_APB2PCENR |= (1u << 14) | (1u << 2);        /* USART1 + GPIOA */
    GPIOA_CFGHR = 0x44444B44u;                      /* PA9 AF-PP, PA10 in */
    USART1_BRR = UART_PCLK / UART_BAUD;             /* 1042 -> 115163 Bd */
    USART1_CTLR1 = (1u << 13) | (1u << 3) | (1u << 2);  /* UE | TE | RE */
}

void uart_putc(char c) {
    while (!(USART1_STATR & STATR_TXE)) { }
    USART1_DATAR = (uint8_t)c;
}

int uart_getc(void) {
    if (!(USART1_STATR & STATR_RXNE)) return -1;
    return (int)(uint8_t)USART1_DATAR;
}

#endif

void uart_puts(const char *s) { while (*s) uart_putc(*s++); }

void uart_puthex(uint32_t v) {
    for (int i = 28; i >= 0; i -= 4) {
        uint8_t n = (v >> i) & 0xFu;
        uart_putc((char)(n < 10 ? '0' + n : 'a' + n - 10));
    }
}

void uart_putdec(uint32_t v) {
    char b[11];
    int i = 0;
    do { b[i++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (i--) uart_putc(b[i]);
}

/* boot window for one console frame, in timer ticks (~100 ms at 10 MHz) */
#define UART_WINDOW 1000000u

unsigned uart_recv(uint8_t *dst, unsigned cap) {
    uint32_t t0 = TIMER_NOW();
    unsigned phase = 0, type = 0, len = 0, idx = 0, sum = 0;
    for (;;) {
        if ((uint32_t)(TIMER_NOW() - t0) > UART_WINDOW) return 0;
        int c = uart_getc();
        if (c < 0) continue;
        switch (phase) {
        case 0:
            phase = (c == 0x7E) ? 1u : 0u;
            break;
        case 1:
            phase = (c == 0x7E) ? 2u : 0u;
            break;
        case 2:                                    /* type: 1 = program */
            type = (unsigned)c;
            sum = type;
            phase = (type == 1u) ? 3u : 0u;
            break;
        case 3:
            sum += (unsigned)c;
            len = (unsigned)c;
            phase = 4u;
            break;
        case 4:
            sum += (unsigned)c;
            len |= (unsigned)c << 8;
            if (len > cap) return 0;
            idx = 0;
            phase = len ? 5u : 6u;
            break;
        case 5:
            dst[idx++] = (uint8_t)c;
            sum += (unsigned)c;
            if (idx == len) phase = 6u;
            break;
        default:
            return (((sum + (unsigned)c) & 0xFFu) == 0u) ? len : 0;
        }
    }
}
