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
#define LSR_THRE (1u << 5)

void uart_init(void) { }
int uart_tx_ready(void) { return (*UART_LSR & LSR_THRE) != 0; }
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

int uart_tx_ready(void) { return (USART1_STATR & STATR_TXE) != 0; }

/* debugger-side observers: the rx ring feeds uart_getc (the host is the
 * wire), the tap copies every TX byte into a ring the host drains */
static void uart_tap(uint8_t c) {
    if (VUART[0] != VU_MAGIC || !(VUART[3] & 1u)) return;
    if ((uint32_t)(VUART[4] - VUART[5]) < 1024u) {
        VU_TX[VUART[4] & 1023u] = c;
        VUART[4] = VUART[4] + 1u;
    }
}

void uart_putc(char c) {
    while (!(USART1_STATR & STATR_TXE)) { }
    USART1_DATAR = (uint8_t)c;
    uart_tap((uint8_t)c);
}

int uart_getc(void) {
    if (VUART[0] == VU_MAGIC && VUART[2] < VUART[1]) {
        int c = VU_RX[VUART[2] & 1023u];
        VUART[2] = VUART[2] + 1u;
        return c;
    }
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

unsigned uart_poll_frame(uint8_t *dst, unsigned cap, uart_frame_rx *st) {
    if (st->phase != 0u &&
        (uint32_t)(TIMER_NOW() - st->last_tick) > UART_FRAME_TIMEOUT) {
        st->phase = 0u;
        st->idx = 0u;
        st->len = 0u;
    }
    for (;;) {
        int c = uart_getc();
        if (c < 0) return 0;
        st->last_tick = TIMER_NOW();
        {
            unsigned n = uart_frame_step((uint8_t)c, dst, cap, st);
            if (n) {
                st->last_tick = TIMER_NOW();
                return n;
            }
        }
    }
}

static int putc_bounded(char c, uint32_t t0, uint32_t budget) {
    while (!uart_tx_ready()) {
        if ((uint32_t)(TIMER_NOW() - t0) > budget) return 0;
    }
    uart_putc(c);
    return 1;
}

int uart_send_frame_limited(uint8_t type, const uint8_t *payload,
                            unsigned len, uint32_t budget) {
    uint8_t hdr[5] = { 0x7E, 0x7E, type,
                       (uint8_t)(len & 0xFFu), (uint8_t)(len >> 8) };
    unsigned sum = type + (len & 0xFFu) + (len >> 8);
    uint32_t t0 = TIMER_NOW();
    for (unsigned i = 0; i < 5u; i++)
        if (!putc_bounded((char)hdr[i], t0, budget)) return 0;
    for (unsigned i = 0; i < len; i++) {
        if (!putc_bounded((char)payload[i], t0, budget)) return 0;
        sum += payload[i];
    }
    return putc_bounded((char)((-sum) & 0xFFu), t0, budget);
}

void uart_send_frame(uint8_t type, const uint8_t *payload, unsigned len) {
    unsigned sum = type + (len & 0xFFu) + (len >> 8);
    uart_putc((char)0x7E);
    uart_putc((char)0x7E);
    uart_putc((char)type);
    uart_putc((char)(len & 0xFFu));
    uart_putc((char)(len >> 8));
    for (unsigned i = 0; i < len; i++) {
        uart_putc((char)payload[i]);
        sum += payload[i];
    }
    uart_putc((char)((-sum) & 0xFFu));
}

unsigned uart_recv(uint8_t *dst, unsigned cap) {
    uart_frame_rx st = { 0, 0, 0, 0, 0 };
    uint32_t t0 = TIMER_NOW();
    for (;;) {
        if ((uint32_t)(TIMER_NOW() - t0) > UART_WINDOW) return 0;
        int c = uart_getc();
        if (c < 0) continue;
        if (uart_frame_step((uint8_t)c, dst, cap, &st) && st.type == 1u)
            return st.len;    /* the boot path takes program frames only;
                                 anything else is channel traffic */
    }
}
