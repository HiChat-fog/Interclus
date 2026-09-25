/* uart.h: 8N1 console. One interface, two targets: QEMU's virt 16550
 * (works unconfigured) and the CH32V307 USART1 on PA9/PA10. */

#ifndef INTERCLUS_UART_H
#define INTERCLUS_UART_H

#include <stdint.h>

/* largest program image a console frame may carry (PROG header + 64 insns) */
#define UART_FRAME_MAX 520u

void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
void uart_puthex(uint32_t v);
void uart_putdec(uint32_t v);
int  uart_getc(void);          /* -1 when the receiver is empty */

/* Console frame receiver: sync(7E 7E), type(1), len16 LE, payload, sum8.
 * The sum covers type..payload; the frame byte must bring it to zero.
 * Payload goes to dst (at most cap). Returns the payload length, or 0
 * when nothing arrived or the frame is bad. The whole hunt is bounded by
 * a fixed boot window, so silence costs the same every boot. */
unsigned uart_recv(uint8_t *dst, unsigned cap);

#endif
