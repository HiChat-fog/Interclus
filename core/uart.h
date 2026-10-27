/* uart.h: 8N1 console. One interface, two targets: QEMU's virt 16550
 * (works unconfigured) and the CH32V307 USART1 on PA9/PA10. */

#ifndef INTERCLUS_UART_H
#define INTERCLUS_UART_H

#include <stdint.h>

/* largest program image a console frame may carry (PROG header + 64 insns) */
#define UART_FRAME_MAX 520u
#define UART_FRAME_TIMEOUT 200000u

void uart_init(void);
int  uart_tx_ready(void);      /* TX buffer empty: putc will not stall */
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

/* Persistent state of the frame assembler: phase machine plus the fields
 * of the frame in flight. Caller-owned, survives across polls; a frame
 * may arrive slower than one poll. */
typedef struct {
    unsigned phase, type, len, idx, sum;
    uint32_t last_tick;
} uart_frame_rx;

/* The wire rules as one pure byte step (core/frame.c); host tests drive
 * it directly. Returns the payload length when a complete frame with a
 * valid checksum just landed, 0 otherwise; the type is in st->type. */
unsigned uart_frame_step(uint8_t byte, uint8_t *dst, unsigned cap,
                         uart_frame_rx *st);

/* Non-blocking drain of the console: consumes what has arrived into the
 * assembler. Same return contract as uart_frame_step; 0 means nothing
 * complete yet, never an error. The runtime channel polls this between
 * rounds — USART1 has no FIFO, so callers must not idle between polls
 * at line rate. */
unsigned uart_poll_frame(uint8_t *dst, unsigned cap, uart_frame_rx *st);

/* One frame out: sync, type, len16, payload, sum8 — the inverse of
 * uart_frame_step. Blocking TX, payload at most 64 bytes. */
void uart_send_frame(uint8_t type, const uint8_t *payload, unsigned len);

/* Best-effort variant: same frame, but gives up after `budget` timer
 * ticks if the wire never drains. Returns 1 sent, 0 abandoned. The
 * eviction path uses this — a stalled receiver must never park the
 * supervisor inside fault handling. */
int uart_send_frame_limited(uint8_t type, const uint8_t *payload,
                            unsigned len, uint32_t budget);

#endif
