/* frame.c — the console frame machine. One pure byte-at-a-time core feeds
 * both consumers: the boot-time window (uart_recv) and the runtime channel
 * (uart_poll_frame). The host tests drive it directly, so the wire rules
 * are pinned without hardware.
 *
 * Frame: sync(7E 7E), type(1), len16 LE, payload, sum8 — the checksum byte
 * brings the sum of type..payload to zero. A bad checksum or an oversized
 * length drops the frame and the machine resyncs on the next sync pair; a
 * partially received frame survives across calls, because the sender may
 * be slower than one poll. A stalled frame holds at most one bogus length
 * window before the next sync pair gets its chance — the resync is bounded
 * by the cap, never by time. */

#include <stdint.h>
#include "uart.h"

unsigned uart_frame_step(uint8_t byte, uint8_t *dst, unsigned cap,
                         uart_frame_rx *st) {
    switch (st->phase) {
    case 0:
        st->phase = (byte == 0x7E) ? 1u : 0u;
        return 0;
    case 1:
        st->phase = (byte == 0x7E) ? 2u : 0u;
        return 0;
    case 2:                                    /* type: caller owns policy */
        st->type = byte;
        st->sum = byte;
        st->phase = 3u;
        return 0;
    case 3:
        st->sum += byte;
        st->len = byte;
        st->phase = 4u;
        return 0;
    case 4:
        st->sum += byte;
        st->len |= (unsigned)byte << 8;
        if (st->len > cap) { st->phase = 0u; return 0; }
        st->idx = 0u;
        st->phase = st->len ? 5u : 6u;
        return 0;
    case 5:
        dst[st->idx++] = byte;
        st->sum += byte;
        st->phase = (st->idx == st->len) ? 6u : 5u;
        return 0;
    default:                                   /* checksum: pass or resync */
        st->phase = 0u;
        return (((st->sum + byte) & 0xFFu) == 0u) ? st->len : 0u;
    }
}
