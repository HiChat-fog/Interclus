/* UART helpers + evidence report for the QEMU build. */

#include <stdint.h>
#include "../pmp/platform.h"

volatile int g_report_ok;

#define UART0 ((volatile uint8_t *)0x10000000u)

static void putc_(char c) {
    UART0[0] = (uint8_t)c;
}
void uart_puts(const char *s) { while (*s) putc_(*s++); }
void uart_puthex(uint32_t v) {
    for (int i = 28; i >= 0; i -= 4) {
        uint8_t n = (v >> i) & 0xFu;
        putc_(n < 10 ? '0' + n : 'a' + n - 10);
    }
}
void uart_putdec(uint32_t v) {
    char b[11];
    int i = 0;
    do { b[i++] = '0' + v % 10; v /= 10; } while (v);
    while (i--) putc_(b[i]);
}
/* exit QEMU via the virt-board test device: 0x5555 = pass, else fail */
void qemu_exit(int code) {
    *(volatile uint32_t *)0x100000u = (code == 0) ? 0x5555u : 0x3333u;
    for (;;) { __asm__ volatile ("wfi"); }
}

int report(void) {
    static const uint32_t want[6] = { 1, 1, 0, 2, 3, 4 };

    uart_puts("verdicts:");
    for (int i = 0; i < 6; i++) { uart_puts(" "); uart_putdec(STATUS[S_CAIJUE + i]); }
    uart_puts("\ninsns:   ");
    for (int i = 0; i < 6; i++) { uart_puts(" "); uart_putdec(STATUS[S_INSNS + i]); }

    /* C mirror of the screening policy over the fixture packets */
    uint32_t m[64] = { 0 };
    uint32_t n = STATUS[S_CHONGTU_N];
    uint32_t mirror_alerts = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t lat, lon;
        __asm__ volatile ("lw %0, 0(%1)" : "=r"(lat) : "r"(MB_DATA + i * 42u + 10u));
        __asm__ volatile ("lw %0, 0(%1)" : "=r"(lon) : "r"(MB_DATA + i * 42u + 14u));
        uint32_t c = ((lat >> 26) & 7u) * 8u + ((lon >> 26) & 7u);
        m[c]++;
        uint32_t left = m[(c - 1u) & 63u], right = m[(c + 1u) & 63u];
        if (m[c] > 3u || left > 3u || right > 3u) mirror_alerts++;
    }

    uint32_t board_alerts = STATUS[S_JINGBAO];
    uint32_t ok = (board_alerts == mirror_alerts) && STATUS[S_NATOK] &&
                  STATUS[S_VINTACT] && STATUS[S_IINTACT] &&
                  STATUS[S_OWNOOK] && STATUS[S_RDROK] &&
                  STATUS[S_INTER] == 4u;
    for (int i = 0; i < 6; i++) {
        if (STATUS[S_CAIJUE + i] != want[i]) ok = 0;
    }

    uart_puts("\nalerts:  board=");
    uart_putdec(board_alerts);
    uart_puts(" mirror=");
    uart_putdec(mirror_alerts);
    uart_puts("\nattack:  n=");
    uart_putdec(STATUS[S_INTER]);
    uart_puts(" mtval:");
    for (int i = 0; i < 4; i++) { uart_puts(" 0x"); uart_puthex(STATUS[S_LOG0C + 1 + i * 2]); }
    uart_puts("\nintegrity: verdicts=");
    uart_putdec(STATUS[S_VINTACT]);
    uart_puts(" checksum=");
    uart_putdec(STATUS[S_IINTACT]);
    uart_puts(" own=");
    uart_putdec(STATUS[S_OWNOOK]);
    uart_puts(" native=");
    uart_putdec(STATUS[S_NATOK]);
    uart_puts(" proof=");
    uart_putdec(STATUS[S_RDROK]);
    uart_puts("\n");
    g_report_ok = ok;
    uart_puts(ok ? "== MATCH ==\n" : "== MISMATCH ==\n");
    return ok;
}
