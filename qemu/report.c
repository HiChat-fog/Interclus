/* Evidence report for the QEMU build; UART primitives come from core/uart.c. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"

volatile int g_report_ok;

#define MON_RESULTS  ((volatile uint32_t *)(MON_BOX + 0x200u))
#define MON_INPUT_W  ((volatile uint32_t *)(MON_BOX + 0x80u))

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
                  STATUS[S_NAT2] == 0xC0DE0002u &&
                  STATUS[S_INTER] == 5u;
    for (int i = 0; i < 6; i++) {
        if (STATUS[S_CAIJUE + i] != want[i]) ok = 0;
    }
    /* the sp-vector attack must not have touched the verdict slots */
    uint32_t svok = 1;
    for (int i = 0; i < 8; i++) {
        if (STATUS[S_BAN_CAIJUE + i] > 5u) svok = 0;
    }
    if (!svok) ok = 0;
    /* the whole forensics chain is deterministic: pin it */
    static const uint32_t wcause[5] = { 7, 7, 5, 5, 1 };
    static const uint32_t wmtval[5] = { (uint32_t)MON_RESULTS,
                                        (uint32_t)MON_INPUT_W,
                                        (uint32_t)MON_RESULTS,
                                        MON_TEXT, MON_TEXT };
    for (int i = 0; i < 5; i++) {
        if (STATUS[S_LOG0C + i * 2] != wcause[i] ||
            STATUS[S_LOG0C + 1 + i * 2] != wmtval[i]) ok = 0;
    }

    uart_puts("\nalerts:  board=");
    uart_putdec(board_alerts);
    uart_puts(" mirror=");
    uart_putdec(mirror_alerts);
    uart_puts("\nattack:  n=");
    uart_putdec(STATUS[S_INTER]);
    uart_puts(" mtval:");
    for (int i = 0; i < 5; i++) { uart_puts(" 0x"); uart_puthex(STATUS[S_LOG0C + 1 + i * 2]); }
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
    uart_puts(" sv=");
    uart_putdec(svok);
    uart_puts(" nat2=");
    uart_putdec(STATUS[S_NAT2] == 0xC0DE0002u);
    uart_puts("\n");
    g_report_ok = ok;
    uart_puts(ok ? "== MATCH ==\n" : "== MISMATCH ==\n");
    return ok;
}
