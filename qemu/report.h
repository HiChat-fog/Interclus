/* report(): UART evidence dump, called by the supervisor's last phase. */

int report(void);
void uart_puts(const char *s);
void uart_puthex(uint32_t v);
void uart_putdec(uint32_t v);
void qemu_exit(int code);
