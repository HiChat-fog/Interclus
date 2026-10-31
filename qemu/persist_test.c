/* QEMU persistence acceptance (E25): a hot-installed native module is
 * mirrored to flash; a full supervisor re-init (supervisor_reset +
 * boot_main — the closest a QEMU test gets to a power cycle without
 * leaving the machine) restores the module from the mirror through the
 * same gates, and its proof returns in the first round after boot.
 *   == PERSIST PASS == / == PERSIST FAIL ==
 * State 0: boot with a poisoned mirror page (bad magic) — the built-in
 *          demo must still serve; proof 0xC0DE0002.
 * State 1: install the variant into slot 1 (mirror write ran).
 * State 2: reboot in place; the variant must come back through the
 *          gates; proof 0xC0DE0003 without any install. */

#include <stdint.h>
#include "../core/platform.h"
#include "../core/uart.h"
#include "../modules/examples/pass_all.c"
#include "trust_stub.h"

void uart_puts(const char *s);
void uart_puthex(uint32_t v);
void uart_putdec(uint32_t v);
int report(void);
void boot_main(void);
void supervisor_reset(void);
void hot_swap(void);
void hot_round(void);
void qemu_exit(int code);

extern const uint8_t _binary_native_trap_s1_qemu_bin_start[];
extern const uint8_t _binary_native_trap_s1_qemu_bin_end[];
extern const uint8_t _binary_native_variant_s1_qemu_bin_start[];
extern const uint8_t _binary_native_variant_s1_qemu_bin_end[];

static volatile unsigned state;

static void stage_native(uint32_t addr, const uint8_t *code, uint32_t len,
                         uint32_t entry, uint32_t slot) {
    volatile uint32_t *a = (volatile uint32_t *)addr;
    volatile uint8_t *p = (volatile uint8_t *)(addr + 16u);
    a[0] = len;
    a[1] = PEND_NATIVE;
    a[2] = entry;
    a[3] = slot;
    for (uint32_t i = 0; i < len; i++) p[i] = code[i];
    trust_stamp((volatile uint8_t *)addr,
                (a[1] == PEND_NATIVE) ? 16u + a[0]
                                      : 8u + a[0] * 8u);
    a[PROG_PEND_MAGIC_OFF / 4u] = PROG_PEND_MAGIC;
}

/* corrupt the mirror header so restore must reject it (blank-flash path
 * is exercised by state 0's first boot) */
extern uint32_t mir_ram[];   /* from core/flash.c (QEMU stand-in) */

void sweep_next(void) {
    uint32_t ok = 1;
    if (state == 0) {
        state = 1;
        ok = STATUS[S_NAT2] == 0xC0DE0002u;   /* built-in demo served */
        /* poison the mirror: magic wrong -> restore keeps the demo */
        mir_ram[0x100u] = 0xDEADBEEFu;
        stage_native(PROG_PEND_ADDR,
                     _binary_native_variant_s1_qemu_bin_start,
                     (uint32_t)(_binary_native_variant_s1_qemu_bin_end
                                - _binary_native_variant_s1_qemu_bin_start),
                     0u, 1u);
        hot_swap();
        if (STATUS[S_HLOAD] != 1u) ok = 0;
    } else if (state == 1) {
        state = 2;
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_NSLOT] == 1u;
        /* reboot in place: supervisor_reset + boot_main walk the whole
         * boot path, including the flash restore */
        supervisor_reset();
        boot_main();
        return;                                /* boot_main never returns */
    } else {
        ok = STATUS[S_NAT2] == 0xC0DE0003u && STATUS[S_NSLOT] == 1u;
        uart_puts(ok ? "\n== PERSIST PASS ==\n" : "\n== PERSIST FAIL ==\n");
        qemu_exit(ok ? 0 : 1);
    }
    if (!ok) {
        uart_puts("\n== PERSIST FAIL ==\n");
        qemu_exit(1);
    }
    hot_round();
}

__attribute__((section(".text.startup")))
void boot(void) {
    /* state 0 wants a BLANK mirror: wipe the RAM stand-in before the
     * first boot_main */
    for (unsigned i = 0; i < 0x800u / 4u; i++) mir_ram[i] = 0xFFFFFFFFu;
    supervisor_reset();
    boot_main();
    for (;;) { __asm__ volatile ("wfi"); }
}

__asm__(
    ".section .text.startup\n"
    ".globl _start\n"
    "_start:\n"
    "  lui  sp, %hi(_sup_stack_top)\n"
    "  addi sp, sp, %lo(_sup_stack_top)\n"
    "  j    boot\n"
);
