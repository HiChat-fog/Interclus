/* host tests for the VRT engine (core/pmp/icp.c): table validation,
 * coverage, the arm mirror, and the fill/violation split. The port is
 * stubbed; the trap-side classification is exercised end to end by
 * qemu/fw_fill. Build:
 *   gcc -O2 -ffreestanding -o test_pmp tests/test_pmp.c core/pmp/icp.c */

#include <stdint.h>
#include <stdio.h>
#include "../core/pmp/icp.h"

static int fails;

#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); fails++; } } while (0)

static uint32_t pair_base[2], pair_cfg, swap_base, pair_calls, swap_calls;

void icp_port_pair(const icp_state *s) {
    pair_base[0] = s->vrt.row[0].paddr;
    pair_base[1] = s->vrt.row[1].paddr;
    pair_cfg = s->cfg0;
    pair_calls++;
}

void icp_port_swap(const icp_row *r, uint32_t cfg) {
    (void)cfg;
    swap_base = r->base;
    swap_calls++;
}

#define RAM  0x80221000u
#define TEXT 0x80220000u
#define SWAP 0x80222000u
#define FAR  0x80223000u

#define NAPOT_RAM  (0x80221000u / 4u + (0x1000u / 8u) - 1u)
#define NAPOT_TEXT (0x80220000u / 4u + (0x1000u / 8u) - 1u)

static void fill_domain(icp_state *d, uint32_t ram, uint32_t text) {
    icp_init(d);
    CHECK(icp_mount(d, ram, 0x1000u, ICP_R | ICP_W) == 0);
    CHECK(icp_mount(d, text, 0x1000u, ICP_R | ICP_X) == 0);
    CHECK(icp_mount(d, SWAP, 0x1000u, ICP_R | ICP_W) == 0);
    CHECK(icp_mount(d, FAR, 0x1000u, ICP_R | ICP_X) == 0);
    icp_lock(d);
    icp_arm(d);
}

int main(void) {
    icp_state d;
    icp_init(&d);

    CHECK(icp_mount(&d, 0x80221000u, 0x200u, ICP_R | ICP_W) == -1);  /* < 1 KiB */
    CHECK(icp_mount(&d, 0x80221000u, 0x1800u, ICP_R | ICP_W) == -1); /* not p2 */
    CHECK(icp_mount(&d, 0x80221400u, 0x1000u, ICP_R | ICP_W) == -1); /* base misaligned */
    CHECK(icp_mount(&d, 0x80221000u, 0x1000u, 8u) == -1);            /* perms bit 3 */
    CHECK(icp_mount(&d, RAM, 0x1000u, ICP_R | ICP_W) == 0);
    CHECK(icp_mount(&d, RAM, 0x800u, ICP_R) == -2);                  /* overlap */
    CHECK(icp_mount(&d, TEXT, 0x1000u, ICP_R | ICP_X) == 0);
    icp_lock(&d);
    CHECK(icp_mount(&d, SWAP, 0x1000u, ICP_R | ICP_W) == -1);        /* locked */
    CHECK(icp_cover(&d, RAM) == 0);
    CHECK(icp_cover(&d, RAM + 0xFFFu) == 0);
    CHECK(icp_cover(&d, TEXT) == 1);
    CHECK(icp_cover(&d, TEXT + 0xFFFu) == 1);
    CHECK(icp_cover(&d, 0x80224000u) == -1);

    icp_state a, b;
    fill_domain(&a, RAM, TEXT);
    CHECK(pair_calls == 1);
    CHECK(pair_base[0] == NAPOT_RAM && pair_base[1] == NAPOT_TEXT);
    CHECK(pair_cfg == 0x18001D1Bu);   /* RW byte0, RX byte1, deny byte3 */
    CHECK(a.switches == 1u);

    icp_cur = &a;
    CHECK(icp_on_fault(SWAP + 4u, ICP_STORE) == ICP_RETRY);
    CHECK(a.swaps == 1u && swap_base == SWAP);
    CHECK(icp_on_fault(SWAP + 8u, ICP_LOAD) == ICP_RETRY);
    CHECK(a.swaps == 2u);
    CHECK(icp_on_fault(FAR, ICP_FETCH) == ICP_RETRY);
    CHECK(a.swaps == 3u && swap_base == FAR);
    CHECK(icp_on_fault(TEXT + 8u, ICP_STORE) == ICP_VIOLATION);
    CHECK(icp_on_fault(TEXT + 8u, ICP_LOAD) == ICP_RETRY);           /* text is R|X */
    CHECK(icp_on_fault(0x80224000u, ICP_LOAD) == ICP_VIOLATION);
    CHECK(icp_on_fault(SWAP, ICP_FETCH) == ICP_VIOLATION);           /* RW row, fetch */

    fill_domain(&b, 0x80226000u, 0x80225000u);
    CHECK(b.switches == 1u && a.switches == 1u);
    CHECK(icp_on_fault(RAM, ICP_LOAD) == ICP_VIOLATION);             /* a's grant is gone */
    CHECK(icp_on_fault(TEXT, ICP_FETCH) == ICP_VIOLATION);
    CHECK(icp_on_fault(0x80226000u, ICP_LOAD) == ICP_RETRY);         /* b's own row */
    CHECK(b.swaps == 1u && swap_base == 0x80226000u);

    printf(fails ? "PMP HOST FAIL (%d)\n" : "PMP HOST PASS\n", fails);
    return fails ? 1 : 0;
}
