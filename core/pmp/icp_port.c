#include "icp.h"

volatile uint32_t g_cfgw;

static void csrw_(unsigned csr, uint32_t v) {
    __asm__ volatile ("csrw %0, %1" :: "n" (csr), "r" (v) : "memory");
}

/* cfg0 is assembled once per mount; the pair consumes it with the rows'
 * precomputed NAPOT addrs */
void icp_port_pair(const icp_state *s) {
    csrw_(0x3a0, 0u);
    csrw_(0x3b0, s->vrt.row[0].paddr);
    csrw_(0x3b1, s->vrt.row[1].paddr);
    csrw_(0x3b2, 0u);
    csrw_(0x3b3, 0xFFFFFFFFu);
    csrw_(0x3a0, s->cfg0);
    g_cfgw = s->cfg0;
}

void icp_port_swap(const icp_row *r, uint32_t cfg) {
    cfg |= (r->perms | 0x18u) << 16;
    (void)*(volatile const uint8_t *)&r->paddr;
    csrw_(0x3b2, r->paddr);
    __asm__ volatile ("fence rw, rw" ::: "memory");
    csrw_(0x3a0, cfg);
    __asm__ volatile ("fence rw, rw" ::: "memory");
    g_cfgw = cfg;
}
