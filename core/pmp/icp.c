#include "icp.h"

icp_state *icp_cur;

uint32_t icp_napot(uint32_t base, uint32_t size) {
    return (base >> 2) | ((size >> 3) - 1u);
}

void icp_init(icp_state *s) {
    s->vrt.n = 0u;
    s->vrt.lock = 0u;
    s->swaps = 0u;
    s->switches = 0u;
    s->cfg0 = 0x18u << 24;
}

int icp_mount(icp_state *s, uint32_t base, uint32_t size, uint32_t perms) {
    if (s->vrt.lock || s->vrt.n >= IC_VRT_MAX || size < 0x400u ||
        (size & (size - 1u)) != 0u || base % size != 0u ||
        base + size <= base || (perms & ~(ICP_R | ICP_W | ICP_X)) != 0u)
        return -1;
    for (uint32_t i = 0; i < s->vrt.n; i++)
        if (base < s->vrt.row[i].base + s->vrt.row[i].size &&
            s->vrt.row[i].base < base + size)
            return -2;
    icp_row *r = &s->vrt.row[s->vrt.n++];
    r->base = base;
    r->size = size;
    r->perms = perms;
    r->paddr = icp_napot(base, size);
    if (s->vrt.n <= IC_PINS) {
        uint32_t sh = (s->vrt.n - 1u) * 8u;
        s->cfg0 = (s->cfg0 & ~(0xFFu << sh)) | ((perms | 0x18u) << sh);
    }
    return 0;
}

void icp_lock(icp_state *s) { s->vrt.lock = 1u; }

int icp_cover(const icp_state *s, uint32_t addr) {
    for (uint32_t i = 0; i < s->vrt.n; i++)
        if (addr - s->vrt.row[i].base < s->vrt.row[i].size) return (int)i;
    return -1;
}

void icp_arm(icp_state *s) {
    icp_cur = s;
    s->switches++;
    icp_port_pair(s);
}

icp_action icp_on_fault(uint32_t addr, icp_op op) {
    icp_state *s = icp_cur;
    int k = icp_cover(s, addr);
    if (k < 0 || (s->vrt.row[k].perms & (1u << op)) == 0u)
        return ICP_VIOLATION;
    s->swaps++;
    icp_port_swap(&s->vrt.row[k], s->cfg0);
    return ICP_RETRY;
}
