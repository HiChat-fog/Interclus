
#include <stdint.h>
#include "../core/ebpf.h"
#include "policies/mavlink.h"
#include "policies/screening.h"
#include "../core/helpers.c"
#include "../core/ebpf.c"
#include "../core/unit.h"

static void native_filter(const ic_unit_ctx *c) {
    for (uint32_t i = 0; i < c->npkt; i++) {
        const volatile uint8_t *p = c->pkts + c->off[i];
        uint32_t v;
        if (p[0] != 0xFDu) {
            v = 0u;
        } else {
            uint32_t msgid = (uint32_t)p[7] | ((uint32_t)p[8] << 8) | ((uint32_t)p[9] << 16);
            uint32_t len = p[1];
            if (msgid != 0u && msgid != 32u && msgid != 33u) v = 2u;
            else if (len > 240u) v = 3u;
            else if (msgid == 33u) {
                uint32_t lat = (uint32_t)p[10] | ((uint32_t)p[11] << 8)
                             | ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 24);
                v = (lat > 900000000u) ? 4u : 1u;
            } else v = 1u;
        }
        c->nverd[i] = v;
    }
}

void monitor_main(const ic_unit_ctx *c) {
    struct ebpf_prog prog = { 0 };
    struct ebpf_result r;
    uint32_t i;

    switch (c->mode[0]) {
    case IC_UNIT_MODE_NATIVE:
        native_filter(c);
        break;
    case IC_UNIT_MODE_SCREEN:
        for (i = 0; i < c->map_cells; i++) c->map[i] = 0;
        prog.ins = POLICY_CONFLICT;
        prog.insn_cnt = POLICY_CONFLICT_CNT;
        prog.map = (uint32_t *)c->map;
        prog.map_cells = c->map_cells;
        prog.region = &c->region;
        prog.max_steps = 1000000u;
        {
            uint32_t al = 0;
            uint32_t n = c->swarm_n[0];
            for (i = 0; i < n; i++) {
                prog.ctx = (const uint8_t *)(c->swarm + c->soff[i]);
                prog.ctx_size = c->ssiz[i];
                ebpf_run(&prog, &r);
                c->screen_verd[i] = (uint32_t)r.retval;
                c->screen_insns[i] = r.insns_executed;
                if (r.retval == 5u) al++;
            }
            c->diag[0]++;
            c->diag[1] = al;
        }
        break;
    default:
        if (c->prog_cnt[0]) {
            prog.ins = (const uint64_t *)c->prog;
            prog.insn_cnt = c->prog_cnt[0];
        } else {
            prog.ins = POLICY_MAVLINK;
            prog.insn_cnt = POLICY_MAVLINK_CNT;
        }
        prog.map = 0;
        prog.map_cells = 0;
        prog.max_steps = 1000000u;
        {
            uint32_t pf = 0;
            for (i = 0; i < c->npkt; i++) {
                prog.ctx = (const uint8_t *)(c->pkts + c->off[i]);
                prog.ctx_size = c->len[i];
                ebpf_run(&prog, &r);
                c->mav_verd[i] = (uint32_t)r.retval;
                c->mav_insns[i] = r.insns_executed;
                if (r.fault) pf = r.fault;
            }
            c->mav_fault[0] = pf;
        }
        break;
    }
    ic_unit_yield();
    for (;;) { __asm__ volatile ("wfi"); }
}

asm(
    ".section .monitor.text\n"
    ".globl monitor_entry\n"
    ".align 2\n"
    "monitor_entry:\n"
    "  lui  t0, %hi(monitor_main)\n"
    "  addi t0, t0, %lo(monitor_main)\n"
    "  jalr t0\n"
    "1: wfi\n"
    "  j 1b\n"
);
