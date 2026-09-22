
#include <stdint.h>
#include "../ebpf/ebpf_mini.h"
#include "../ebpf/policy_mavlink.h"
#include "../ebpf/policy_conflict.h"
#include "../ebpf/helpers_rv32.c"
#include "../ebpf/ebpf_mini.c"

#include "platform.h"

static void native_filter(void) {
    for (int i = 0; i < 6; i++) {
        const volatile uint8_t *p = MON_INPUT + MON_OFF[i];
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
        MON_NATIVE_VERD[i] = v;
    }
}

void monitor_main(void) {
    struct ebpf_prog prog;
    struct ebpf_result r;
    int i;

    switch (MON_MODE[0]) {
    case 2u:                                  
        native_filter();
        break;
    case 1u:                                  
        for (i = 0; i < (int)MAP_CELLS; i++) MON_MAP[i] = 0;  
        prog.ins = POLICY_CONFLICT;
        prog.insn_cnt = POLICY_CONFLICT_CNT;
        prog.map = (uint32_t *)MON_MAP;
        prog.map_cells = MAP_CELLS;
        prog.max_steps = 1000000u;
        {
            uint32_t al = 0;
            for (i = 0; i < (int)MON_CONFN[0]; i++) {
                prog.ctx = MON_DATA + MON_SOFF[i];
                prog.ctx_size = MON_SSIZES[i];
                ebpf_run(&prog, &r);
                MON_SCREEN_VERD[i] = (uint32_t)r.retval;
                MON_SCREEN_INSNS[i] = r.insns_executed;
                if (r.retval == 5u) al++;
            }
            DIAG_RUNS[0]++;
            DIAG_ALRT[0] = al;
        }
        break;
    default:                                  
        prog.ins = POLICY_MAVLINK;
        prog.insn_cnt = POLICY_MAVLINK_CNT;
        prog.map = 0;
        prog.map_cells = 0;
        prog.max_steps = 1000000u;
        for (i = 0; i < 6; i++) {
            prog.ctx = (const uint8_t *)(MON_INPUT + MON_OFF[i]);
            prog.ctx_size = MON_SIZES[i];
            ebpf_run(&prog, &r);
            MON_VERDICTS[i] = (uint32_t)r.retval;
            MON_INSNS[i] = r.insns_executed;
        }
        break;
    }
    __asm__ volatile ("ecall");
    for (;;) { __asm__ volatile ("wfi"); }
}

asm(
    ".section .monitor.text\n"
    ".globl monitor_entry\n"
    ".align 2\n"
    "monitor_entry:\n"
    "  lui  sp, %hi(_mon_stack_top)\n"
    "  addi sp, sp, %lo(_mon_stack_top)\n"
    "  lui  t0, %hi(monitor_main)\n"
    "  addi t0, t0, %lo(monitor_main)\n"
    "  jalr t0\n"
    "1: wfi\n"
    "  j 1b\n"
);
