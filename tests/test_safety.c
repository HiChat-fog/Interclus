/* E45 verifier-safety differential harness. Reads one program per line
 * ("cnt i0 i1 ..." as hex u64 words), runs ic_program_check, and for
 * every accepted program executes it against six fuzzed contexts. One
 * output line per program:
 *   V <verdict> <fault-bitmap> <pcmin> <pcmax>
 * fault bitmap: bit n set when the run set ended with fault n
 * (EBPF_OK..EBPF_FAULT_FP); pcmin/pcmax bound insns_executed across the
 * FAULT_PC runs only, 0/0 when PC never fired. The campaign contract
 * lives in tools/safety.py. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../core/ebpf.h"
#include "../core/loader.c"

#define RUNS 6
#define STEPS 3000u
#define CTX_SIZE 38u

static uint32_t map_cells = 64u;

static unsigned next_seed = 0x5E451u;
static uint32_t rnd(void) {
    next_seed = next_seed * 1103515245u + 12345u;
    return next_seed >> 8;
}

int main(void) {
    static char line[4096];
    static struct ebpf_prog prog;
    static struct ebpf_result res;
    static uint8_t ctx[CTX_SIZE];
    static uint64_t ins[EBPF_MAX_INSNS];

    while (fgets(line, sizeof line, stdin)) {
        unsigned cnt;
        char *p = line, *end;
        if (sscanf(p, "%u", &cnt) != 1 || cnt == 0 ||
            cnt > EBPF_MAX_INSNS) {
            printf("V 999 0 0 0\n");
            continue;
        }
        while (*p && *p != ' ') p++;        /* past the cnt field */
        for (unsigned i = 0; i < cnt; i++) {
            while (*p == ' ') p++;
            unsigned long long v = strtoull(p, &end, 16);
            if (end == p) {
                printf("V 998 0 0 0\n");
                goto next;
            }
            ins[i] = (uint64_t)v;
            p = end;
        }
        {
            ic_status verdict = ic_program_check(ins, cnt);
            if (verdict != IC_OK) {
                printf("V %d 0 0 0\n", (int)verdict);
                goto next;
            }
        }
        {
            uint32_t bitmap = 0, pcmin = 0xFFFFFFFFu, pcmax = 0;
            prog.ins = ins;
            prog.insn_cnt = cnt;
            prog.map_cells = map_cells;
            prog.max_steps = STEPS;
            for (int k = 0; k < RUNS; k++) {
                switch (k) {
                case 0: memset(ctx, 0, sizeof ctx); break;
                case 1: memset(ctx, 0xFF, sizeof ctx); break;
                case 2: memset(ctx, 0x80, sizeof ctx); break;
                default:
                    for (unsigned b = 0; b < CTX_SIZE; b++)
                        ctx[b] = (uint8_t)rnd();
                    break;
                }
                prog.ctx = ctx;
                prog.ctx_size = CTX_SIZE;
                {
                    static uint32_t map[64];
                    memset(map, 0, sizeof map);
                    prog.map = map;
                }
                memset(&res, 0, sizeof res);
                ebpf_run(&prog, &res);
                if (res.fault < 32u) bitmap |= 1u << res.fault;
                if (res.fault == EBPF_FAULT_PC) {
                    if (res.insns_executed < pcmin) pcmin = res.insns_executed;
                    if (res.insns_executed > pcmax) pcmax = res.insns_executed;
                }
            }
            printf("V 0 %u %u %u\n", bitmap, pcmin, pcmax);
        }
next: ;
        fflush(stdout);
    }
    return 0;
}
