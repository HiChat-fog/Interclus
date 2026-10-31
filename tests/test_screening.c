/* E41: two unaudited surfaces in one pass.
 *
 * 1. The screening conflict policy — the swarm product semantics —
 *    runs statefully: each msgid-33 packet indexes a 64-cell grid from
 *    its latitude/longitude words, increments its cell, and alerts when
 *    the cell or either neighbor exceeds three. The differential seeds
 *    every (cell, count, left, right) scenario, runs one packet through
 *    the real interpreter, and compares the verdict and the map
 *    post-state against the reference mirror semantics.
 * 2. The descriptor gate (gate one of four) had never been machine
 *    audited: ic_module_check is enumerated over magic/version/kind/
 *    reserved/region/entry combinations and compared against the
 *    contract restated as a reference classifier.
 * The teeth demonstrations weaken the alert threshold and the
 * power-of-two region check; both must be caught exactly. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../core/ebpf.h"
#include "../modules/policies/screening.h"
#include "../core/loader.h"
#include "../core/contract.h"

static unsigned fails;

/* ---- section 1: screening differential ---- */

static uint32_t ref_screen(uint32_t n, uint32_t l, uint32_t r) {
    uint32_t count = n + 1u;             /* the packet increments its cell */
    if (count > 3u || l > 3u || r > 3u) return 5u;
    return 1u;
}

static void run_screen(uint32_t cell, uint32_t n, uint32_t l, uint32_t r) {
    uint32_t map[64];
    uint8_t pkt[42];
    struct ebpf_prog prog;
    struct ebpf_result res;
    memset(map, 0, sizeof map);
    map[cell] = n;
    map[(cell + 63u) & 63u] = l;
    map[(cell + 1u) & 63u] = r;
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0xFDu;
    pkt[1] = 32u;
    pkt[7] = 0x21u;                      /* msgid 33 */
    uint32_t lat_cell = cell >> 3u, lon_cell = cell & 7u;
    uint32_t lat_word = lat_cell << 26u, lon_word = lon_cell << 26u;
    pkt[10] = (uint8_t)lat_word;
    pkt[11] = (uint8_t)(lat_word >> 8);
    pkt[12] = (uint8_t)(lat_word >> 16);
    pkt[13] = (uint8_t)(lat_word >> 24);
    pkt[14] = (uint8_t)lon_word;
    pkt[15] = (uint8_t)(lon_word >> 8);
    pkt[16] = (uint8_t)(lon_word >> 16);
    pkt[17] = (uint8_t)(lon_word >> 24);
    prog.ins = POLICY_CONFLICT;
    prog.insn_cnt = POLICY_CONFLICT_CNT;
    prog.ctx = pkt;
    prog.ctx_size = sizeof pkt;
    prog.map = map;
    prog.map_cells = 64u;
    prog.max_steps = 100000u;
    ebpf_run(&prog, &res);
    uint32_t want = ref_screen(n, l, r);
    if (res.fault != 0u || (uint32_t)res.retval != want) {
        fails++;
        if (fails < 8u)
            printf("screen cell=%u n=%u l=%u r=%u: verdict=%llu want=%u "
                   "fault=%u\n", cell, n, l, r,
                   (unsigned long long)res.retval, want, res.fault);
    }
    if (map[cell] != n + 1u || map[(cell + 63u) & 63u] != l
        || map[(cell + 1u) & 63u] != r) {
        fails++;
        if (fails < 8u)
            printf("screen post-state wrong cell=%u: %u (want %u)\n",
                   cell, map[cell], n + 1u);
    }
}

static void sweep_screen(void) {
    for (uint32_t cell = 0; cell < 64u; cell++)
        for (uint32_t n = 0; n <= 6u; n++)
            for (uint32_t l = 0; l <= 6u; l++)
                for (uint32_t r = 0; r <= 6u; r++)
                    run_screen(cell, n, l, r);
}

/* ---- section 2: the descriptor gate, restated ---- */

static int ref_region(uint32_t base, uint32_t size) {
    return base % 0x1000u == 0u && size >= 0x400u
        && (size & (size - 1u)) == 0u && base + size > base;
}

/* {OK=0, CONTRACT, ARGUMENT} classification */
static int ref_module(uint32_t magic, uint32_t ver, uint32_t kind,
                      uint32_t reserved, uint32_t tb, uint32_t ts,
                      uint32_t sb, uint32_t ss, uint32_t entry) {
    if (magic != IC_MODULE_MAGIC) return 1;
    if (ver != IC_CONTRACT_VERSION) return 1;
    if (kind != IC_MODULE_EBPF && kind != IC_MODULE_NATIVE) return 2;
    if (reserved != 0u) return 2;
    if (kind == IC_MODULE_EBPF) {
        if (tb != 0u && tb % 8u != 0u) return 2;
        if (ts % 8u != 0u || ts < 8u) return 2;
        if (entry % 8u != 0u || entry >= ts) return 2;
        if (sb != 0u && sb % 4u != 0u) return 2;
        if (sb != 0u && ss == 0u) return 2;
        return 0;
    }
    if (!ref_region(tb, ts) || !ref_region(sb, ss)) return 2;
    if ((entry & 1u) || entry >= ts) return 2;
    return 0;
}

static int real_class(ic_status s) {
    switch (s) {
    case IC_OK: return 0;
    case IC_ERR_CONTRACT: return 1;
    default: return 2;
    }
}

static void sweep_descriptor(void) {
    static const uint32_t regions[] = {
        0x00000000u, 0x00000000u,          /* empty                */
        0x2000A000u, 0x00001000u,          /* valid                */
        0x2000A000u, 0x00000400u,          /* valid, minimal       */
        0x2000A001u, 0x00001000u,          /* misaligned base      */
        0x2000A000u, 0x00001001u,          /* not a power of two   */
        0x2000A000u, 0x00000200u,          /* too small            */
        0x2000A000u, 0x00000000u,          /* zero size            */
        0xFFFFF000u, 0x00001000u,          /* wraps the space      */
        0x2000A000u, 0x00000800u,          /* valid, half          */
    };
    static const uint32_t entries[] = { 0u, 0x408u, 0x409u, 0x1000u };
    static const uint32_t magics[3] = { IC_MODULE_MAGIC,
                                        IC_MODULE_MAGIC + 1u, 0u };
    static const uint32_t vers[3] = { IC_CONTRACT_VERSION, 0u,
                                      IC_CONTRACT_VERSION + 1u };
    static const uint32_t kinds[4] = { 0u, IC_MODULE_EBPF,
                                       IC_MODULE_NATIVE, 3u };
    unsigned n = 0;
    for (unsigned m = 0; m < 3u; m++)
    for (unsigned v = 0; v < 3u; v++)
    for (unsigned k = 0; k < 4u; k++)
    for (unsigned rsv = 0; rsv < 2u; rsv++)
    for (unsigned ti = 0; ti < 9u; ti += 2u)
    for (unsigned si = 0; si < 9u; si += 2u)
    for (unsigned e = 0; e < 4u; e++) {
        ic_module_desc d;
        d.magic = magics[m];
        d.contract_ver = vers[v];
        d.kind = kinds[k];
        d.reserved = rsv;
        d.text_base = regions[ti];
        d.text_size = regions[ti + 1];
        d.sram_base = regions[si];
        d.sram_size = regions[si + 1];
        d.entry_offset = entries[e];
        int want = ref_module(d.magic, d.contract_ver, d.kind, d.reserved,
                              d.text_base, d.text_size, d.sram_base,
                              d.sram_size, d.entry_offset);
        int got = real_class(ic_module_check(&d));
        n++;
        if (got != want) {
            fails++;
            if (fails < 8u)
                printf("gate: kind=%u got=%d want=%d (tb=%u ts=%u "
                       "entry=%u)\n", kinds[k], got, want,
                       d.text_base, d.text_size, d.entry_offset);
        }
    }
    printf("  descriptor cases: %u\n", n);
}

int main(void) {
    sweep_screen();
    sweep_descriptor();
    printf(fails ? "SCREENING FAIL (%u)\n" : "SCREENING PASS (%u)\n",
           fails);
    return fails != 0;
}
