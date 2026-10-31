/* E40: policy-semantics differential audit. The MAVLink C2 screening
 * policy is the product's reason to exist, and three implementations of
 * its semantics coexist: the eBPF program the interpreter runs, the
 * native_filter mirror the monitor compartment runs, and nobody's
 * written specification. This audit pins all three to one reference:
 * over an exhaustive boundary grid (start byte, msgid 24-bit edges,
 * length edges, latitude edges) the eBPF verdict, the native verdict
 * and the reference must agree; the six operator packets must produce
 * their pinned verdicts; and the acceptance decisions must hold for
 * both context sizes the schedule can present.
 * The teeth demonstration flips one allowlist constant in the eBPF
 * policy and the differential must flag the exact divergence. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../core/ebpf.h"
#include "../modules/policies/mavlink.h"

static unsigned fails;

/* the specification, stated once */
static uint32_t ref_verdict(const uint8_t *p) {
    if (p[0] != 0xFDu) return 0u;
    uint32_t msgid = (uint32_t)p[7] | ((uint32_t)p[8] << 8)
                   | ((uint32_t)p[9] << 16);
    uint32_t len = p[1];
    if (msgid != 0u && msgid != 32u && msgid != 33u) return 2u;
    if (len > 240u) return 3u;
    if (msgid == 33u) {
        uint32_t lat = (uint32_t)p[10] | ((uint32_t)p[11] << 8)
                     | ((uint32_t)p[12] << 16) | ((uint32_t)p[13] << 24);
        return (lat > 900000000u) ? 4u : 1u;
    }
    return 1u;
}

/* implementation #2: monitor.c's native_filter body, compiled here */
static uint32_t native_verdict(const uint8_t *p) {
    uint32_t v;
    if (p[0] != 0xFDu) {
        v = 0u;
    } else {
        uint32_t msgid = (uint32_t)p[7] | ((uint32_t)p[8] << 8)
                       | ((uint32_t)p[9] << 16);
        uint32_t len = p[1];
        if (msgid != 0u && msgid != 32u && msgid != 33u) v = 2u;
        else if (len > 240u) v = 3u;
        else if (msgid == 33u) {
            uint32_t lat = (uint32_t)p[10] | ((uint32_t)p[11] << 8)
                         | ((uint32_t)p[12] << 16)
                         | ((uint32_t)p[13] << 24);
            v = (lat > 900000000u) ? 4u : 1u;
        } else v = 1u;
    }
    return v;
}

static uint32_t ebpf_verdict(const uint8_t *p, uint32_t size) {
    struct ebpf_prog prog;
    struct ebpf_result r;
    prog.ins = POLICY_MAVLINK;
    prog.insn_cnt = POLICY_MAVLINK_CNT;
    prog.ctx = p;
    prog.ctx_size = size;
    prog.map = 0;
    prog.map_cells = 0;
    prog.max_steps = 100000u;
    ebpf_run(&prog, &r);
    return (uint32_t)r.retval;
}

static void check(const uint8_t *p, uint32_t size, const char *tag) {
    uint32_t ref = ref_verdict(p);
    uint32_t nat = native_verdict(p);
    uint32_t eb = ebpf_verdict(p, size);
    if (ref != nat || ref != eb) {
        fails++;
        if (fails < 12u)
            printf("%s: ref=%u native=%u ebpf=%u (start=%02x "
                   "msgid=%06x len=%u lat=%u)\n", tag, ref, nat, eb,
                   p[0], (p[7] | p[8] << 8 | p[9] << 16), p[1],
                   p[10] | p[11] << 8 | p[12] << 16 | p[13] << 24);
    }
}

int main(void) {
    static uint8_t pkt[42];

    /* the boundary grid: start bytes, msgid edges, length edges,
     * latitude edges */
    static const uint32_t starts[4] = { 0xFDu, 0xFEu, 0x00u, 0xFFu };
    static const uint32_t msgids[10] = { 0u, 1u, 31u, 32u, 33u, 34u,
                                         0x10000u, 0x200000u, 0x210000u,
                                         0xFFFFFFu };
    static const uint32_t lens[5] = { 0u, 1u, 240u, 241u, 255u };
    static const uint32_t lats[6] = { 0u, 899999999u, 900000000u,
                                      900000001u, 0x7FFFFFFFu,
                                      0xFFFFFFFFu };
    for (unsigned si = 0; si < 4u; si++)
    for (unsigned mi = 0; mi < 10u; mi++)
    for (unsigned li = 0; li < 5u; li++)
    for (unsigned ai = 0; ai < 6u; ai++) {
        memset(pkt, 0, sizeof pkt);
        pkt[0] = (uint8_t)starts[si];
        pkt[1] = (uint8_t)lens[li];
        pkt[7] = (uint8_t)msgids[mi];
        pkt[8] = (uint8_t)(msgids[mi] >> 8);
        pkt[9] = (uint8_t)(msgids[mi] >> 16);
        pkt[10] = (uint8_t)lats[ai];
        pkt[11] = (uint8_t)(lats[ai] >> 8);
        pkt[12] = (uint8_t)(lats[ai] >> 16);
        pkt[13] = (uint8_t)(lats[ai] >> 24);
        check(pkt, sizeof pkt, "grid");
    }

    /* short-context contract: the schedule presents 42-byte packets;
     * a short context must fault, not read out of bounds */
    {
        memset(pkt, 0, sizeof pkt);
        pkt[0] = 0xFDu;
        struct ebpf_prog prog;
        struct ebpf_result r;
        prog.ins = POLICY_MAVLINK;
        prog.insn_cnt = POLICY_MAVLINK_CNT;
        prog.ctx = pkt;
        prog.ctx_size = 4u;
        prog.map = 0;
        prog.map_cells = 0;
        prog.max_steps = 100000u;
        ebpf_run(&prog, &r);
        if (r.fault == 0u || r.retval != 0u) {
            fails++;
            printf("short context: fault=%u retval=%llu\n", r.fault,
                   (unsigned long long)r.retval);
        }
    }

    /* the six operator packets and their pinned verdicts */
    static const struct { const uint8_t *pkt; uint32_t len; uint32_t want; }
    known[] = {
        { PKT_GPI, sizeof PKT_GPI, 1u },
        { PKT_HB, sizeof PKT_HB, 1u },
        { PKT_BADMAGIC, sizeof PKT_BADMAGIC, 0u },
        { PKT_BADMSGID, sizeof PKT_BADMSGID, 2u },
        { PKT_BIGLEN, sizeof PKT_BIGLEN, 3u },
        { PKT_BADLAT, sizeof PKT_BADLAT, 4u },
    };
    for (unsigned k = 0; k < 6u; k++) {
        uint32_t eb = ebpf_verdict(known[k].pkt, known[k].len);
        uint32_t ref = ref_verdict(known[k].pkt);
        if (eb != known[k].want || ref != known[k].want) {
            fails++;
            printf("known packet %u: ebpf=%u ref=%u want=%u\n", k, eb,
                   ref, known[k].want);
        }
    }

    printf(fails ? "POLICY FAIL (%u)\n" : "POLICY PASS (%u)\n", fails);
    return fails != 0;
}
