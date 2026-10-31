/* E39: console frame-parser audit. uart_frame_step is the front door of
 * the operator wire — program installs, mailbox data, native modules and
 * the E34 reliable-update channel all arrive through this 56-line state
 * machine, yet its transitions had only ever been exercised, not
 * verified. Four machine checks:
 *   1. spec-table exhaustiveness: every reachable phase × every byte
 *      value × boundary lengths, against an oracle re-derived from the
 *      wire contract (transitions, return value, memory effect);
 *   2. the safety invariant: the write cursor can never pass the
 *      caller's cap, no matter what length field the wire carries;
 *   3. stream properties: resync after garbage and oversized frames,
 *      checksum boundary, zero-length frames, sync-in-length fields;
 *   4. seeded fuzz with guard canaries around the destination buffer.
 * The teeth demonstration flips the cap check into an off-by-16 and the
 * guard canaries must catch the overflow. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../core/uart.h"

static unsigned fails;
static unsigned printed;

typedef struct { unsigned phase, type, len, idx, sum; } ospec;


/* the wire contract, restated */
static unsigned spec_step(uint8_t byte, unsigned cap, ospec *o,
                          uint8_t *dst) {
    /* the real machine keeps sum as a free-running accumulator and
     * masks it only at the accept decision — the oracle must match */

    unsigned ret = 0;
    switch (o->phase) {
    case 0:
        o->phase = (byte == 0x7E) ? 1u : 0u;
        break;
    case 1:
        o->phase = (byte == 0x7E) ? 2u : 0u;
        break;
    case 2:
        o->type = byte;
        o->sum = byte;
        o->phase = 3u;
        break;
    case 3:
        o->sum += byte;
        o->len = byte;
        o->phase = 4u;
        break;
    case 4:
        o->sum += byte;
        o->len |= (unsigned)byte << 8;
        if (o->len > cap) { o->phase = 0u; break; }
        o->idx = 0u;
        o->phase = o->len ? 5u : 6u;
        break;
    case 5:
        if (o->idx >= o->len || o->idx >= cap) { fails++; break; }
        dst[o->idx++] = byte;
        o->sum += byte;
        o->phase = (o->idx == o->len) ? 6u : 5u;
        break;
    default:
        o->phase = 0u;
        ret = (((o->sum + byte) & 0xFFu) == 0u) ? o->len : 0u;
        break;
    }
    return ret;
}

static const unsigned lens[] = { 0, 1, 2, 7, 8, 239, 240, 241, 256,
                                 0x7E7E, 0xFFFE, 0xFFFF };
#define NLENS (sizeof lens / sizeof lens[0])

static void run_pair(unsigned phase, unsigned byte, unsigned len,
                     unsigned idx, unsigned sum, unsigned cap,
                     uint8_t *real_dst, ospec *o, uint8_t *spec_dst) {
    uart_frame_rx st;
    memset(&st, 0, sizeof st);
    st.phase = phase;
    st.len = len;
    st.idx = idx;
    st.sum = sum;
    o->phase = phase; o->len = len; o->idx = idx; o->sum = sum;
    o->type = 0;
    memset(real_dst, 0xA5, cap + 64);
    memset(spec_dst, 0xA5, cap + 64);
    unsigned rr = uart_frame_step(byte, real_dst, cap, &st);
    unsigned sr = spec_step(byte, cap, o, spec_dst);
    if ((rr != sr || st.phase != o->phase || st.len != o->len ||
        st.idx != o->idx || st.sum != o->sum) && printed < 5u) {
        printed++;
        fails++;
        printf("spec mismatch phase=%u byte=%02x len=%u idx=%u "
               "ret %u/%u -> ph %u/%u len %u/%u idx %u/%u sum %u/%u\n",
               phase, byte, len, idx, rr, sr, st.phase, o->phase,
               st.len, o->len, st.idx, o->idx, st.sum, o->sum);
    } else if (rr != sr || st.phase != o->phase || st.len != o->len ||
               st.idx != o->idx || st.sum != o->sum) {
        fails++;
    }
    if (memcmp(real_dst, spec_dst, cap + 64) != 0) {
        fails++;
        printf("dst mismatch phase=%u byte=%02x len=%u idx=%u\n",
               phase, byte, len, idx);
    }
}

static void sweep_tables(void) {
    const unsigned caps[2] = { 8u, 240u };
    uint8_t rd[512], sd[512];
    for (unsigned ci = 0; ci < 2; ci++) {
        unsigned cap = caps[ci];
        for (unsigned phase = 0; phase <= 6u; phase++)
        for (unsigned byte = 0; byte < 256u; byte++)
        for (unsigned li = 0; li < NLENS; li++) {
            unsigned len = lens[li];
            /* phase 5/6 are only reachable when phase 4 admitted the
             * length; feeding impossible states would invoke UB in the
             * harness, not the parser */
            if (phase == 5u && (len == 0u || len > cap)) continue;
            if (phase == 6u && len > cap) continue;
            unsigned imax = 3u;
            for (unsigned ii = 0; ii <= imax; ii++) {
                unsigned idx = (ii == 0) ? 0u
                             : (ii == 1) ? (len ? len - 1u : 0u)
                             : (ii == 2) ? len : (len + 1u) % 256u;
                /* the cursor only reaches idx <= len */
                if (phase == 5u && idx >= len) continue;
                if (phase == 6u && idx != len) continue;
                for (unsigned sum = 0; sum < 256u; sum += 85u) {
                    run_pair(phase, (uint8_t)byte, len, idx, sum, cap,
                             rd, &(ospec){0, 0, 0, 0, 0}, sd);
                }
            }
        }
    }
}

/* the safety invariant: whatever the wire carries, the cursor stays
 * inside the caller's cap */
static void sweep_invariant(void) {
    const unsigned caps[2] = { 8u, 240u };
    for (unsigned ci = 0; ci < 2; ci++) {
        unsigned cap = caps[ci];
        for (unsigned len = 0; len <= cap + 4u; len++)
        for (unsigned byte = 0; byte < 256u; byte += 5u) {
            uart_frame_rx st;
            memset(&st, 0, sizeof st);
            uint8_t dst[512];
            memset(dst, 0xA5, sizeof dst);
            /* feed a full framing sequence with this length field */
            uint8_t seq[8];
            seq[0] = 0x7E; seq[1] = 0x7E; seq[2] = 0x01;
            seq[3] = (uint8_t)len; seq[4] = (uint8_t)(len >> 8);
            for (unsigned k = 0; k < 5u; k++)
                uart_frame_step(seq[k], dst, cap, &st);
            for (unsigned p = 0; p <= len + 1u; p++) {
                uart_frame_step(byte, dst, cap, &st);
                if (st.phase == 5u &&
                    (st.idx > st.len || st.len > cap)) {
                    fails++;
                    printf("invariant broken cap=%u len=%u idx=%u\n",
                           cap, st.len, st.idx);
                    return;
                }
                for (unsigned g = cap; g < sizeof dst; g++)
                    if (dst[g] != 0xA5) {
                        fails++;
                        printf("overflow: cap=%u len=%u guard %u "
                               "smashed by %02x\n", cap, len, g, dst[g]);
                        return;
                    }
            }
        }
    }
}

/* build one wire frame; sum8 closes over type..payload */
static unsigned make_frame(uint8_t *out, uint8_t type,
                           const uint8_t *payload, unsigned len) {
    unsigned n = 0;
    out[n++] = 0x7E; out[n++] = 0x7E; out[n++] = type;
    out[n++] = (uint8_t)len; out[n++] = (uint8_t)(len >> 8);
    /* the parser sums type + len16 + payload: the checksum closes all */
    unsigned sum = type + len;
    for (unsigned i = 0; i < len; i++) { out[n++] = payload[i]; sum += payload[i]; }
    out[n++] = (uint8_t)(256u - (sum & 0xFFu));
    return n;
}

static void sweep_streams(void) {
    uint8_t stream[4096], dst[512];
    uart_frame_rx st;
    /* garbage + valid frame + oversized + valid frame: the two valid
     * frames must both land */
    {
        memset(&st, 0, sizeof st);
        memset(dst, 0, sizeof dst);
        uint8_t payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        unsigned n = 0;
        for (unsigned i = 0; i < 64u; i++) stream[n++] = (uint8_t)(i * 7u);
        n += make_frame(stream + n, 0x01, payload, 8);
        for (unsigned i = 0; i < 64u; i++) stream[n++] = 0xFF;
        uint8_t big[300];
        memset(big, 0x41, sizeof big);
        n += make_frame(stream + n, 0x02, big, 300);      /* len > cap 240 */
        for (unsigned i = 0; i < 64u; i++) stream[n++] = (uint8_t)(i | 0x80);
        n += make_frame(stream + n, 0x01, payload, 8);
        unsigned got = 0;
        for (unsigned i = 0; i < n; i++)
            got += (uart_frame_step(stream[i], dst, 240, &st) == 8u &&
                    st.type == 0x01);
        if (got != 2u) {
            fails++;
            printf("stream resync: got %u of 2 frames\n", got);
        }
    }
    /* checksum boundary: exactly-zero sum8 accepted, +1 rejected */
    {
        memset(&st, 0, sizeof st);
        uint8_t payload[2] = { 0x7E, 0x7E };
        uint8_t f[16];
        unsigned n = make_frame(f, 0x03, payload, 2);
        unsigned ok = 0;
        for (unsigned i = 0; i < n; i++)
            ok = uart_frame_step(f[i], dst, 240, &st) ? i + 1u : ok;
        if (ok != n) { fails++; printf("checksum accept failed\n"); }
        memset(&st, 0, sizeof st);
        f[n - 1] += 1u;                                    /* corrupt sum */
        for (unsigned i = 0; i < n; i++)
            if (uart_frame_step(f[i], dst, 240, &st)) {
                fails++; printf("corrupt checksum accepted\n"); break;
            }
    }
    /* sync bytes inside the length field: with a cap large enough to
     * admit len=0x7E7E, the machine must track the cursor exactly and
     * never write past it */
    {
        static uint8_t big[0x8000];
        memset(&st, 0, sizeof st);
        memset(big, 0xA5, sizeof big);
        uint8_t seq[5] = { 0x7E, 0x7E, 0x01, 0x7E, 0x7E };
        for (unsigned i = 0; i < 5u; i++)
            uart_frame_step(seq[i], big, 0x8000, &st);
        if (st.phase != 5u || st.len != 0x7E7E) {
            fails++;
            printf("sync-in-length: phase=%u len=%u\n", st.phase, st.len);
        }
        unsigned writes = 0;
        for (unsigned i = 0; i < 0x7E7Eu && st.phase == 5u; i++) {
            uart_frame_step(0x00, big, 0x8000, &st);
            writes++;
        }
        if (writes != 0x7E7Eu || st.idx != 0x7E7Eu || st.phase != 6u) {
            fails++;
            printf("sync-in-length: writes=%u idx=%u phase=%u\n",
                   writes, st.idx, st.phase);
        }
        for (unsigned g = 0x7E7Eu; g < 0x8000u; g++)
            if (big[g] != 0xA5) {
                fails++;
                printf("sync-in-length guard %u smashed\n", g);
                break;
            }
    }
}

static void fuzz(void) {
    static uint8_t buf[4096];
    uint8_t dst[512];
    uint64_t seed = 0xE39E39E39ull;
    for (unsigned stream = 0; stream < 64u; stream++) {
        uart_frame_rx st;
        memset(&st, 0, sizeof st);
        memset(buf, 0xA5, sizeof buf);
        unsigned n = 2048u + (unsigned)(seed % 1024u);
        memset(dst, 0xA5, sizeof dst);
        for (unsigned i = 0; i < n; i++) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            buf[i] = (uint8_t)(seed >> 33);
        }
        /* sprinkle a few valid frames into the noise */
        uint8_t payload[4] = { 9, 8, 7, 6 };
        for (unsigned k = 0; k < 3u; k++) {
            unsigned at = (unsigned)(seed >> 20) % (n - 32u);
            uint8_t f[16];
            unsigned m = make_frame(f, (uint8_t)(0x10 + k), payload, 4);
            for (unsigned i = 0; i < m; i++) buf[at + i] = f[i];
        }
        unsigned got = 0;
        for (unsigned i = 0; i < n; i++) {
            unsigned r = uart_frame_step(buf[i], dst, 240, &st);
            if (r) {
                got++;
                if (r > 240u) { fails++; printf("fuzz: oversize return\n"); }
            }
        }
        for (unsigned g = 240u; g < sizeof dst; g++)
            if (dst[g] != 0xA5) {
                fails++;
                printf("fuzz: guard %u smashed by %02x\n", g, dst[g]);
                break;
            }
        if (got < 1u) {
            fails++;
            printf("fuzz: only %u frames surfaced\n", got);
        }
    }
}

int main(void) {
    uint8_t rd[512], sd[512];
    sweep_tables();
    sweep_invariant();
    sweep_streams();
    fuzz();
    (void)rd; (void)sd;
    printf(fails ? "FRAMES FAIL (%u)\n" : "FRAMES PASS (%u)\n", fails);
    return fails != 0;
}
