#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../core/update.h"

void sha256(const uint8_t *, uint32_t, uint8_t *);

static unsigned fails;
static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static unsigned make(uint8_t *p, uint8_t op, uint32_t id,
                     uint16_t seq, uint16_t off, const uint8_t *data,
                     uint8_t len) {
    unsigned n = 0;
    p[n++] = op; put32(p + n, id); n += 4;
    if (op == UPDATE_OP_BEGIN) {
        put16(p + n, (uint16_t)off); n += 2;
        memcpy(p + n, data, 32); n += 32;
    } else if (op == UPDATE_OP_DATA) {
        put16(p + n, seq); n += 2; put16(p + n, off); n += 2;
        p[n++] = len; memcpy(p + n, data, len); n += len;
    }
    {
        uint16_t crc = update_crc16(p, n);
        p[n++] = crc; p[n++] = crc >> 8;
    }
    return n;
}
static void check(const char *name, int ok) {
    printf("%-28s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

int main(void) {
    uint8_t image[96], stage[512], p[96], digest[32];
    volatile uint32_t magic = 0;
    update_rx rx = {0};
    update_reply r;
    uint32_t id = 0x12345678u;
    unsigned n;
    memset(image, 0, sizeof image);
    put32(image, 7u); put32(image + 4, 1u);
    for (unsigned i = 8; i < 64; i++) image[i] = (uint8_t)(i * 3u);
    sha256(image, 64, image + 64);
    sha256(image, sizeof image, digest);
    n = make(p, UPDATE_OP_BEGIN, id, 0, sizeof image, digest, 0);
    check("begin accepted", update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_ACK && rx.total == sizeof image);
    for (unsigned off = 0, seq = 0; off < sizeof image; off += 32, seq++) {
        n = make(p, UPDATE_OP_DATA, id, seq, off, image + off, 32);
        check("data ack", update_process(&rx, p, n, stage, &magic, &r) &&
              r.code == UPDATE_ACK && r.next_seq == seq + 1);
        if (seq == 1u) {
            check("duplicate idempotent", update_process(&rx, p, n, stage,
                  &magic, &r) && r.code == UPDATE_ACK && r.next_seq == 2);
        }
    }
    n = make(p, UPDATE_OP_COMMIT, id, 0, 0, 0, 0);
    check("commit stages", update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_REPLY_STAGED && magic == UPDATE_PEND_MAGIC);
    check("stage byte exact", !memcmp(stage, image, sizeof image));

    update_reset(&rx); magic = 0;
    n = make(p, UPDATE_OP_BEGIN, id, 0, sizeof image, digest, 0);
    update_process(&rx, p, n, stage, &magic, &r);
    n = make(p, UPDATE_OP_DATA, id, 1, 32, image + 32, 32);
    check("out of order rejected", !update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_NACK && r.detail == UPDATE_ERR_SEQUENCE && magic == 0);
    n = make(p, UPDATE_OP_DATA, id, 0, 0, image, 32);
    update_process(&rx, p, n, stage, &magic, &r);
    p[10] ^= 1u;
    check("bad crc rejected", !update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_NACK && r.detail == UPDATE_ERR_CRC);
    n = make(p, UPDATE_OP_COMMIT, id, 0, 0, 0, 0);
    check("missing chunks rejected", !update_process(&rx, p, n, stage, &magic, &r) &&
          r.detail == UPDATE_ERR_SEQUENCE && magic == 0);

    /* retransmitted BEGIN during ACTIVE must not rewind progress */
    n = make(p, UPDATE_OP_BEGIN, id, 0, sizeof image, digest, 0);
    check("begin retransmit keeps progress",
          update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_ACK && r.next_seq == rx.next_seq && rx.received == 32);
    n = make(p, UPDATE_OP_BEGIN, 0x99999999u, 0, sizeof image, digest, 0);
    check("new id while active is busy",
          !update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_NACK && r.detail == UPDATE_ERR_BUSY);

    /* abort discards the transaction and the staging magic */
    n = make(p, UPDATE_OP_ABORT, id, 0, 0, 0, 0);
    check("abort clears transaction",
          update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_ABORTED && magic == 0 &&
          rx.state == UPDATE_STATE_IDLE);
    n = make(p, UPDATE_OP_DATA, id, 0, 0, image, 32);
    check("data after abort rejected",
          !update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_NACK && r.detail == UPDATE_ERR_ID);

    /* complete transfer, then simulate the gate verdict twice */
    n = make(p, UPDATE_OP_BEGIN, id, 0, sizeof image, digest, 0);
    update_process(&rx, p, n, stage, &magic, &r);
    for (unsigned off = 0, seq = 0; off < sizeof image; off += 32, seq++) {
        n = make(p, UPDATE_OP_DATA, id, seq, off, image + off, 32);
        update_process(&rx, p, n, stage, &magic, &r);
    }
    n = make(p, UPDATE_OP_COMMIT, id, 0, 0, 0, 0);
    check("commit before verdict",
          update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_REPLY_STAGED);
    update_finish(&rx, 1);
    check("duplicate commit returns verdict once",
          update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_ACCEPT && rx.state == UPDATE_STATE_DONE);
    check("rejected verdict state", rx.final_code == UPDATE_ACCEPT);
    update_finish(&rx, 1);
    check("second finalize is a no-op for state", rx.state == UPDATE_STATE_DONE);

    /* wrong image hash: complete bytes, bad expected digest */
    update_reset(&rx); magic = 0;
    memset(digest, 0xA5, sizeof digest);
    n = make(p, UPDATE_OP_BEGIN, id, 0, sizeof image, digest, 0);
    update_process(&rx, p, n, stage, &magic, &r);
    for (unsigned off = 0, seq = 0; off < sizeof image; off += 32, seq++) {
        n = make(p, UPDATE_OP_DATA, id, seq, off, image + off, 32);
        update_process(&rx, p, n, stage, &magic, &r);
    }
    n = make(p, UPDATE_OP_COMMIT, id, 0, 0, 0, 0);
    check("bad overall hash rejected",
          !update_process(&rx, p, n, stage, &magic, &r) &&
          r.code == UPDATE_NACK && r.detail == UPDATE_ERR_HASH && magic == 0);

    /* size limits */
    n = make(p, UPDATE_OP_BEGIN, id, 0, 40, digest, 0);
    check("too small rejected", !update_process(&rx, p, n, stage, &magic, &r) &&
          r.detail == UPDATE_ERR_FORMAT);
    n = make(p, UPDATE_OP_BEGIN, id, 0, 553, digest, 0);
    check("too large rejected", !update_process(&rx, p, n, stage, &magic, &r) &&
          r.detail == UPDATE_ERR_FORMAT && magic == 0);
    n = make(p, UPDATE_OP_BEGIN, id, 0, 552, digest, 0);
    check("max image accepted", update_process(&rx, p, n, stage, &magic, &r) &&
          magic == 0);

    puts(fails ? "UPDATE FAIL" : "UPDATE PASS");
    return fails != 0;
}
