#include "update.h"

void sha256(const uint8_t *data, uint32_t len, uint8_t out[32]);

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int crc_ok(const uint8_t *p, unsigned n) {
    return update_crc16(p, n - 2u) == le16(p + n - 2u);
}

static void reply_set(update_rx *rx, update_reply *r, uint8_t code,
                      uint8_t detail, uint32_t id) {
    r->id = id ? id : rx->id;
    r->next_seq = rx->next_seq;
    r->code = code;
    r->detail = detail;
}

void update_reset(update_rx *rx) {
    volatile uint8_t *p = (volatile uint8_t *)rx;
    for (unsigned i = 0; i < sizeof(*rx); i++) p[i] = 0;
}

uint16_t update_crc16(const uint8_t *data, uint32_t len) {
    uint16_t crc = 0xFFFFu;
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned b = 0; b < 8u; b++)
            crc = (crc & 1u) ? (uint16_t)((crc >> 1) ^ 0xA001u)
                             : (uint16_t)(crc >> 1);
    }
    return crc;
}

int update_process(update_rx *rx, const uint8_t *p, unsigned n,
                   volatile uint8_t *pend, volatile uint32_t *pend_magic,
                   update_reply *r) {
    uint8_t op = n ? p[0] : 0u;
    uint32_t id = n >= 5u ? le32(p + 1) : 0u;

    if (!n) {
        reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, 0u);
        return 0;
    }
    if (op == UPDATE_OP_BEGIN) {
        uint16_t total;
        if (n != 41u) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        if (!crc_ok(p, n)) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_CRC, id);
            return 0;
        }
        total = le16(p + 5);
        if (!id || total < 48u || total > UPDATE_MAX_IMAGE) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        /* BEGIN is retransmittable at every transaction boundary.  A
         * byte-for-byte repeat never restarts an in-flight or staged image;
         * a different image id is rejected while either owns the PEND slot. */
        if ((rx->state == UPDATE_STATE_ACTIVE ||
             rx->state == UPDATE_STATE_STAGED ||
             rx->state == UPDATE_STATE_DONE) && rx->id == id) {
            if (rx->total != total) {
                reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_ID, id);
                return 0;
            }
            for (unsigned i = 0; i < 32u; i++) {
                if (rx->expected_sha[i] != p[7u + i]) {
                    reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_ID, id);
                    return 0;
                }
            }
            if (rx->state == UPDATE_STATE_DONE)
                reply_set(rx, r, rx->final_code, 0u, id);
            else if (rx->state == UPDATE_STATE_STAGED)
                reply_set(rx, r, UPDATE_REPLY_STAGED, 0u, id);
            else
                reply_set(rx, r, UPDATE_ACK, 0u, id);
            return 1;
        }
        if (rx->state == UPDATE_STATE_ACTIVE ||
            rx->state == UPDATE_STATE_STAGED || *pend_magic == UPDATE_PEND_MAGIC) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_BUSY, id);
            return 0;
        }
        update_reset(rx);
        rx->id = id;
        rx->total = total;
        for (unsigned i = 0; i < 32u; i++) rx->expected_sha[i] = p[7u + i];
        rx->state = UPDATE_STATE_ACTIVE;
        *pend_magic = 0u;
        reply_set(rx, r, UPDATE_ACK, 0u, id);
        return 1;
    }
    if (n < 7u) {
        reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
        return 0;
    }
    if (!crc_ok(p, n)) {
        reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_CRC, id);
        return 0;
    }
    if (rx->state == UPDATE_STATE_IDLE || id != rx->id) {
        reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_ID, id);
        return 0;
    }
    if (op == UPDATE_OP_DATA) {
        uint16_t seq, off;
        uint8_t len;
        if (n < 12u) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        seq = le16(p + 5);
        off = le16(p + 7);
        len = p[9];
        if (!len || len > UPDATE_MAX_CHUNK || n != 12u + len ||
            (uint32_t)off + len > rx->total) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        if (rx->state != UPDATE_STATE_ACTIVE) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_STATE, id);
            return 0;
        }
        if (seq + 1u == rx->next_seq && (uint32_t)off + len == rx->received) {
            for (unsigned i = 0; i < len; i++) {
                if (pend[off + i] != p[10u + i]) {
                    reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_SEQUENCE, id);
                    return 0;
                }
            }
            reply_set(rx, r, UPDATE_ACK, 0u, id);
            return 1;
        }
        if (seq != rx->next_seq || off != rx->received) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_SEQUENCE, id);
            return 0;
        }
        for (unsigned i = 0; i < len; i++) pend[off + i] = p[10u + i];
        rx->received = (uint16_t)(rx->received + len);
        rx->next_seq++;
        reply_set(rx, r, UPDATE_ACK, 0u, id);
        return 1;
    }
    if (op == UPDATE_OP_COMMIT) {
        uint8_t digest[32];
        if (n != 7u) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        if (rx->state == UPDATE_STATE_DONE) {
            reply_set(rx, r, rx->final_code, 0u, id);
            return 1;
        }
        if (rx->state == UPDATE_STATE_STAGED) {
            reply_set(rx, r, UPDATE_REPLY_STAGED, 0u, id);
            return 1;
        }
        if (rx->state != UPDATE_STATE_ACTIVE) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_STATE, id);
            return 0;
        }
        if (rx->received != rx->total) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_SEQUENCE, id);
            return 0;
        }
        sha256((const uint8_t *)pend, rx->total, digest);
        for (unsigned i = 0; i < 32u; i++) {
            if (digest[i] != rx->expected_sha[i]) {
                rx->state = UPDATE_STATE_IDLE;
                reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_HASH, id);
                return 0;
            }
        }
        *pend_magic = UPDATE_PEND_MAGIC;
        rx->state = UPDATE_STATE_STAGED;
        reply_set(rx, r, UPDATE_REPLY_STAGED, 0u, id);
        return 1;
    }
    if (op == UPDATE_OP_ABORT) {
        if (n != 7u) {
            reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
            return 0;
        }
        if (rx->state == UPDATE_STATE_ACTIVE) {
            *pend_magic = 0u;
            rx->state = UPDATE_STATE_IDLE;
            rx->received = 0u;
            rx->next_seq = 0u;
            reply_set(rx, r, UPDATE_ABORTED, 0u, id);
            return 1;
        }
        reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_STATE, id);
        return 0;
    }
    reply_set(rx, r, UPDATE_NACK, UPDATE_ERR_FORMAT, id);
    return 0;
}

void update_finish(update_rx *rx, int accepted) {
    rx->final_code = accepted ? UPDATE_ACCEPT : UPDATE_REJECT;
    rx->state = UPDATE_STATE_DONE;
}
