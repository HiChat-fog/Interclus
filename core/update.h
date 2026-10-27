#ifndef INTERCLUS_UPDATE_H
#define INTERCLUS_UPDATE_H

#include <stdint.h>

#define UPDATE_MAX_IMAGE 480u
#define UPDATE_MAX_CHUNK 64u
#define UPDATE_FRAME_TIMEOUT 200000u
#define UPDATE_FRAME 0x4u
#define UPDATE_REPLY_FRAME 0xCu
#define UPDATE_OP_BEGIN 0x1u
#define UPDATE_OP_DATA 0x2u
#define UPDATE_OP_COMMIT 0x3u
#define UPDATE_OP_ABORT 0x4u
#define UPDATE_ACK 0x80u
#define UPDATE_NACK 0x81u
#define UPDATE_REPLY_STAGED 0x82u
#define UPDATE_ACCEPT 0x83u
#define UPDATE_REJECT 0x84u
#define UPDATE_ABORTED 0x85u
#define UPDATE_ERR_FORMAT 1u
#define UPDATE_ERR_CRC 2u
#define UPDATE_ERR_SEQUENCE 3u
#define UPDATE_ERR_BUSY 4u
#define UPDATE_ERR_HASH 5u
#define UPDATE_ERR_STATE 6u
#define UPDATE_ERR_ID 7u
#define UPDATE_PEND_MAGIC 0x444E4550u
#define UPDATE_STATE_IDLE 0u
#define UPDATE_STATE_ACTIVE 1u
#define UPDATE_STATE_STAGED 2u
#define UPDATE_STATE_DONE 3u

typedef struct {
    uint32_t id;
    uint16_t total;
    uint16_t received;
    uint16_t next_seq;
    uint8_t expected_sha[32];
    uint8_t state;
    uint8_t final_code;
} update_rx;

typedef struct {
    uint32_t id;
    uint16_t next_seq;
    uint8_t code;
    uint8_t detail;
} update_reply;

void update_reset(update_rx *rx);
uint16_t update_crc16(const uint8_t *data, uint32_t len);
int update_process(update_rx *rx, const uint8_t *payload, unsigned len,
                   volatile uint8_t *pend,
                   volatile uint32_t *pend_magic,
                   update_reply *reply);
void update_finish(update_rx *rx, int accepted);

#endif
