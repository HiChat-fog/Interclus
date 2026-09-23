/* rate_limit.h: example module for docs/add-a-policy.md. Counts frames per
 * msgid class in the map grid (cell = msgid & 63). Frames 1..3 per class
 * pass (verdict 1); past that the class alerts (verdict 5) and stays
 * alerted until the host clears the map, same window model as screening. */

#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <stdint.h>
#include "../../core/ebpf_asm.h"
#include "../../core/contract.h"

static const uint64_t RATE_LIMIT[] = {
    LDXB(2, 1, 7),        /* r2 = msgid byte 0 */
    LDXB(3, 1, 8),
    SLL64I(3, 8),
    OR64(2, 3),
    LDXB(3, 1, 9),
    SLL64I(3, 16),
    OR64(2, 3),           /* r2 = 24-bit msgid */
    AND64I(2, 63),        /* r2 = grid cell */
    MOV64(1, 2),
    CALL(1),              /* r0 = map[cell] (frames seen so far) */
    ADD64I(0, 1),
    MOV64(6, 0),          /* r6 = count */
    MOV64(1, 2),
    MOV64(2, 6),
    CALL(2),              /* map[cell] = count */
    JGT64I(6, 3, 2),      /* count > 3 -> alert */
    MOV64I(0, 1),         /* pass */
    EXIT(),
    MOV64I(0, 5),         /* alert */
    EXIT(),
};
#define RATE_LIMIT_CNT 20
#define RATE_LIMIT_MAP_CELLS 64u

static const ic_module_desc ic_module_rate_limit __attribute__((unused)) = {
    IC_MODULE_MAGIC, IC_CONTRACT_VERSION, IC_MODULE_EBPF,
    0u, (uint32_t)sizeof(RATE_LIMIT),
    0u, RATE_LIMIT_MAP_CELLS * 4u, 0u, 0u
};

#endif
