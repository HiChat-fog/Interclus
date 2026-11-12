/* loader.h — core-internal gate surface. Modules see contract.h only;
 * this header is for the supervisor and the host tests. */

#ifndef INTERCLUS_LOADER_H
#define INTERCLUS_LOADER_H

#include "contract.h"

/* transport cap for a loaded program; matches the monitor slot */
#define IC_PROG_MAX_INSNS 64u

/* Static preflight: length, opcodes, registers, jumps, helpers, typed
 * interval dataflow, bounded-loop proof. ctx_size > 0 additionally proves
 * every LDX offset against it; region != NULL gates helper permissions. */
ic_status ic_program_check(const uint64_t *ins, uint32_t cnt);
ic_status ic_program_check_ctx(const uint64_t *ins, uint32_t cnt,
                               uint32_t ctx_size, const ic_region *region);

/* Verifier workspace: 64 PCs x (type word + two 11-entry intervals) plus
 * the pending/seen bytes. A host with a small task stack keeps it in a
 * granted page and passes it in; the self host uses a stack instance. */
#define IC_VFY_WS_BYTES (IC_PROG_MAX_INSNS * 92u + 2u * IC_PROG_MAX_INSNS)
typedef union {
    uint32_t w[IC_VFY_WS_BYTES / 4u];
    uint8_t  b[IC_VFY_WS_BYTES];
} ic_vfy_ws;

ic_status ic_program_check_ws(const uint64_t *ins, uint32_t cnt,
                              uint32_t ctx_size, const ic_region *region,
                              ic_vfy_ws *ws);

#endif
