/* layout_asserts.h — compile-time pins for every cross-file layout
 * contract the audits and drills hand-compute. A struct field move, an
 * index drift, or a constant divergence breaks the build here instead
 * of silently desyncing a debugger-side consumer. */

#ifndef LAYOUT_ASSERTS_H
#define LAYOUT_ASSERTS_H

#include "contract.h"
#include "ebpf.h"
#include "loader.h"
#include "platform.h"

/* the guarded STATUS window must cover every named field: the wire
 * telemetry (FRAME_STATUS) walks exactly STATUS_WORDS words, and a
 * truncated window once hid S_TXABORT/S_HALT/S_NSLOT from operators */
_Static_assert(S_FUZZR + 1u <= STATUS_WORDS, "STATUS window truncates a named field");
_Static_assert(STATUS_WORDS == 106u, "STATUS window size drifted");

/* the loader and the interpreter must agree on the program bound */
_Static_assert(IC_PROG_MAX_INSNS == EBPF_MAX_INSNS, "program bound diverges");

/* the interpreter's map helpers index with (cells - 1) masks */
_Static_assert((MAP_CELLS & (MAP_CELLS - 1u)) == 0u && MAP_CELLS != 0u,
               "MAP_CELLS must be a power of two");

/* PEND staging: the trust digest can never reach the magic word */
_Static_assert(8u + IC_PROG_MAX_INSNS * 8u + 32u < PROG_PEND_MAGIC_OFF,
               "staged body overruns the PEND magic word");

/* the wire frame types are a stable operator contract */
#if FRAME_UPDATE != 4u || FRAME_UPDATE_REPLY != 0xCu
#error "update frame types drifted"
#endif

/* the four-gate kinds are a module-visible contract */
_Static_assert(IC_MODULE_EBPF == 1u && IC_MODULE_NATIVE == 2u,
               "module kinds drifted");

#endif
