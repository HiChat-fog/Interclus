/* Minimal module example: a filter policy that accepts every frame with a
 * valid MAVLink v2 start byte, no whitelist. Seven instructions, no core
 * edits — this file plus a test case is the whole module cost.
 * A real policy adds checks: see modules/policies/mavlink.h. */

#include <stdint.h>
#include "../../core/ebpf_asm.h"
#include "../../core/contract.h"

const uint64_t pass_all_ins[] = {
    LDXB(0, 1, 0),        /* r0 = ctx[0] (start byte); ctx arrives in r1 */
    MOV64I(1, 0xFD),
    JEQ64(0, 1, 2),         /* equal -> skip the reject insn (off is relative to next) */
    MOV64I(0, 0),         /* reject: retval 0 */
    EXIT(),
    MOV64I(0, 1),         /* accept: retval 1 */
    EXIT(),
};
const unsigned pass_all_cnt = sizeof(pass_all_ins) / sizeof(pass_all_ins[0]);

/* every module ships one of these; the loader gate runs it before first use.
 * text_base stays zero: the linked address is not the author's to declare */
static const ic_module_desc ic_module_pass_all __attribute__((unused)) = {
    IC_MODULE_MAGIC, IC_CONTRACT_VERSION, IC_MODULE_EBPF,
    0u, (uint32_t)sizeof(pass_all_ins),
    0u, 0u, 0u, 0u
};
