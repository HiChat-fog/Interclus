/* Minimal module example: a filter policy that accepts every frame with a
 * valid MAVLink v2 start byte, no whitelist. Two instructions, zero core
 * edits — this file plus a test case is the whole extension cost.
 * A real policy adds checks: see modules/policies/mavlink.h. */

#include "../../core/ebpf_asm.h"

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
