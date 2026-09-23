/* loader.h — core-internal gate surface. Modules see contract.h only;
 * this header is for the supervisor and the host tests. */

#ifndef INTERCLUS_LOADER_H
#define INTERCLUS_LOADER_H

#include "contract.h"

/* transport cap for a loaded program; matches the monitor slot */
#define IC_PROG_MAX_INSNS 64u

/* Static preflight for a program about to run on the interpreter: length,
 * known opcodes, register range, in-bounds jumps, known helpers. Shape
 * checks only, no register typing; memory safety stays at run time. */
ic_status ic_program_check(const uint64_t *ins, uint32_t cnt);

#endif
