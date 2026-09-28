/* compartment.h: the time-multiplexed PMP compartment table (contract v1).
 * Mechanism only; the supervisor wires specs and decides the schedule.
 * The table lives in the pinned .comp_state section, zeroed by startup.
 *
 * Lifetime model (contract v1.1): compartment_set instantiates a fresh
 * lifetime (clean TCB, unmarked); a faulting compartment is evicted by
 * the supervisor via compartment_evict — its frame is kept in the TCB as
 * evidence, its live registers were wiped by the trap path, and it is
 * never scheduled again. Entering an evicted compartment parks the core. */

#ifndef INTERCLUS_COMPARTMENT_H
#define INTERCLUS_COMPARTMENT_H

#include "contract.h"

extern volatile uint32_t cur_tcb;   /* TCB of the running compartment (trap.S) */
extern volatile uint32_t cur_comp;  /* index of the running compartment */

void compartment_set(unsigned i, const ic_compartment_spec *spec,
                     uint32_t entry);
void compartment_arm(unsigned i);
void compartment_evict(unsigned i);
unsigned compartment_evicted(unsigned i);
void compartment_enter(unsigned i) __attribute__((noreturn));

#endif
