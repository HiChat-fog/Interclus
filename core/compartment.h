/* compartment.h: the time-multiplexed PMP compartment table (contract v1).
 * Mechanism only; the supervisor wires specs and decides the schedule.
 * The table lives in the pinned .comp_state section, zeroed by startup. */

#ifndef INTERCLUS_COMPARTMENT_H
#define INTERCLUS_COMPARTMENT_H

#include "contract.h"

void compartment_set(unsigned i, const ic_compartment_spec *spec,
                     uint32_t entry);
void compartment_arm(unsigned i);
void compartment_enter(unsigned i) __attribute__((noreturn));

#endif
