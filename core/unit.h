#ifndef INTERCLUS_UNIT_H
#define INTERCLUS_UNIT_H

#include <stdint.h>
#include "contract.h"

#define IC_UNIT_ABI 1u

#define IC_UNIT_MODE_MAVLINK 0u
#define IC_UNIT_MODE_SCREEN  1u
#define IC_UNIT_MODE_NATIVE  2u

/* LecsOS scheduler syscall numbers; 0 stays the legacy yield. */
#define IC_SYS_EXIT   0u
#define IC_SYS_SEND   2u
#define IC_SYS_RECV   3u
#define IC_SYS_YIELD  4u
#define IC_SYS_KILL   6u
#define IC_SYS_DEVMAP 7u

static inline void ic_unit_yield(void) {
    __asm__ volatile ("li a7, 4\n\tecall" ::: "a7", "memory");
}

/* One context for every Interclus workload. The host owns placement and
 * fills the pointers; a unit never computes a fixed address on its own. */
typedef struct {
    uint32_t abi;
    volatile uint32_t *mode;

    const volatile uint8_t  *pkts;
    const volatile uint32_t *off, *len;
    uint32_t npkt;

    volatile uint32_t *map;
    uint32_t map_cells;
    ic_region region;

    const volatile uint8_t  *swarm;
    const volatile uint32_t *soff, *ssiz;
    const volatile uint32_t *swarm_n;

    volatile uint32_t *screen_verd, *screen_insns;
    volatile uint32_t *mav_verd, *mav_insns, *mav_fault;
    volatile uint32_t *nverd, *diag;

    const volatile uint64_t *prog;
    const volatile uint32_t *prog_cnt;

    volatile uint32_t *own, *proof;
    uint32_t mon_results, mon_input, mon_flash, sp_poison;
} ic_unit_ctx;

#endif
