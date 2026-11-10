#ifndef ICP_H
#define ICP_H

#include <stdint.h>
#include <stddef.h>

#define IC_DOM_MAX  4u
#define IC_PINS     2u
#define IC_VRT_MAX  8u

#define ICP_R 1u
#define ICP_W 2u
#define ICP_X 4u

typedef enum { ICP_LOAD = 0, ICP_STORE = 1, ICP_FETCH = 2 } icp_op;
typedef enum { ICP_RETRY = 0, ICP_VIOLATION = 1 } icp_action;

typedef struct { uint32_t base, size, perms, paddr; } icp_row;

typedef struct {
    uint32_t n, lock;
    icp_row row[IC_VRT_MAX];
} icp_vrt;

typedef struct {
    icp_vrt vrt;
    uint32_t swaps, switches, cfg0;
} icp_state;

void icp_init(icp_state *s);
int icp_mount(icp_state *s, uint32_t base, uint32_t size, uint32_t perms);
void icp_lock(icp_state *s);
int icp_cover(const icp_state *s, uint32_t addr);
void icp_arm(icp_state *s);
icp_action icp_on_fault(uint32_t addr, icp_op op);

extern icp_state *icp_cur;

void icp_port_pair(const icp_state *s);
void icp_port_swap(const icp_row *r, uint32_t cfg);

uint32_t icp_napot(uint32_t base, uint32_t size);

#define ICP_VRT_N    0u
#define ICP_VRT_LOCK 4u
#define ICP_VRT_ROWS 8u
#define ICP_ROW_SZ   16u
#define ICP_ROW_BASE 0u
#define ICP_ROW_SIZE 4u
#define ICP_ROW_PERM 8u
#define ICP_ROW_PADD 12u
#define ICP_ST_SWAPS ((unsigned)offsetof(icp_state, swaps))
#define ICP_ST_CFG0  ((unsigned)offsetof(icp_state, cfg0))

_Static_assert(sizeof(icp_row) == ICP_ROW_SZ, "row layout");
_Static_assert(offsetof(icp_state, vrt) == 0u, "vrt first");
_Static_assert(offsetof(icp_state, swaps) == sizeof(icp_vrt), "swaps offset");
_Static_assert(offsetof(icp_state, cfg0) == sizeof(icp_vrt) + 8u, "cfg0 offset");

#endif
