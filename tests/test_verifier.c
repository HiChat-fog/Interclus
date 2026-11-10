/* host tests for the region-aware verifier gate: helper permissions derive
 * from the VRT-backed region (R for map load, W for map store), and the
 * region bound replaces the legacy map_cells mask. Build:
 *   gcc -O2 -ffreestanding -o test_verifier tests/test_verifier.c core/loader.c */

#include <stdio.h>
#include "../core/contract.h"
#include "../core/loader.h"
#include "../core/ebpf_asm.h"

static int fails;

#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); fails++; } } while (0)

static const ic_region rw   = { 0x80216000u, 64u, IC_REGION_R | IC_REGION_W };
static const ic_region ro   = { 0x80216000u, 64u, IC_REGION_R };
static const ic_region wo   = { 0x80216000u, 64u, IC_REGION_W };

static const uint64_t load_only[]  = { MOV64I(1, 0), CALL(1), MOV64I(0, 0), EXIT() };
static const uint64_t store_only[] = { MOV64I(1, 0), MOV64I(2, 7), CALL(2), EXIT() };
static const uint64_t both[]       = { MOV64I(1, 0), MOV64I(2, 7), CALL(1), CALL(2), EXIT() };
static const uint64_t bogus[]      = { MOV64I(1, 0), CALL(3), EXIT() };

int main(void) {
    CHECK(ic_program_check_region(load_only, 4, &rw) == IC_OK);
    CHECK(ic_program_check_region(store_only, 4, &rw) == IC_OK);
    CHECK(ic_program_check_region(both, 5, &rw) == IC_OK);

    CHECK(ic_program_check_region(store_only, 4, &ro) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_region(load_only, 4, &wo) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_region(both, 5, &ro) == IC_ERR_VALIDATE);

    CHECK(ic_program_check_region(both, 5, 0) == IC_ERR_ARGUMENT);
    {
        const ic_region bad_cells = { 0x80216000u, 63u, IC_REGION_R | IC_REGION_W };
        CHECK(ic_program_check_region(both, 5, &bad_cells) == IC_ERR_ARGUMENT);
    }
    {
        const ic_region bad_perms = { 0x80216000u, 64u, 8u };
        CHECK(ic_program_check_region(both, 4, &bad_perms) == IC_ERR_ARGUMENT);
    }
    CHECK(ic_program_check_region(bogus, 3, &rw) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(load_only, 4) == IC_OK);          /* legacy path intact */
    CHECK(ic_program_check_region(load_only, 4, &rw) == IC_OK);

    printf(fails ? "VERIFIER HOST FAIL (%d)\n" : "VERIFIER HOST PASS\n", fails);
    return fails ? 1 : 0;
}
