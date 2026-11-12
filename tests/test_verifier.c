/* host tests for the region/range verifier: helper permissions, typed
 * intervals, static ctx bounds, and the bounded-loop proof. Build:
 *   gcc -O2 -ffreestanding -o test_verifier tests/test_verifier.c core/loader.c */

#include <stdio.h>
#include "../core/contract.h"
#include "../core/loader.h"
#include "../core/ebpf_asm.h"
#include "../modules/policies/mavlink.h"
#include "../modules/policies/screening.h"

#define LDXDW(d, s, o)  EBPF_ENC(0x79, d, s, o, 0)
#define SUB64(d, s)     EBPF_ENC(0x1f, d, s, 0, 0)
#define JLT64I(d, i, o) EBPF_ENC(0xa5, d, 0, o, i)
#define JLE64I(d, i, o) EBPF_ENC(0xb5, d, 0, o, i)
#define JA(o)           EBPF_ENC(0x05, 0, 0, o, 0)

static int fails;

#define CHECK(c) do { if (!(c)) { printf("FAIL %d: %s\n", __LINE__, #c); fails++; } } while (0)

static const ic_region rw   = { 0x80216000u, 64u, IC_REGION_R | IC_REGION_W };
static const ic_region ro   = { 0x80216000u, 64u, IC_REGION_R };
static const ic_region wo   = { 0x80216000u, 64u, IC_REGION_W };

static const uint64_t load_only[]  = { MOV64I(1, 0), CALL(1), MOV64I(0, 0), EXIT() };
static const uint64_t store_only[] = { MOV64I(1, 0), MOV64I(2, 7), CALL(2), EXIT() };
static const uint64_t both[]       = { MOV64I(1, 0), MOV64I(2, 7), CALL(1), CALL(2), EXIT() };
static const uint64_t bogus[]      = { MOV64I(1, 0), CALL(3), EXIT() };

/* one byte past the end is still past the end */
static const uint64_t ld_b15[] = { LDXB(0, 1, 15), EXIT() };
static const uint64_t ld_b16[] = { LDXB(0, 1, 16), EXIT() };
static const uint64_t ld_w12[] = { LDXW(0, 1, 12), EXIT() };
static const uint64_t ld_w13[] = { LDXW(0, 1, 13), EXIT() };
static const uint64_t ld_d8[]  = { LDXDW(0, 1, 8), EXIT() };
static const uint64_t ld_d9[]  = { LDXDW(0, 1, 9), EXIT() };
static const uint64_t ld_h15[] = { LDXH(0, 1, 15), EXIT() };
static const uint64_t ld_neg[] = { LDXB(0, 1, -1), EXIT() };
static const uint64_t ld_far[] = { LDXB(0, 1, 32767), EXIT() };

/* decreasing counter, constant bound */
static const uint64_t loop_ok[] = {
    MOV64I(2, 3),
    JLE64I(2, 0, 2),
    SUB64I(2, 1),
    JA(-3),
    MOV64I(0, 1), EXIT()
};
static const uint64_t loop_jlt[] = {
    MOV64I(2, 5),
    JLT64I(2, 2, 2),
    SUB64I(2, 1),
    JA(-3),
    MOV64I(0, 1), EXIT()
};
static const uint64_t loop_self[] = {
    MOV64I(0, 0), JA(-1), EXIT()
};
static const uint64_t loop_noexit[] = {
    MOV64I(2, 3),
    SUB64I(2, 1),
    JA(-2),
    MOV64I(0, 0), EXIT()
};
static const uint64_t loop_regstep[] = {
    MOV64I(2, 3), MOV64I(3, 1),
    JLE64I(2, 0, 2),
    SUB64(2, 3),
    JA(-4),
    MOV64I(0, 1), EXIT()
};
static const uint64_t loop_twowrite[] = {
    MOV64I(2, 3),
    JLE64I(2, 0, 3),
    SUB64I(2, 1),
    MOV64I(2, 1),
    JA(-4),
    MOV64I(0, 1), EXIT()
};
static const uint64_t loop_jeq[] = {
    MOV64I(2, 3),
    JEQ64I(2, 0, 2),
    SUB64I(2, 2),
    JA(-3),
    MOV64I(0, 1), EXIT()
};
static const uint64_t loop_unknown[] = {
    LDXW(2, 1, 0),
    JLE64I(2, 0, 2),
    SUB64I(2, 1),
    JA(-3),
    MOV64I(0, 1), EXIT()
};

int main(void) {
    /* region gate: helper permissions from the mounted row */
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
        CHECK(ic_program_check_region(both, 5, &bad_perms) == IC_ERR_ARGUMENT);
    }
    CHECK(ic_program_check_region(bogus, 3, &rw) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(load_only, 4) == IC_OK);

    /* ctx bounds: every LDX offset must fit inside the declared context */
    CHECK(ic_program_check_ctx(ld_b15, 2, 16u, 0) == IC_OK);
    CHECK(ic_program_check_ctx(ld_b16, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_w12, 2, 16u, 0) == IC_OK);
    CHECK(ic_program_check_ctx(ld_w13, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_d8, 2, 16u, 0) == IC_OK);
    CHECK(ic_program_check_ctx(ld_d9, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_h15, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_neg, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_far, 2, 16u, 0) == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(ld_far, 2, 0u, 0) == IC_OK);         /* legacy: no floor */

    /* the real policies at their exact boundary */
    CHECK(ic_program_check_ctx(POLICY_MAVLINK, POLICY_MAVLINK_CNT, 14u, 0) == IC_OK);
    CHECK(ic_program_check_ctx(POLICY_MAVLINK, POLICY_MAVLINK_CNT, 13u, 0)
          == IC_ERR_VALIDATE);
    CHECK(ic_program_check_ctx(POLICY_CONFLICT, POLICY_CONFLICT_CNT, 18u, &rw) == IC_OK);
    CHECK(ic_program_check_ctx(POLICY_CONFLICT, POLICY_CONFLICT_CNT, 17u, &rw)
          == IC_ERR_VALIDATE);

    /* bounded loops: ranking counter with a constant exit bound */
    CHECK(ic_program_check(loop_ok, 6) == IC_OK);
    CHECK(ic_program_check(loop_jlt, 6) == IC_OK);
    CHECK(ic_program_check(loop_self, 3) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(loop_noexit, 5) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(loop_regstep, 7) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(loop_twowrite, 7) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(loop_jeq, 6) == IC_ERR_VALIDATE);
    CHECK(ic_program_check(loop_unknown, 6) == IC_ERR_VALIDATE);

    printf(fails ? "VERIFIER HOST FAIL (%d)\n" : "VERIFIER HOST PASS\n", fails);
    return fails ? 1 : 0;
}
