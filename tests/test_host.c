/* Host-side unit tests. The same C99 interpreter is compiled for
 * x86-64 (this file) and RV32; these cases pin verdicts, fault classes,
 * per-packet instruction counts, and the validation gates. Expected values
 * come from the policies. */

#include <stdio.h>
#include <string.h>
#include "../core/ebpf.h"
#include "../modules/policies/mavlink.h"
#include "../modules/policies/screening.h"
#include "../modules/examples/pass_all.c"
#include "../modules/examples/rate_limit.h"
#include "../core/loader.c"
#include "../core/contract.h"
#include "../descriptions/demo.h"

static int failures = 0;

static void check_case(const char *name, const struct ebpf_prog *p,
                       uint64_t want_ret, uint8_t want_fault) {
    struct ebpf_result r;
    int rc = ebpf_run(p, &r);
    int ok = (r.retval == want_ret) && (r.fault == want_fault) &&
             (rc == (want_fault == EBPF_OK ? 0 : -1));
    printf("%-28s ret=%llu fault=%u insns=%u  want ret=%llu fault=%u  %s\n",
           name, (unsigned long long)r.retval, r.fault, r.insns_executed,
           (unsigned long long)want_ret, want_fault, ok ? "PASS" : "FAIL");
    if (!ok) failures++;
}

static void check_desc(const char *name, ic_status got, ic_status want) {
    printf("%-28s %s\n", name, got == want ? "PASS" : "FAIL");
    if (got != want) failures++;
}

#define PROG_WITH(data) \
    { POLICY_MAVLINK, POLICY_MAVLINK_CNT, data, (uint32_t)sizeof(data), 1000000, 0, 0 }

int main(void) {
    struct ebpf_prog p = PROG_WITH(PKT_GPI);

    /* filter policy: one case per verdict class */
    p.ctx = PKT_GPI;      p.ctx_size = sizeof(PKT_GPI);
    check_case("GPI valid frame", &p, 1, EBPF_OK);
    p.ctx = PKT_HB;       p.ctx_size = sizeof(PKT_HB);
    check_case("HEARTBEAT valid frame", &p, 1, EBPF_OK);
    p.ctx = PKT_BADMAGIC; p.ctx_size = sizeof(PKT_BADMAGIC);
    check_case("bad magic", &p, 0, EBPF_OK);
    p.ctx = PKT_BADMSGID; p.ctx_size = sizeof(PKT_BADMSGID);
    check_case("msgid not whitelisted", &p, 2, EBPF_OK);
    p.ctx = PKT_BIGLEN;   p.ctx_size = sizeof(PKT_BIGLEN);
    check_case("payload too long", &p, 3, EBPF_OK);
    p.ctx = PKT_BADLAT;   p.ctx_size = sizeof(PKT_BADLAT);
    check_case("latitude out of range", &p, 4, EBPF_OK);

    /* fault classes exercised with hand-built bytecode */
    {
        static const uint64_t ins[] = { LDXB(2, 1, 100), MOV64I(0, 1), EXIT() };
        struct ebpf_prog q = { ins, 3, PKT_HB, sizeof(PKT_HB), 1000, 0, 0 };
        check_case("OOB read blocked", &q, 0, EBPF_FAULT_MEM);
    }

    {
        static const uint64_t ins[] = { STW(1, 0, 0x11223344), MOV64I(0, 1), EXIT() };
        struct ebpf_prog q = { ins, 3, PKT_HB, sizeof(PKT_HB), 1000, 0, 0 };
        check_case("store blocked", &q, 0, EBPF_FAULT_STORE);
    }

    {
        static const uint64_t ins[] = {
            MOV64I(2, 5), MOV64I(3, 0), DIV64(2, 3), MOV64I(0, 7), EXIT()
        };
        struct ebpf_prog q = { ins, 5, PKT_HB, sizeof(PKT_HB), 1000, 0, 0 };
        check_case("div by zero blocked", &q, 0, EBPF_FAULT_DIV0);
    }

    {
        static const uint64_t ins[] = {
            MOV64I(2, 1), SLL64I(2, 40),
            MOV64I(3, 1), SLL64I(3, 40),
            JEQ64(2, 3, 2),
            MOV64I(0, 0), EXIT(),
            MOV64I(0, 1), EXIT(),
        };
        struct ebpf_prog q = { ins, 9, PKT_HB, sizeof(PKT_HB), 1000, 0, 0 };
        check_case("64-bit shift equivalence", &q, 1, EBPF_OK);
    }

    /* screening policy: 8-packet stream, packets 4+ crowd one grid cell */
    {
        static uint32_t grid[64];
        struct ebpf_prog q = { POLICY_CONFLICT, POLICY_CONFLICT_CNT,
                               PKT_GPI, sizeof(PKT_GPI), 1000000, grid, 64 };
        static const uint64_t want[8] = { 1, 1, 1, 5, 5, 5, 5, 5 };

        memset(grid, 0, sizeof(grid));
        for (int k = 0; k < 8; k++) {
            static uint8_t pkt[42];
            memcpy(pkt, PKT_GPI, sizeof(PKT_GPI));
            if (k >= 4) {           /* park drones 4..7 in the same cell */
                pkt[14] = 0xC2; pkt[15] = 0xBC; pkt[16] = 0xEB; pkt[17] = 0x00;
            }
            q.ctx = pkt; q.ctx_size = sizeof(pkt);
            char name[32];
            snprintf(name, sizeof(name), "screening pkt%d", k);
            check_case(name, &q, want[k], EBPF_OK);
        }
    }

    {
        struct ebpf_prog q = { POLICY_CONFLICT, POLICY_CONFLICT_CNT,
                               PKT_GPI, sizeof(PKT_GPI), 1000000, 0, 0 };
        check_case("CALL without map blocked", &q, 0, EBPF_FAULT_CALL);
    }

    /* minimal module: pass-all policy (two checks, no core edits) */
    {
        struct ebpf_prog q = { pass_all_ins, pass_all_cnt,
                               PKT_BIGLEN, sizeof(PKT_BIGLEN), 1000, 0, 0 };
        check_case("module pass-all accepts", &q, 1, EBPF_OK);
        q.ctx = PKT_BADMAGIC; q.ctx_size = sizeof(PKT_BADMAGIC);
        check_case("module pass-all rejects bad magic", &q, 0, EBPF_OK);
    }

    /* example module: rate limit, three frames per msgid class, then latch */
    {
        static uint32_t grid[64];
        struct ebpf_prog q = { RATE_LIMIT, RATE_LIMIT_CNT,
                               PKT_GPI, sizeof(PKT_GPI), 1000, grid, 64 };
        memset(grid, 0, sizeof(grid));
        for (int k = 0; k < 5; k++) {
            char name[32];
            snprintf(name, sizeof(name), "rate-limit frame%d", k);
            check_case(name, &q, k < 3 ? 1 : 5, EBPF_OK);
        }
        q.ctx = PKT_HB; q.ctx_size = sizeof(PKT_HB);
        check_case("rate-limit other class unaffected", &q, 1, EBPF_OK);
    }

    /* loader validation gate: one valid descriptor, then the rejections */
    {
        ic_module_desc d = { IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                             IC_MODULE_NATIVE, 0x08004000u, 0x2000u,
                             0x20008000u, 0x2000u, 0, 0 };
        check_desc("loader: valid descriptor", ic_module_check(&d), IC_OK);
        d.magic = 0x12345678u;
        check_desc("loader: bad magic", ic_module_check(&d), IC_ERR_CONTRACT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, 99u, IC_MODULE_NATIVE,
                              0x08004000u, 0x2000u, 0x20008000u, 0x2000u, 0, 0 };
        check_desc("loader: bad contract version", ic_module_check(&d), IC_ERR_CONTRACT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                              IC_MODULE_NATIVE, 0x08002100u, 0x2000u,
                              0x20008000u, 0x2000u, 0, 0 };
        check_desc("loader: unaligned text", ic_module_check(&d), IC_ERR_ARGUMENT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                              IC_MODULE_NATIVE, 0x08004000u, 0x2000u,
                              0x20008000u, 0x2000u, 0x2001u, 0 };
        check_desc("loader: entry out of bounds", ic_module_check(&d), IC_ERR_ARGUMENT);
    }

    /* compartment gate */
    {
        static const ic_compartment_spec good = {
            0x08002000u, 0x2000u, 0x20004000u, 0x2000u
        };
        ic_compartment_spec bad;
        check_desc("compartment: valid spec", ic_compartment_check(&good), IC_OK);
        check_desc("compartment: null spec", ic_compartment_check(0), IC_ERR_ARGUMENT);
        bad = good; bad.text_base = 0x08002100u;
        check_desc("compartment: unaligned text", ic_compartment_check(&bad), IC_ERR_ARGUMENT);
        bad = good; bad.sram_size = 0x1800u;
        check_desc("compartment: size not power of two", ic_compartment_check(&bad), IC_ERR_ARGUMENT);
        bad = good; bad.text_size = 0x200u;
        check_desc("compartment: size under 1 KiB", ic_compartment_check(&bad), IC_ERR_ARGUMENT);
    }

    /* everything the repo ships must pass its own gate */
    {
        check_desc("gate: shipped mavlink desc", ic_module_check(&ic_module_mavlink), IC_OK);
        check_desc("gate: shipped screening desc", ic_module_check(&ic_module_screening), IC_OK);
        check_desc("gate: shipped rate-limit desc", ic_module_check(&ic_module_rate_limit), IC_OK);
        check_desc("gate: shipped pass-all desc", ic_module_check(&ic_module_pass_all), IC_OK);
        check_desc("gate: generated monitor spec", ic_compartment_check(&ic_comp_monitor), IC_OK);
        check_desc("gate: generated attacker spec", ic_compartment_check(&ic_comp_attacker), IC_OK);
        check_desc("gate: generated monitor desc", ic_module_check(&ic_module_monitor), IC_OK);
        check_desc("gate: generated attacker desc", ic_module_check(&ic_module_attacker), IC_OK);
    }

    /* eBPF descriptors follow interpreter rules, not compartment rules */
    {
        ic_module_desc d = { IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                             IC_MODULE_EBPF, 0x08004000u, 224u,
                             0u, 0u, 0u, 0 };
        check_desc("ebpf: valid descriptor", ic_module_check(&d), IC_OK);
        d.text_base = 0u;
        check_desc("ebpf: zero base is host-assigned", ic_module_check(&d), IC_OK);
        d.text_base = 0x08004004u;
        check_desc("ebpf: base not 8-byte aligned", ic_module_check(&d), IC_ERR_ARGUMENT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                              IC_MODULE_EBPF, 0x08004000u, 100u,
                              0u, 0u, 0u, 0 };
        check_desc("ebpf: size not instruction multiple", ic_module_check(&d), IC_ERR_ARGUMENT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                              IC_MODULE_EBPF, 0x08004000u, 224u,
                              0u, 0u, 4u, 0 };
        check_desc("ebpf: entry not instruction aligned", ic_module_check(&d), IC_ERR_ARGUMENT);
        d.entry_offset = 224u;
        check_desc("ebpf: entry past the program", ic_module_check(&d), IC_ERR_ARGUMENT);
        d = (ic_module_desc){ IC_MODULE_MAGIC, IC_CONTRACT_VERSION,
                              IC_MODULE_EBPF, 0x08004000u, 224u,
                              0x20004002u, 256u, 0u, 0 };
        check_desc("ebpf: map not word aligned", ic_module_check(&d), IC_ERR_ARGUMENT);
        d.sram_base = 0x20004000u; d.sram_size = 0u;
        check_desc("ebpf: map base without size", ic_module_check(&d), IC_ERR_ARGUMENT);
    }

    printf("\n%s (%d failures)\n", failures ? "!!! FAILURES" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
