/* loader.c — the module validation gate (contract v1).
 * A pass here means the descriptor is well-formed; the PMP boundary
 * remains the safety guarantee. Native modules are PMP-shaped; eBPF
 * modules are instruction arrays and follow interpreter rules. */

#include "contract.h"
#include "loader.h"

#define IC_MIN_REGION 0x400u

static int region_ok(uint32_t base, uint32_t size) {
    return base % 0x1000u == 0 && size >= IC_MIN_REGION &&
           (size & (size - 1u)) == 0 && base + size > base;
}

ic_status ic_compartment_check(const ic_compartment_spec *s) {
    if (!s) return IC_ERR_ARGUMENT;
    if (!region_ok(s->text_base, s->text_size)) return IC_ERR_ARGUMENT;
    if (!region_ok(s->sram_base, s->sram_size)) return IC_ERR_ARGUMENT;
    return IC_OK;
}

static ic_status check_native(const ic_module_desc *d) {
    if (!region_ok(d->text_base, d->text_size)) return IC_ERR_ARGUMENT;
    if (!region_ok(d->sram_base, d->sram_size)) return IC_ERR_ARGUMENT;
    if ((d->entry_offset & 1u) || d->entry_offset >= d->text_size)
        return IC_ERR_ARGUMENT;
    return IC_OK;
}

static ic_status check_ebpf(const ic_module_desc *d) {
    if (d->text_base && d->text_base % 8u) return IC_ERR_ARGUMENT;
    if (d->text_size % 8u || d->text_size < 8u) return IC_ERR_ARGUMENT;
    if (d->entry_offset % 8u || d->entry_offset >= d->text_size)
        return IC_ERR_ARGUMENT;
    if (d->sram_size && d->sram_base % 4u) return IC_ERR_ARGUMENT;
    if (d->sram_base && !d->sram_size) return IC_ERR_ARGUMENT;
    return IC_OK;
}

ic_status ic_module_check(const ic_module_desc *d) {
    if (!d) return IC_ERR_ARGUMENT;
    if (d->magic != IC_MODULE_MAGIC) return IC_ERR_CONTRACT;
    if (d->contract_ver != IC_CONTRACT_VERSION) return IC_ERR_CONTRACT;
    if (d->kind != IC_MODULE_EBPF && d->kind != IC_MODULE_NATIVE)
        return IC_ERR_ARGUMENT;
    if (d->reserved != 0u) return IC_ERR_ARGUMENT;
    return (d->kind == IC_MODULE_EBPF) ? check_ebpf(d) : check_native(d);
}

/* opcodes the interpreter executes; LD/ST/STX classes never appear in a
 * program this core accepts (stores are rejected at run time anyway) */
static int opcode_known(uint8_t op) {
    switch (op & 0x07u) {
    case 0x01u:                       /* LDX: plain context loads */
        return (op & 0xe0u) == 0x60u;
    case 0x04u: case 0x07u: {         /* ALU32 / ALU64 */
        uint8_t o = op & 0xf0u;
        if (o == 0xd0u) return (op & 0x08u) != 0;   /* endian swap, reg-src */
        return o <= 0xc0u;
    }
    case 0x05u: case 0x06u: {         /* JMP / JMP32 */
        uint8_t o = op & 0xf0u;
        return o <= 0x90u || (o >= 0xa0u && o <= 0xd0u);
    }
    default:
        return 0;
    }
}

ic_status ic_program_check(const uint64_t *ins, uint32_t cnt) {
    if (!ins || !cnt || cnt > IC_PROG_MAX_INSNS) return IC_ERR_ARGUMENT;
    for (uint32_t pc = 0; pc < cnt; pc++) {
        uint64_t e = ins[pc];
        uint8_t op  = (uint8_t)(e & 0xffu);
        uint8_t dst = (uint8_t)((e >> 8) & 0x0fu);
        uint8_t src = (uint8_t)((e >> 12) & 0x0fu);
        int16_t off = (int16_t)((e >> 16) & 0xffffu);
        if (dst > 10u || src > 10u) return IC_ERR_VALIDATE;
        if (!opcode_known(op)) return IC_ERR_VALIDATE;
        if ((op & 0x07u) == 0x05u || (op & 0x07u) == 0x06u) {
            uint8_t hi = op & 0xf0u;
            if (hi == 0x90u) continue;              /* exit */
            if (hi == 0x80u) {                      /* call: helpers 1 and 2 */
                if (op & 0x08u) return IC_ERR_VALIDATE;
                if ((uint32_t)((e >> 32) & 0xffffffffu) > 2u)
                    return IC_ERR_VALIDATE;
                continue;
            }
            {
                int32_t target = (int32_t)pc + 1 + off;
                if (target < 0 || target >= (int32_t)cnt)
                    return IC_ERR_VALIDATE;
            }
        }
    }
    return IC_OK;
}
