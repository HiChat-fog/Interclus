/* loader.c — the module validation gate (contract v1).
 * A pass here means the descriptor is well-formed; the PMP boundary
 * remains the safety guarantee. Native modules are PMP-shaped; eBPF
 * modules are instruction arrays and follow interpreter rules. */

#include "contract.h"

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
