/* loader.c — the module validation gate (contract v1).
 * A pass here means the descriptor is well-formed; the PMP boundary
 * remains the safety guarantee. */

#include "contract.h"

#define IC_MIN_REGION 0x400u

ic_status ic_module_check(const ic_module_desc *d) {
    if (!d) return IC_ERR_ARGUMENT;
    if (d->magic != IC_MODULE_MAGIC) return IC_ERR_CONTRACT;
    if (d->contract_ver != IC_CONTRACT_VERSION) return IC_ERR_CONTRACT;
    if (d->kind != IC_MODULE_EBPF && d->kind != IC_MODULE_NATIVE)
        return IC_ERR_ARGUMENT;
    if (d->text_base % 0x1000u || d->sram_base % 0x1000u)
        return IC_ERR_ARGUMENT;
    if (!d->text_size || (d->text_size & (d->text_size - 1u)) ||
        d->text_size < IC_MIN_REGION)
        return IC_ERR_ARGUMENT;
    if (!d->sram_size || (d->sram_size & (d->sram_size - 1u)) ||
        d->sram_size < IC_MIN_REGION)
        return IC_ERR_ARGUMENT;
    if (d->text_base + d->text_size <= d->text_base) return IC_ERR_ARGUMENT;
    if (d->sram_base + d->sram_size <= d->sram_base) return IC_ERR_ARGUMENT;
    if ((d->entry_offset & 1u) || d->entry_offset >= d->text_size)
        return IC_ERR_ARGUMENT;
    if (d->reserved != 0u) return IC_ERR_ARGUMENT;
    return IC_OK;
}
