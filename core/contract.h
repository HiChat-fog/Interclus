/* contract.h: the Interclus core contract, version 1.
 *
 * Reading rules for module authors:
 *   1. This file and the eBPF instruction encodings (core/ebpf_asm.h) are
 *      all a module needs to read. If a module needs anything outside
 *      them, the architecture is wrong; say so instead of working around
 *      it.
 *   2. Everything outside core/ is a module. Modules include these two
 *      files and depend on nothing else.
 *   3. The contract only grows. Functions and enum values may be appended;
 *      existing ones never change meaning, order, or signature. A module
 *      built against contract v1 runs on every core that speaks v1 or later.
 *   4. Validation runs before anything dangerous: eBPF programs pass the
 *      in-interpreter verifier, module descriptors pass ic_module_check.
 *      A pass means "well-formed", not "the code is safe". The PMP
 *      boundary is the safety guarantee.
 *   5. If writing a module requires reading more than rule 1 names, the
 *      architecture is too complex. Fix the architecture.
 *
 * Style: freestanding C99, stdint only, static memory only, every call
 * reports through ic_status (or returns a handle). */

#ifndef INTERCLUS_CONTRACT_H
#define INTERCLUS_CONTRACT_H

#include <stdint.h>

#define IC_CONTRACT_VERSION 1u
#define IC_MODULE_MAGIC     0x494E434Cu   /* "INCL" */

/* ---- status: every interface reports through this ---- */
typedef enum {
    IC_OK = 0,
    IC_ERR_NOMEM,     /* no compartment slot or memory left */
    IC_ERR_ARGUMENT,  /* malformed argument */
    IC_ERR_CONTRACT,  /* module targets a different contract version */
    IC_ERR_VALIDATE,  /* module rejected by validation */
    IC_ERR_STATE,     /* operation invalid in the current lifecycle state */
    IC_ERR_PLATFORM   /* the hardware refused (entry budget, alignment, ...) */
} ic_status;

/* ---- 1. compartments: PMP-boxed memory regions ----
 *
 * A compartment is one execute-only text region plus one read/write SRAM
 * region. The platform decides how many live at once (QingKe V4F: one, by
 * time-multiplexing; richer silicon: several at once). Module authors never
 * touch PMP encodings; they describe memory, the core translates it to
 * whatever the silicon needs (NAPOT today). */

typedef struct {
    uint32_t text_base;   /* 4 KiB aligned */
    uint32_t text_size;   /* power of two, >= 1 KiB */
    uint32_t sram_base;   /* 4 KiB aligned */
    uint32_t sram_size;   /* power of two, >= 1 KiB */
} ic_compartment_spec;

typedef uint32_t ic_compartment;   /* handle; IC_COMPARTMENT_NONE = none */
#define IC_COMPARTMENT_NONE 0u

ic_status ic_compartment_alloc(const ic_compartment_spec *spec,
                               ic_compartment *out);
ic_status ic_compartment_free(ic_compartment c);

/* Well-formedness gate for a spec: base alignment, size classes, overflow.
 * Run it before a spec is ever translated into PMP entries. */
ic_status ic_compartment_check(const ic_compartment_spec *spec);

/* Arms PMP for c and enters its U-mode entry point. Returns to M-mode when
 * the compartment yields (ecall) or faults (trap -> forensics -> here). */
ic_status ic_compartment_enter(ic_compartment c, uint32_t entry_offset);

/* ---- 2. programs: eBPF execution inside a compartment ---- */

typedef struct {
    const uint64_t *ins;
    uint32_t        insn_cnt;
    const uint8_t  *ctx;         /* packet buffer, read-only to the program */
    uint32_t        ctx_size;
    uint32_t        max_steps;
    uint32_t       *map;         /* optional grid; NULL = helper calls fault */
    uint32_t        map_cells;
} ic_program;

typedef struct {
    uint64_t retval;
    uint32_t insns_executed;
    uint8_t  fault;              /* ic_fault, zero on clean exit */
} ic_result;

typedef enum {
    IC_FAULT_OK = 0,
    IC_FAULT_PC,       /* jump outside the program */
    IC_FAULT_STEPS,    /* step cap hit */
    IC_FAULT_MEM,      /* read outside ctx */
    IC_FAULT_STORE,    /* stores are never allowed */
    IC_FAULT_DIV0,
    IC_FAULT_OPCODE,
    IC_FAULT_CALL,     /* helper misuse */
    IC_FAULT_FP
} ic_fault;

ic_status ic_program_run(const ic_program *p, ic_result *r);

/* ---- 3. modules: descriptors and the validation gate ---- */

typedef enum {
    IC_MODULE_EBPF   = 1,   /* runs on the interpreter; verifier is the gate */
    IC_MODULE_NATIVE = 2    /* raw machine code; descriptor-checked, PMP-boxed */
} ic_module_kind;

typedef struct {
    uint32_t magic;          /* IC_MODULE_MAGIC */
    uint16_t contract_ver;   /* must equal IC_CONTRACT_VERSION */
    uint16_t kind;           /* ic_module_kind */
    uint32_t text_base;
    uint32_t text_size;
    uint32_t sram_base;
    uint32_t sram_size;
    uint32_t entry_offset;   /* offset into text; native: 2-byte aligned,
                                  eBPF: 8-byte (one instruction) */
    uint32_t reserved;       /* zero; growth room keeps v1 structs stable */
} ic_module_desc;

/* The validation gate. Shared checks: magic, contract version, kind,
 * reserved. Native modules are compartment-shaped: 4 KiB-aligned bases,
 * power-of-two sizes >= 1 KiB, 2-byte-aligned entry. eBPF modules are
 * instruction arrays: 8-byte-aligned size and entry; text_base is the
 * linked program address, which a module author does not know, so zero
 * means "host or linker assigns"; a nonzero base must be 8-byte aligned.
 * Map backing (if any) 4-byte-aligned. eBPF modules additionally face the
 * in-interpreter verifier at run. A pass means "well-formed", not "the
 * code is safe". The PMP boundary is the safety guarantee. */
ic_status ic_module_check(const ic_module_desc *d);

/* ---- lifecycle ----
 * v1 covers: alloc / enter / yield-by-ecall / fault-recover. pause, resume,
 * unload, and child-task loading append in later contract versions, designed
 * against the same rules. Native and eBPF modules share this one lifecycle. */

#endif /* INTERCLUS_CONTRACT_H */
