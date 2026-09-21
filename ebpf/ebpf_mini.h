
#ifndef EBPF_MINI_H
#define EBPF_MINI_H

#include <stdint.h>

#define EBPF_OK            0
#define EBPF_FAULT_PC      1  
#define EBPF_FAULT_STEPS   2  
#define EBPF_FAULT_MEM     3  
#define EBPF_FAULT_STORE   4  
#define EBPF_FAULT_DIV0    5
#define EBPF_FAULT_OPCODE  6
#define EBPF_FAULT_CALL    7
#define EBPF_FAULT_FP      8  

struct ebpf_insn { uint8_t opcode, dst, src; int16_t off; int32_t imm; };

struct ebpf_prog {
    const uint64_t *ins;      
    uint32_t       insn_cnt;
    const uint8_t  *ctx;      
    uint32_t       ctx_size;
    uint32_t       max_steps;
    uint32_t       *map;      
    uint32_t       map_cells; 
};

struct ebpf_result {
    uint64_t retval;          
    uint32_t insns_executed;
    uint8_t  fault;           
};

int ebpf_run(const struct ebpf_prog *p, struct ebpf_result *r);

#endif
