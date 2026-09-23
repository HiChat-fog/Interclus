
#ifndef POLICY_CONFLICT_H
#define POLICY_CONFLICT_H

#include <stdint.h>
#include "../../core/ebpf_asm.h"
#include "../../core/contract.h"

static const uint64_t POLICY_CONFLICT[] = {
     LDXH(2, 1, 7),
     LDXB(3, 1, 9),
     SLL64I(3, 16),
     OR64(2, 3),                 
     MOV64I(3, 33),
     JNE64I(2, 33, 24),          
     LDXW(4, 1, 10),             
     LDXW(5, 1, 14),             
     RSH64I(4, 26),
     AND64I(4, 7),               
     RSH64I(5, 26),
     AND64I(5, 7),               
     SLL64I(4, 3),
     OR64(4, 5),                 
     MOV64(1, 4),
     CALL(1),                    
     MOV64(6, 0),
     ADD64I(6, 1),               
     MOV64(1, 4),
     MOV64(2, 6),
     CALL(2),                    
     JGT64I(6, 3, 10),           
     MOV64(1, 4),
     SUB64I(1, 1),               
     CALL(1),
     JGT64I(0, 3, 6),            
     MOV64(1, 4),
     ADD64I(1, 1),               
     CALL(1),
     JGT64I(0, 3, 2),            
     MOV64I(0, 1),
     EXIT(),                     
     MOV64I(0, 5),
     EXIT(),                     
};
#define POLICY_CONFLICT_CNT 34

/* module self-description: 64 grid cells (256 B), host-assigned, so
 * sram_base stays zero and the size states the requirement. text_base
 * stays zero too: the linked address is not the author's to declare */
static const ic_module_desc ic_module_screening __attribute__((unused)) = {
    IC_MODULE_MAGIC, IC_CONTRACT_VERSION, IC_MODULE_EBPF,
    0u, (uint32_t)sizeof(POLICY_CONFLICT),
    0u, 256u, 0u, 0u
};

#endif
