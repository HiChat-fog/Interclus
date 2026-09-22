
#ifndef EBPF_ASM_H
#define EBPF_ASM_H

#define EBPF_ENC(op, d, s, o, i) \
    ((uint64_t)(uint8_t)(op) \
     | ((uint64_t)(uint8_t)(((d) & 0xf) | (((s) & 0xf) << 4)) << 8) \
     | ((uint64_t)(uint16_t)(o) << 16) \
     | ((uint64_t)(uint32_t)(i) << 32))

#define MOV64I(d, i)  EBPF_ENC(0xb7, d, 0, 0, i)
#define SLL64I(d, i)  EBPF_ENC(0x67, d, 0, 0, i)
#define RSH64I(d, i)  EBPF_ENC(0x77, d, 0, 0, i)
#define ADD64I(d, i)  EBPF_ENC(0x07, d, 0, 0, i)
#define SUB64I(d, i)  EBPF_ENC(0x17, d, 0, 0, i)
#define AND64I(d, i)  EBPF_ENC(0x57, d, 0, 0, i)

#define ADD64(d, s)   EBPF_ENC(0x0f, d, s, 0, 0)
#define OR64(d, s)    EBPF_ENC(0x4f, d, s, 0, 0)
#define DIV64(d, s)   EBPF_ENC(0x3f, d, s, 0, 0)
#define MOV64(d, s)   EBPF_ENC(0xbf, d, s, 0, 0)

#define JEQ64I(d, i, o) EBPF_ENC(0x15, d, 0, o, i)
#define JNE64I(d, i, o) EBPF_ENC(0x55, d, 0, o, i)
#define JGT64I(d, i, o) EBPF_ENC(0x25, d, 0, o, i)

#define JEQ64(d, s, o)  EBPF_ENC(0x1d, d, s, o, 0)

#define CALL(h)       EBPF_ENC(0x85, 0, 0, 0, h)

#define LDXB(d, s, o) EBPF_ENC(0x71, d, s, o, 0)
#define LDXH(d, s, o) EBPF_ENC(0x69, d, s, o, 0)
#define LDXW(d, s, o) EBPF_ENC(0x61, d, s, o, 0)

#define STW(d, o, i)  EBPF_ENC(0x62, d, 0, o, i)
#define EXIT()        EBPF_ENC(0x95, 0, 0, 0, 0)

#endif
