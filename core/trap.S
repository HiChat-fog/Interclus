
    .section .text
    .align 4
    .globl xianjing_rukou
xianjing_rukou:
    csrr t0, mcause
    li   t1, 8
    beq  t0, t1, .Lecall

    /* the interrupted sp belongs to U-mode: swap in the M-mode scratch
     * stack before storing anything */
    csrrw sp, mscratch, sp
    addi sp, sp, -48
    sw   a0, 0(sp)
    sw   a1, 4(sp)
    sw   t0, 8(sp)
    sw   t1, 12(sp)
    sw   t2, 16(sp)
    sw   t3, 20(sp)
    sw   t4, 24(sp)
    sw   t5, 28(sp)
    sw   t6, 32(sp)

    lui  t3, %hi(g_ri_xuhao)
    addi t3, t3, %lo(g_ri_xuhao)
    lw   t4, 0(t3)
    slli t5, t4, 2

    csrr t6, mtval

    lui  a0, %hi(g_ri_yuanyin)
    addi a0, a0, %lo(g_ri_yuanyin)
    add  a0, a0, t5
    sw   t0, 0(a0)

    lui  a1, %hi(g_ri_zhi)
    addi a1, a1, %lo(g_ri_zhi)
    add  a1, a1, t5
    sw   t6, 0(a1)

    addi t4, t4, 1
    li   t1, 8
    blt  t4, t1, .Lidx_ok
    li   t4, 7
.Lidx_ok:
    sw   t4, 0(t3)

    li   t1, 1
    beq  t0, t1, .Lredirect

    csrr t1, mepc
    lhu  t2, 0(t1)
    andi t2, t2, 3
    addi t1, t1, 2
    li   t3, 3
    bne  t2, t3, .Lskip_done
    addi t1, t1, 2
.Lskip_done:
    csrw mepc, t1
    j    .Lrestore

.Lredirect:
    lui  t4, %hi(g_zhiding)
    addi t4, t4, %lo(g_zhiding)
    lw   t4, 0(t4)
    csrw mepc, t4

.Lrestore:
    lw   a0, 0(sp)
    lw   a1, 4(sp)
    lw   t0, 8(sp)
    lw   t1, 12(sp)
    lw   t2, 16(sp)
    lw   t3, 20(sp)
    lw   t4, 24(sp)
    lw   t5, 28(sp)
    lw   t6, 32(sp)
    addi sp, sp, 48
    csrrw sp, mscratch, sp      /* back to the interrupted sp */
    mret

.Lecall:
    /* park the compartment's register file in its TCB, then leave the
     * live registers zeroed: the next compartment inherits nothing */
    csrrw sp, mscratch, sp
    sw   x5, -12(sp)
    sw   x6, -8(sp)
    sw   x7, -4(sp)
    lui  t0, %hi(cur_tcb)
    lw   t0, %lo(cur_tcb)(t0)
    beqz t0, .Lecall_zero
    sw   x1, 4(t0)
    sw   x3, 12(t0)
    sw   x4, 16(t0)
    lw   t1, -12(sp)
    sw   t1, 20(t0)
    lw   t1, -8(sp)
    sw   t1, 24(t0)
    lw   t1, -4(sp)
    sw   t1, 28(t0)
    sw   x8, 32(t0)
    sw   x9, 36(t0)
    sw   x10, 40(t0)
    sw   x11, 44(t0)
    sw   x12, 48(t0)
    sw   x13, 52(t0)
    sw   x14, 56(t0)
    sw   x15, 60(t0)
    sw   x16, 64(t0)
    sw   x17, 68(t0)
    sw   x18, 72(t0)
    sw   x19, 76(t0)
    sw   x20, 80(t0)
    sw   x21, 84(t0)
    sw   x22, 88(t0)
    sw   x23, 92(t0)
    sw   x24, 96(t0)
    sw   x25, 100(t0)
    sw   x26, 104(t0)
    sw   x27, 108(t0)
    sw   x28, 112(t0)
    sw   x29, 116(t0)
    sw   x30, 120(t0)
    sw   x31, 124(t0)
    csrr t1, mscratch
    sw   t1, 8(t0)               /* TCB[2] = compartment sp */
.Lecall_zero:
    lui  t0, %hi(trap_sp0_top)
    addi t0, t0, %lo(trap_sp0_top)
    csrw mscratch, t0
    mv   x1, x0
    mv   x3, x0
    mv   x4, x0
    mv   x5, x0
    mv   x6, x0
    mv   x7, x0
    mv   x8, x0
    mv   x9, x0
    mv   x10, x0
    mv   x11, x0
    mv   x12, x0
    mv   x13, x0
    mv   x14, x0
    mv   x15, x0
    mv   x16, x0
    mv   x17, x0
    mv   x18, x0
    mv   x19, x0
    mv   x20, x0
    mv   x21, x0
    mv   x22, x0
    mv   x23, x0
    mv   x24, x0
    mv   x25, x0
    mv   x26, x0
    mv   x27, x0
    mv   x28, x0
    mv   x29, x0
    mv   x30, x0
    mv   x31, x0
    lui  sp, %hi(_sup_stack_top)
    addi sp, sp, %lo(_sup_stack_top)
    lui  t0, %hi(guanli_huifu)
    addi t0, t0, %lo(guanli_huifu)
    csrw mepc, t0
    csrr t1, mstatus
    li   t2, 0x1800
    or   t1, t1, t2
    csrw mstatus, t1
    mret

    .section .trap_scratch, "aw", @nobits
    .p2align 3
    .globl trap_sp0_top
trap_sp0:
    .space 64                   /* fault-path scratch; pinned by the linker
                                   scripts, U-mode never sees it */
trap_sp0_top:
