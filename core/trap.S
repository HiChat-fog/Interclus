
    .section .text
    .align 4
    .globl xianjing_rukou
xianjing_rukou:
    csrr t0, mcause
    li   t1, 8
    beq  t0, t1, .Lecall

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
    mret

.Lecall:
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
