
    .section .text
    .align 4
    .globl trap_entry
trap_entry:
    /* unified trap frame on the M-mode scratch stack: the scratch regs are
     * saved BEFORE mcause is read, so the victim's register file survives
     * intact for the TCB evidence copy */
    csrrw sp, mscratch, sp
    addi sp, sp, -48
    sw   x1, 0(sp)              /* ra */
    sw   x5, 4(sp)              /* t0 */
    sw   x6, 8(sp)              /* t1 */
    sw   x7, 12(sp)             /* t2 */
    sw   x10, 16(sp)            /* a0 */
    sw   x11, 20(sp)            /* a1 */
    sw   x28, 24(sp)            /* t3 */
    sw   x29, 28(sp)            /* t4 */
    sw   x30, 32(sp)            /* t5 */
    sw   x31, 36(sp)            /* t6 */
    csrr t0, mcause
    sw   t0, 40(sp)
    li   t1, 8
    beq  t0, t1, .Lecall

    csrr t0, mtval
    sw   t0, 44(sp)

    /* forensics ring: g_ri_cause[idx] = mcause, g_ri_addr[idx] = mtval */
    lui  t2, %hi(g_ri_index)
    addi t2, t2, %lo(g_ri_index)
    lw   t3, 0(t2)
    slli t4, t3, 2
    lui  t5, %hi(g_ri_cause)
    addi t5, t5, %lo(g_ri_cause)
    add  t5, t5, t4
    lw   t6, 40(sp)
    sw   t6, 0(t5)
    lui  t5, %hi(g_ri_addr)
    addi t5, t5, %lo(g_ri_addr)
    add  t5, t5, t4
    lw   t6, 44(sp)
    sw   t6, 0(t5)
    addi t3, t3, 1
    li   t4, 8
    blt  t3, t4, .Lidx_ok
    li   t3, 7
.Lidx_ok:
    sw   t3, 0(t2)

    /* MPP==M: the supervisor's own fault — skip the faulting instruction
     * and resume (supervisor robustness, unchanged from v1) */
    csrr t1, mstatus
    srli t1, t1, 11
    andi t1, t1, 3
    li   t2, 3
    beq  t1, t2, .Lskip

    /* U-mode fault (contract v1.1): the compartment's first fault evicts
     * it. The victim's register file goes into TCB[cur_tcb] as evidence,
     * every register and the scratch frame are wiped, and the supervisor
     * resumes at supervisor_fault(mcause, mtval). This replaces v1's
     * skip-and-continue and the g_zhiding redirect. */
    lui  t0, %hi(cur_tcb)
    lw   t0, %lo(cur_tcb)(t0)
    beqz t0, .Lev_nosave
    sw   x1, 4(t0)
    sw   x3, 12(t0)
    sw   x4, 16(t0)
    lw   t1, 4(sp)
    sw   t1, 20(t0)             /* x5: from the frame, entry clobbered it */
    lw   t1, 8(sp)
    sw   t1, 24(t0)             /* x6 */
    lw   t1, 12(sp)
    sw   t1, 28(t0)             /* x7 */
    sw   x8, 32(t0)
    sw   x9, 36(t0)
    lw   t1, 16(sp)
    sw   t1, 40(t0)             /* x10: clobbered by the ring record */
    lw   t1, 20(sp)
    sw   t1, 44(t0)             /* x11 */
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
    lw   t1, 24(sp)
    sw   t1, 112(t0)            /* x28 */
    lw   t1, 28(sp)
    sw   t1, 116(t0)            /* x29 */
    lw   t1, 32(sp)
    sw   t1, 120(t0)            /* x30 */
    lw   t1, 36(sp)
    sw   t1, 124(t0)            /* x31 */
    csrr t1, mscratch
    sw   t1, 8(t0)              /* TCB[2] = victim sp */
.Lev_nosave:
    lw   a0, 40(sp)             /* supervisor_fault(mcause, mtval) */
    lw   a1, 44(sp)
    /* no victim byte may survive in M-mode memory */
    sw   x0, 0(sp)
    sw   x0, 4(sp)
    sw   x0, 8(sp)
    sw   x0, 12(sp)
    sw   x0, 16(sp)
    sw   x0, 20(sp)
    sw   x0, 24(sp)
    sw   x0, 28(sp)
    sw   x0, 32(sp)
    sw   x0, 36(sp)
    sw   x0, 40(sp)
    sw   x0, 44(sp)
    lui  t0, %hi(trap_sp0_top)
    addi t0, t0, %lo(trap_sp0_top)
    csrw mscratch, t0
    /* zero the register file except a0/a1 (the cleanup convention) */
    mv   x1, x0
    mv   x3, x0
    mv   x4, x0
    mv   x5, x0
    mv   x6, x0
    mv   x7, x0
    mv   x8, x0
    mv   x9, x0
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
    lui  t0, %hi(supervisor_fault)
    addi t0, t0, %lo(supervisor_fault)
    csrw mepc, t0
    csrr t1, mstatus
    li   t2, 0x1800
    or   t1, t1, t2
    csrw mstatus, t1
    mv   t0, x0
    mv   t1, x0
    mv   t2, x0
    mret

.Lskip:
    csrr t1, mepc
    lhu  t2, 0(t1)
    andi t2, t2, 3
    addi t1, t1, 2
    li   t3, 3
    bne  t2, t3, .Lskip_done
    addi t1, t1, 2
.Lskip_done:
    csrw mepc, t1

.Lrestore:
    lw   x1, 0(sp)
    lw   x5, 4(sp)
    lw   x6, 8(sp)
    lw   x7, 12(sp)
    lw   x10, 16(sp)
    lw   x11, 20(sp)
    lw   x28, 24(sp)
    lw   x29, 28(sp)
    lw   x30, 32(sp)
    lw   x31, 36(sp)
    addi sp, sp, 48
    csrrw sp, mscratch, sp      /* back to the interrupted sp */
    mret

.Lecall:
    /* park the compartment's register file in its TCB, then leave the
     * live registers zeroed: the next compartment inherits nothing */
    lui  t0, %hi(cur_tcb)
    lw   t0, %lo(cur_tcb)(t0)
    beqz t0, .Lecall_zero
    sw   x1, 4(t0)
    sw   x3, 12(t0)
    sw   x4, 16(t0)
    lw   t1, 4(sp)
    sw   t1, 20(t0)             /* x5: entry clobbered it with mcause */
    lw   t1, 8(sp)
    sw   t1, 24(t0)             /* x6: entry clobbered it with the li */
    sw   x7, 28(t0)
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
    sw   t1, 8(t0)              /* TCB[2] = compartment sp */
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
    lui  t0, %hi(supervisor_resume)
    addi t0, t0, %lo(supervisor_resume)
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
