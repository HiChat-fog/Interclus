/* platform.h — address map, PMP encodings, and timer plumbing for the two
 * build targets: the CH32V307 board and QEMU's riscv32 'virt' machine.
 * QEMU_TARGET switches between them; the board values are the reference. */

#ifdef QEMU_TARGET

#define MON_TEXT   0x80100000u
#define NAT_TEXT   0x80210000u   /* native compartment slot 0 (RAM, exec) */
#define NAT_SRAM   0x80211000u
#define NAT2_TEXT  0x80212000u   /* native compartment slot 1 */
#define NAT2_SRAM  0x80213000u
#define ATK_TEXT   0x80102000u
#define MON_BOX    0x80200000u
#define ATK_BOX    0x80208000u
#define SUP_STACK  0x8000F000u
#define MON_STACK  0x80201F00u
#define ATK_STACK  0x80209F00u
#define PROG_AREA  0x80020000u   /* boot-time program image, untrusted */
#define FLASH_TOP  0x8078000u    /* QEMU: RAM-backed mirror */
#define STATUS      ((volatile uint32_t *)0x80010000u)
#define STATUS_NAME ((volatile char *)0x80010110u)
#define MAILBOX    ((volatile uint32_t *)0x80011000u)
#define MB_DATA     ((volatile uint8_t *)(0x80011000u + 8u))
#define TIMER_INIT()  do { } while (0)
#define TIMER_NOW()   \
    ({ uint32_t t; __asm__ volatile ("rdtime %0" : "=r"(t)); t; })

/* E28 budget: the machine timer interrupt. QEMU virt's CLINT at
 * 0x02000000: mtime at +0xBFF8, hart 0's mtimecmp at +0x4000. The
 * supervisor arms a fresh deadline before every compartment entry; a
 * fire means the running compartment overran its budget. M-mode runs
 * with MIE=0, so a spent deadline never leaks into supervisor code. mie.MTIE (bit 7) is the interrupt
 * enable; mstatus.MIE is left to compartment_enter. */
#define BUDGET_INIT() \
    do { __asm__ volatile ("csrs mie, %0" :: "r" (1u << 7)); } while (0)
#define BUDGET_ARM(ticks) \
    do { \
        volatile uint32_t *cmp = (volatile uint32_t *)0x02004000u; \
        volatile uint32_t *mt = (volatile uint32_t *)0x0200BFF8u; \
        uint32_t now = mt[0], hi = mt[1]; \
        uint32_t lo = now + (uint32_t)(ticks); \
        if (lo < now) hi++; \
        cmp[1] = 0xFFFFFFFFu;        /* hi first: no spurious match */ \
        cmp[0] = lo; \
        cmp[1] = hi; \
    } while (0)
#define BUDGET_ACK()  do { } while (0)
#define WDT_ARM()   do { } while (0)
#define WDT_FEED()  do { } while (0)
#else

#define MON_TEXT   0x08004000u
#define NAT_TEXT   0x2000A000u   /* native compartment slot 0 (RAM, exec) */
#define NAT_SRAM   0x2000B000u
#define NAT2_TEXT  0x2000C000u   /* native compartment slot 1 */
#define NAT2_SRAM  0x2000D000u
#define ATK_TEXT   0x08006000u
#define MON_BOX    0x20004000u
#define ATK_BOX    0x20008000u
#define SUP_STACK  0x20003F00u
#define MON_STACK  0x20005F00u
#define ATK_STACK  0x20009F00u
#define PROG_AREA  0x20003000u   /* boot-time program image, untrusted */
#define FLASH_TOP  0x8040000u    /* 256K real; mirror at the top 4K */
#define STATUS      ((volatile uint32_t *)0x20000100u)
#define STATUS_NAME ((volatile char *)0x20000110u)
#define MAILBOX    ((volatile uint32_t *)0x20002000u)
#define MB_DATA     ((volatile uint8_t *)(0x20002000u + 8u))
#define STK_CTLR (*(volatile uint32_t *)0xE000F000u)
#define STK_CNT  (*(volatile uint32_t *)0xE000F008u)
#define TIMER_INIT()  do { STK_CTLR |= 1u; } while (0)
#define TIMER_NOW()   (STK_CNT)

/* E28 budget on the board: QingKe's SysTick is a 64-bit up counter —
 * CTLR, SR, CNT(64) at +0x08, CMP(64) at +0x10 — and its interrupt is
 * IRQ 12 through the PFIC, not a standard machine-timer interrupt. */
#define STK_SR     (*(volatile uint32_t *)0xE000F004u)
#define STK_CNT_HI (*(volatile uint32_t *)0xE000F00Cu)
#define STK_CMP_LO (*(volatile uint32_t *)0xE000F010u)
#define STK_CMP_HI (*(volatile uint32_t *)0xE000F014u)
#define PFIC_IENR0 (*(volatile uint32_t *)0xE000E100u)
#define PFIC_IRER0 (*(volatile uint32_t *)0xE000E180u)
#define PFIC_IPRR0 (*(volatile uint32_t *)0xE000E280u)
/* PFIC enables and the SysTick counter survive a core reset, so boot
 * starts with the line masked; ARM re-enables it only after a future
 * compare is installed and the stale pending bit is dropped. */
#define BUDGET_INIT() do { \
    PFIC_IRER0 = (1u << 12); \
    STK_SR = 0u; \
    STK_CTLR |= (1u << 1); \
} while (0)
#define BUDGET_ARM(ticks) do { \
    uint32_t hi, lo0; \
    do { hi = STK_CNT_HI; lo0 = STK_CNT; } while (hi != STK_CNT_HI); \
    uint32_t lo = lo0 + (uint32_t)(ticks); \
    if (lo < lo0) hi++; \
    STK_CMP_HI = 0xFFFFFFFFu; \
    STK_CMP_LO = lo; \
    STK_CMP_HI = hi; \
    STK_SR = 0u; \
    PFIC_IPRR0 = (1u << 12); \
    PFIC_IENR0 = (1u << 12); \
} while (0)
#define BUDGET_ACK()  do { STK_SR = 0u; PFIC_IPRR0 = (1u << 12); } while (0)

/* E31 watchdog: IWDG on the 40 kHz LSI, ~3.2 s. Armed only after the
 * boot gate passes — corrupted flash parks for forensics, while a
 * runtime fail-stop (heartbeat) stops feeding and the measured boot
 * takes over. CSR 0x7C0 bit8 freezes the dog while halted by debug. */
#define IWDG_CTLR (*(volatile uint32_t *)0x40003000u)
#define IWDG_PSCR (*(volatile uint32_t *)0x40003004u)
#define IWDG_RLDR (*(volatile uint32_t *)0x40003008u)
#define WDT_ARM()  do { \
    __asm__ volatile ("csrs 0x7C0, %0" :: "r" (0x100u)); \
    IWDG_CTLR = 0x5555u; \
    IWDG_PSCR = 3u; \
    IWDG_RLDR = 4000u; \
    IWDG_CTLR = 0xAAAAu; \
    IWDG_CTLR = 0xCCCCu; \
} while (0)
#define WDT_FEED() do { IWDG_CTLR = 0xAAAAu; } while (0)

/* E32: the debugger as a stand-in wire. Words at VUART: [0]=magic,
 * [1]=rx_wr [2]=rx_rd [3]=flags (bit0 tx ring tap), [4]=tx_wr [5]=tx_rd;
 * rx ring 1024 B at +0x20, tx ring 1024 B at +0x420. The host stages
 * frame bytes then bumps rx_wr; uart_getc drains the rx ring before the
 * peripheral. */
#define VUART     ((volatile uint32_t *)0x20001700u)
#define VU_MAGIC  0x54524156u
#define VU_RX     ((volatile uint8_t *)(0x20001700u + 0x20u))
#define VU_TX     ((volatile uint8_t *)(0x20001700u + 0x420u))

#endif

/* monitor-box slots, offsets from MON_BOX */
#define MON_MODE     ((volatile uint32_t *)(MON_BOX + 0x20u))
#define MON_OFF      ((volatile uint32_t *)(MON_BOX + 0x40u))
#define MON_SIZES    ((volatile uint32_t *)(MON_BOX + 0x60u))
#define MON_INPUT    ((volatile uint8_t *)(MON_BOX + 0x80u))
#define MON_CONFN    ((volatile uint32_t *)(MON_BOX + 0x180u))
#define MON_SOFF   ((volatile uint32_t *)(MON_BOX + 0x184u))
#define MON_SSIZES   ((volatile uint32_t *)(MON_BOX + 0x290u))
#define MON_VERDICTS   ((volatile uint32_t *)(MON_BOX + 0x400u))
#define MON_INSNS    ((volatile uint32_t *)(MON_BOX + 0x430u))
#define MON_SCREEN_VERD ((volatile uint32_t *)(MON_BOX + 0x460u))
#define MON_SCREEN_INSNS   ((volatile uint32_t *)(MON_BOX + 0x560u))
#define MON_NATIVE_VERD    ((volatile uint32_t *)(MON_BOX + 0x680u))
#define DIAG_RUNS    ((volatile uint32_t *)(MON_BOX + 0x700u))
#define DIAG_ALRT    ((volatile uint32_t *)(MON_BOX + 0x704u))
#define MON_MAP      ((volatile uint32_t *)(MON_BOX + 0x800u))
#define MON_DATA    ((volatile uint8_t *)(MON_BOX + 0xA00u))
#define MAP_CELLS    64u

/* loaded-program slot in monitor SRAM: count word, then up to 64 insns;
 * 0x1800 < MON_STACK (0x1F00) so the slot never meets the stack */
#define MON_PROG_CNT ((volatile uint32_t *)(MON_BOX + 0x15FCu))
#define MON_PROG     ((volatile uint64_t *)(MON_BOX + 0x1600u))
#define PROG_MAGIC   0x474F5250u   /* "PROG" */

/* hot-swap slots: B is the last-known-good shadow (count word trails the
 * image); MON_PROG_FAULT is the live program's last interpreter fault */
#define MON_PROG_B      ((volatile uint64_t *)(MON_BOX + 0x1800u))
#define MON_PROG_B_CNT  ((volatile uint32_t *)(MON_BOX + 0x1A00u))
#define MON_PROG_FAULT  ((volatile uint32_t *)(MON_BOX + 0x15F8u))

/* runtime staging area for the hot path. The magic word sits AFTER the
 * image on purpose: a slow transport (flash-programming word by word)
 * writes cnt, then the insns, then the magic — the poller never sees a
 * half-written image. hot_swap consumes the image by clearing the magic.
 * Word 1 picks the kind: an eBPF program (word 0 = insn count, payload =
 * insns) or a native module (word 0 = code bytes, word 2 = entry offset,
 * word 3 = slot index, payload = raw code linked for that slot's base) —
 * both capped by the payload window. */
#define PROG_PEND_ADDR  (PROG_AREA + 0x800u)
#define PROG_PEND_MAGIC 0x444E4550u   /* "PEND" */
#define PROG_PEND_MAGIC_OFF 0x240u
/* the magic sits beyond the largest staged body (8 + 512 + 32 = 552):
 * at +0x208 it once overlapped the trust digest of a full-length
 * program, making 61..64-insn images silently uninstallable */
#define PROG_PEND_OK    ((volatile uint32_t *)(PROG_PEND_ADDR + PROG_PEND_MAGIC_OFF))
#define PEND_EBPF       1u
#define PEND_NATIVE     2u

/* E26 trust: every PEND image trails a 32-byte SHA-256 digest of the
 * bytes that precede it (header + payload). The gate recomputes the
 * digest over the staged bytes and rejects on mismatch, so a flipped
 * bit anywhere in transit never reaches the schedule. The key idea
 * lives in the trust_notes: the digest is an integrity check; identity
 * comes from pinning the allowed digests at build time. */
#define SHA256_LEN      32u

/* attacker-box slots */
#define ATK_OWN      ((volatile uint32_t *)(ATK_BOX + 0x0u))
#define ATK_PROOF    ((volatile uint32_t *)(ATK_BOX + 0x8u))

/* supervisor STATUS slots (word indices) */
#define S_CAIJUE 16u  
#define S_INSNS   24u  
#define S_VINTACT 32u
#define S_IINTACT 33u
#define S_OWNOOK  34u
#define S_INTER   40u  
#define S_LOG0C   41u  
#define S_DONE    56u  
#define S_BAN_CAIJUE   64u  
#define S_CINSNS  72u  
#define S_CYC0    80u  
#define S_CYC1    81u  
#define S_CYC2    82u  
#define S_JINGBAO   83u  
#define S_CHONGTU_N   84u  
#define S_LAIYUAN     85u  
#define S_NATOK   86u  
#define S_RDROK   87u  
#define S_GATE    88u   /* boot gate: 0xC0DE0000 clean, else 0xC0DE0000|code */
#define S_LOAD    89u   /* program load: 0 none, 1 loaded, 2..4 failure codes */
#define S_UTX     90u   /* UART TX self-test: STK ticks for 64 bytes */
#define S_URX     91u   /* UART loopback: 1 matched, 0 no/failed */
#define S_NAT2    92u   /* native compartment proof word */
#define S_HLOAD   93u   /* hot swaps promoted through the gates */
#define S_HREJ    94u   /* hot swaps rejected by the gates */
#define S_ROLL    95u   /* runtime rollbacks to last-known-good */
#define S_REMAP   96u   /* native slot remap drill: STK ticks for the
                         PMP-pair rewrite onto a different base */
#define S_NSLOT   97u   /* native slot table: index wired into comp 2 */
#define S_REARM   98u   /* operator re-arm commands accepted */
#define S_FPROG   99u   /* last flash mirror write: 0 ok */
#define S_PREEMPT 100u  /* compartments killed for overrunning budget */
#define S_TXABORT 101u  /* telemetry frames abandoned: TX never drained */
#define S_HALT   102u   /* fail-stop marker, survives the watchdog reset */
#define S_HALTC  103u   /* last fail-stop cause: phase<<24 | mcause */
#define S_FUZZA  104u   /* boot fuzz: random images the verifier accepted */
#define S_FUZZR  105u   /* boot fuzz: rejected (the rest) */

/* channel frame types beyond the loader set (E24/E29) */
#define FRAME_TELE   0xFu   /* device -> host: fault evidence */
#define FRAME_REARM  0xEu   /* host -> device: operator re-arms slot k */
#define FRAME_STATUS 0xDu   /* host -> device: read the STATUS window;
                               device -> host: [window:4][words LE] */
#define FRAME_UPDATE 0x4u   /* reliable update transaction command */
#define FRAME_UPDATE_REPLY 0xCu /* ACK/NACK/STAGED/ACCEPT/REJECT */
#define STATUS_WORDS 106u    /* the guarded STATUS window, words 0..105: S_FUZZR is the
                           highest named field, and the wire telemetry
                           walks exactly this many words */

/* PMP NAPOT encodings, derived from the map */
#define NAPOT(base, size) (((base) >> 2) | ((size) >> 3) - 1u)
#define MON_RAM_PMP   NAPOT(MON_BOX, 8192u)
#define MON_FLASH_PMP NAPOT(MON_TEXT, 8192u)
#define ATK_RAM_PMP   NAPOT(ATK_BOX, 8192u)
#define ATK_FLASH_PMP NAPOT(ATK_TEXT, 8192u)
#define PMP_DENY      0xFFFFFFFFu
