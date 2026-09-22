/* platform.h — address map, PMP encodings, and timer plumbing for the two
 * build targets: the CH32V307 board and QEMU's riscv32 'virt' machine.
 * QEMU_TARGET switches between them; the board values are the reference. */

#ifdef QEMU_TARGET

#define MON_TEXT   0x80100000u
#define ATK_TEXT   0x80102000u
#define MON_BOX    0x80200000u
#define ATK_BOX    0x80208000u
#define SUP_STACK  0x8000F000u
#define MON_STACK  0x80201F00u
#define ATK_STACK  0x80209F00u
#define STATUS      ((volatile uint32_t *)0x80010000u)
#define STATUS_NAME ((volatile char *)0x80010110u)
#define MAILBOX    ((volatile uint32_t *)0x80011000u)
#define MB_DATA     ((volatile uint8_t *)(0x80011000u + 8u))
#define TIMER_INIT()  do { } while (0)
#define TIMER_NOW()   \
    ({ uint32_t t; __asm__ volatile ("rdtime %0" : "=r"(t)); t; })

#else

#define MON_TEXT   0x08002000u
#define ATK_TEXT   0x08004000u
#define MON_BOX    0x20004000u
#define ATK_BOX    0x20008000u
#define SUP_STACK  0x20003F00u
#define MON_STACK  0x20005F00u
#define ATK_STACK  0x20009F00u
#define STATUS      ((volatile uint32_t *)0x20000100u)
#define STATUS_NAME ((volatile char *)0x20000110u)
#define MAILBOX    ((volatile uint32_t *)0x20002000u)
#define MB_DATA     ((volatile uint8_t *)(0x20002000u + 8u))
#define STK_CTLR (*(volatile uint32_t *)0xE000F000u)
#define STK_CNT  (*(volatile uint32_t *)0xE000F008u)
#define TIMER_INIT()  do { STK_CTLR |= 1u; } while (0)
#define TIMER_NOW()   (STK_CNT)

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

/* PMP NAPOT encodings, derived from the map */
#define NAPOT(base, size) (((base) >> 2) | ((size) >> 3) - 1u)
#define MON_RAM_PMP   NAPOT(MON_BOX, 8192u)
#define MON_FLASH_PMP NAPOT(MON_TEXT, 8192u)
#define ATK_RAM_PMP   NAPOT(ATK_BOX, 8192u)
#define ATK_FLASH_PMP NAPOT(ATK_TEXT, 8192u)
#define PMP_DENY      0xFFFFFFFFu
