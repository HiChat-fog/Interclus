/* libgcc-style 64-bit helpers for RV32. eBPF is a 64-bit ISA, the core is
 * not; the __muldi3-style names must stay so clang emits calls to them. */

#include <stdint.h>

void *memset(void *dst, int c, unsigned int n) {
    unsigned char *d = (unsigned char *)dst;
    unsigned char v = (unsigned char)c;
    while (n--) { *d++ = v; }
    return dst;
}

void *memcpy(void *dst, const void *src, unsigned int n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) { *d++ = *s++; }
    return dst;
}

unsigned long long __ashldi3(unsigned long long a, int b) {
    unsigned int lo = (unsigned int)a;
    unsigned int hi = (unsigned int)((unsigned long long)a >> 32);
    b &= 63;
    if (b >= 32)      { hi = lo << (b - 32); lo = 0; }
    else if (b > 0)   { hi = (hi << b) | (lo >> (32 - b)); lo = lo << b; }
    return ((unsigned long long)hi << 32) | lo;
}

unsigned long long __lshrdi3(unsigned long long a, int b) {
    unsigned int lo = (unsigned int)a;
    unsigned int hi = (unsigned int)((unsigned long long)a >> 32);
    b &= 63;
    if (b >= 32)      { lo = hi >> (b - 32); hi = 0; }
    else if (b > 0)   { lo = (lo >> b) | (hi << (32 - b)); hi = hi >> b; }
    return ((unsigned long long)hi << 32) | lo;
}

long long __ashrdi3(long long a, int b) {
    unsigned int lo = (unsigned int)(unsigned long long)a;
    int hi = (int)((unsigned long long)a >> 32);
    b &= 63;
    if (b >= 32)      { lo = (unsigned int)(hi >> (b - 32)); hi = hi >> 31; }
    else if (b > 0)   { lo = (lo >> b) | ((unsigned int)hi << (32 - b)); hi = hi >> b; }
    return (long long)(((unsigned long long)(unsigned int)hi << 32) | lo);
}

unsigned long long __muldi3(unsigned long long a, unsigned long long b) {
    unsigned int al = (unsigned int)a, ah = (unsigned int)(a >> 32);
    unsigned int bl = (unsigned int)b, bh = (unsigned int)(b >> 32);
    unsigned long long ll = (unsigned long long)al * bl;
    unsigned long long lh = (unsigned long long)al * bh;
    unsigned long long hl = (unsigned long long)ah * bl;
    return ll + ((lh + hl) << 32); 
}

/* restoring division: one bit per iteration, 64 rounds */
static unsigned long long udivmod(unsigned long long a, unsigned long long b,
                                  unsigned long long *rem) {
    unsigned long long q = 0, r = 0;
    int i;
    if (b == 0) { if (rem) *rem = 0; return 0; } 
    for (i = 63; i >= 0; i--) {
        r = (r << 1) | ((a >> i) & 1);
        if (r >= b) { r -= b; q |= (unsigned long long)1 << i; }
    }
    if (rem) *rem = r;
    return q;
}

unsigned long long __udivdi3(unsigned long long a, unsigned long long b) {
    return udivmod(a, b, 0);
}

unsigned long long __umoddi3(unsigned long long a, unsigned long long b) {
    unsigned long long r;
    (void)udivmod(a, b, &r);
    return r;
}

long long __divdi3(long long a, long long b) {
    unsigned long long ua = (a < 0) ? -(unsigned long long)a : (unsigned long long)a;
    unsigned long long ub = (b < 0) ? -(unsigned long long)b : (unsigned long long)b;
    unsigned long long q = udivmod(ua, ub, 0);
    return ((a < 0) != (b < 0)) ? -(long long)q : (long long)q;
}

long long __moddi3(long long a, long long b) {
    unsigned long long ua = (a < 0) ? -(unsigned long long)a : (unsigned long long)a;
    unsigned long long ub = (b < 0) ? -(unsigned long long)b : (unsigned long long)b;
    unsigned long long r;
    udivmod(ua, ub, &r);
    return (a < 0) ? -(long long)r : (long long)r;
}
