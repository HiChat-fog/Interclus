/* E42: primitive audit for the trust and transport engines. SHA-256 is
 * the entire weight of the trust gate (E26 pins digests it computes)
 * and CRC16 guards every reliable-update frame (E34). The vectors here:
 * the FIPS 180-4 one-shot examples, the million-'a' vector, a CRC-16
 * MODBUS check value, and a printable differential block — every
 * boundary length 0..136 and a long pattern — that the drill verifies
 * against hashlib and the Python CRC twin. Any wrong round constant,
 * padding bug, or polynomial drift shows up as a mismatched line. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void sha256(const uint8_t *data, uint32_t len, uint8_t out[32]);
#include "../core/update.h"

static void put_line(const char *tag, const uint8_t *d, unsigned n) {
    printf("%s%u ", tag, n);
    for (unsigned i = 0; i < 32u; i++) printf("%02x", d[i]);
    printf("\n");
}

int main(void) {
    uint8_t d[32];
    unsigned fails = 0;

    /* FIPS 180-4 one-shot examples */
    sha256((const uint8_t *)"", 0u, d);
    put_line("SHA", d, 0u);
    sha256((const uint8_t *)"abc", 3u, d);
    put_line("SHA", d, 3u);
    {
        const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256((const uint8_t *)m, (uint32_t)strlen(m), d);
        put_line("SHA", d, (uint32_t)strlen(m));
    }
    {
        /* million 'a': forces many compression blocks */
        static uint8_t big[1000000];
        memset(big, 'a', sizeof big);
        sha256(big, sizeof big, d);
        put_line("SHA", d, 1000000u);
    }
    /* the printable differential block: every boundary length through
     * the padding logic; hashlib checks each digest */
    for (unsigned n = 0; n <= 136u; n++) {
        uint8_t buf[136];
        for (unsigned i = 0; i < n; i++)
            buf[i] = (uint8_t)(0x20u + ((i * 7u + n) % 0x5Fu));
        sha256(buf, n, d);
        put_line("SHAL", d, n);
    }
    /* long block crossing many 64-byte windows */
    for (unsigned n = 200u; n <= 600u; n += 13u) {
        uint8_t buf[600];
        for (unsigned i = 0; i < n; i++)
            buf[i] = (uint8_t)(0x41u + (i % 26u));
        sha256(buf, n, d);
        put_line("SHAL", d, n);
    }

    /* CRC-16/REFLECT (poly 0xA001) == MODBUS: the check value over
     * "123456789" is 0x4B37 */
    {
        uint8_t v[9];
        memcpy(v, "123456789", 9);
        uint16_t c = update_crc16(v, 9u);
        printf("CRC9 %04x\n", c);
        if (c != 0x4B37u) fails++;
    }
    /* printable differential block for the Python twin */
    for (unsigned n = 0; n <= 600u; n += 7u) {
        uint8_t buf[600];
        for (unsigned i = 0; i < n; i++)
            buf[i] = (uint8_t)(0x30u + ((i * 5u + n) % 0x4Fu));
        printf("CRCL%u %04x\n", n, update_crc16(buf, n));
    }

    printf(fails ? "PRIM FAIL (%u)\n" : "PRIM PASS (%u)\n", fails);
    return fails != 0;
}
