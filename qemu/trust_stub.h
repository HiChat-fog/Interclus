/* shared test helper: append a SHA-256 trailer over the staged bytes so
 * the images pass the E26 trust gate. The real digest comes from
 * core/sha256.c — tests include it directly. */
extern void sha256(const uint8_t *data, uint32_t len,
                   uint8_t out[32]);

static void trust_stamp(volatile uint8_t *pend, uint32_t body) {
    uint8_t d[32];
    sha256((const uint8_t *)pend, body, d);
    for (uint32_t k = 0; k < 32u; k++) pend[body + k] = d[k];
}
