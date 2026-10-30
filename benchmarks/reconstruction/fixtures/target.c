#include <stdint.h>

/* Owned evaluation targets. Unsigned operations have defined modular semantics. */
__attribute__((noinline, annotate("aegis.protect")))
uint32_t recon_mix(uint32_t x, uint32_t key) {
    x += key;
    x ^= x >> 13;
    x += x << 7;
    x ^= x >> 17;
    return x + UINT32_C(0x9e3779b9);
}

__attribute__((noinline, annotate("aegis.protect")))
uint32_t recon_gate(uint32_t x, uint32_t key) {
    uint32_t v = x + key;
    if ((v & 7u) == 3u)
        return (v ^ UINT32_C(0xa5a5a5a5)) + 17u;
    return (v >> 3) + (key ^ UINT32_C(0x13579bdf));
}
