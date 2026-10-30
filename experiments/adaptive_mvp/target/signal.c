/* Trusted, AEGIS-owned fixture. This is never model output. */
#include <stdint.h>
#include <stdio.h>

__attribute__((annotate("aegis.protect"), noinline))
uint32_t signal_mix(uint32_t a, uint32_t b, uint32_t c) {
    return (a * 3u) + (b ^ c) + 0x9e3779b9u;
}

int main(void) {
    uint32_t state = 42u, hash = 0u;
    for (unsigned i = 0; i < 1000000; ++i) {
        state = state * 1664525u + 1013904223u;
        hash ^= signal_mix(state, i, state >> 16);
    }
    printf("%08x\n", hash);
    return 0;
}
