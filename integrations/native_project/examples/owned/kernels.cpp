#include "compute.h"

// Explicit symbol selection in project.json: source need not carry annotations.
extern "C" __attribute__((noinline)) uint32_t mix_pair(uint32_t a, uint32_t b) {
    return (a + b) ^ ((a << 7) + (b >> 3));
}

extern "C" __attribute__((noinline)) uint32_t fold_word(uint32_t a, uint32_t b) {
    uint32_t x = a + 0x9e3779b9u;
    return (x ^ (x >> 16)) + b;
}
