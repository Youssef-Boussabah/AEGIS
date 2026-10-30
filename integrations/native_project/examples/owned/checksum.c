#include "compute.h"

// Demonstrate the existing source annotation path alongside symbol selection.
__attribute__((annotate("aegis.protect"), noinline))
uint32_t step_byte(uint32_t state, uint32_t value) {
    return (state ^ value) + ((state << 5) | (state >> 27));
}
