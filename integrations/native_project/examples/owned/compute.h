#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
uint32_t mix_pair(uint32_t a, uint32_t b);
uint32_t fold_word(uint32_t a, uint32_t b);
uint32_t step_byte(uint32_t state, uint32_t value);
#ifdef __cplusplus
}
int classify(int value);
#endif
