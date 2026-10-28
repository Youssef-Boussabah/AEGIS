#include <stdint.h>

__attribute__((noinline, annotate("aegis.protect"))) uint64_t
shield_kernel(uint64_t x, uint64_t key) {
  x += key;
  x ^= x >> 17;
  x += x << 11;
  x ^= x >> 23;
  x += UINT64_C(0x9e3779b97f4a7c15);
  return x + key;
}
