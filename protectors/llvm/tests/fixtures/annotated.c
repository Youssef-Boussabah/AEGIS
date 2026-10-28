#include <stdint.h>

__attribute__((annotate("aegis.protect"), noinline)) uint32_t
selected(uint32_t a, uint32_t b) {
  return a + b;
}

__attribute__((annotate("aegis.protect.extra"), noinline)) uint32_t
other_annotation(uint32_t a, uint32_t b) {
  return a + b;
}

__attribute__((noinline)) uint32_t plain(uint32_t a, uint32_t b) {
  return a + b;
}
