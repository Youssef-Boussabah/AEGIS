#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint32_t width2(uint32_t, uint32_t);
extern uint32_t width3(uint32_t, uint32_t);
extern uint32_t width7(uint32_t, uint32_t);
extern uint32_t width8(uint32_t, uint32_t);
extern uint32_t width16(uint32_t, uint32_t);
extern uint32_t width32(uint32_t, uint32_t);
extern uint64_t width64(uint64_t, uint64_t);
extern __uint128_t width65(__uint128_t, __uint128_t);
extern __uint128_t width127(__uint128_t, __uint128_t);
extern __uint128_t width128(__uint128_t, __uint128_t);
extern uint64_t chain(uint64_t, uint64_t);
extern uint32_t cycle(uint32_t, uint32_t);
extern uint64_t twice(uint64_t);
extern uint64_t constant(void);

static uint64_t state = UINT64_C(0x123456789abcdef0);
static uint64_t random64(void) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}
static uint64_t digest;
static void check(uint64_t actual, uint64_t expected) {
  if (actual != expected) {
    fprintf(stderr, "mismatch: %" PRIu64 " != %" PRIu64 "\n", actual, expected);
    exit(1);
  }
  digest = (digest ^ actual) * UINT64_C(0x100000001b3);
}
static void pair(uint64_t a, uint64_t b) {
  check(width2(a, b), (a + b) & 3);
  check(width3(a, b), (a + b) & 7);
  check(width7(a, b), (a + b) & 127);
  check(width8(a, b), (a + b) & 255);
  check(width16(a, b), (a + b) & 65535);
  check(width32(a, b), (uint32_t)(a + b));
  check(width64(a, b), a + b);
  __uint128_t x = ((__uint128_t)a << 64) | b;
  __uint128_t y = ((__uint128_t)b << 64) | a;
  __uint128_t actual = width128(x, y), expected = x + y;
  check((uint64_t)actual, (uint64_t)expected);
  check((uint64_t)(actual >> 64), (uint64_t)(expected >> 64));
  actual = width65(x, y);
  check((uint64_t)actual, (uint64_t)expected);
  check((uint64_t)(actual >> 64), (uint64_t)(expected >> 64) & 1);
  actual = width127(x, y);
  check((uint64_t)actual, (uint64_t)expected);
  check((uint64_t)(actual >> 64),
        (uint64_t)(expected >> 64) & UINT64_C(0x7fffffffffffffff));
  check(chain(a, b), ((((a + b) ^ (a + 17)) + b) ^ a) + UINT64_MAX);
  check(twice(a), a + a);
}
int main(void) {
  // Exhaust every pair of 8-bit inputs, including all i2 pairs.
  for (unsigned a = 0; a < 256; ++a)
    for (unsigned b = 0; b < 256; ++b)
      pair(a, b);
  const uint64_t edges[] = {0,
                            1,
                            2,
                            127,
                            128,
                            255,
                            256,
                            65535,
                            65536,
                            UINT32_MAX,
                            UINT64_C(0x7fffffffffffffff),
                            UINT64_C(0x8000000000000000),
                            UINT64_MAX};
  for (unsigned i = 0; i < sizeof(edges) / sizeof(*edges); ++i)
    for (unsigned j = 0; j < sizeof(edges) / sizeof(*edges); ++j)
      pair(edges[i], edges[j]);
  for (unsigned i = 0; i < 100000; ++i) {
    uint64_t a = random64(), b = random64();
    pair(a, b);
    uint32_t n = b & 31;
    check(cycle(a, n), (uint32_t)a * n);
  }
  check(constant(), 0);
  printf("%016" PRIx64 "\n", digest);
  return 0;
}
