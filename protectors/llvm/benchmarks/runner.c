#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern uint64_t shield_kernel(uint64_t, uint64_t);

int main(int argc, char **argv) {
  uint64_t iterations = argc == 2 ? strtoull(argv[1], NULL, 10) : 20000000;
  uint64_t x = UINT64_C(0x0123456789abcdef);
  struct timespec begin, end;
  if (clock_gettime(CLOCK_MONOTONIC, &begin))
    return 1;
  for (uint64_t i = 0; i < iterations; ++i)
    x = shield_kernel(x, i ^ UINT64_C(0xfedcba9876543210));
  if (clock_gettime(CLOCK_MONOTONIC, &end))
    return 1;
  double elapsed = (double)(end.tv_sec - begin.tv_sec) +
                   (double)(end.tv_nsec - begin.tv_nsec) * 1e-9;
  printf("{\"seconds\": %.9f, \"checksum\": \"%016" PRIx64 "\"}\n", elapsed, x);
  return 0;
}
