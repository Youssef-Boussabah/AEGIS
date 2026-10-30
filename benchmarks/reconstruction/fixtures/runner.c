#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint32_t recon_mix(uint32_t, uint32_t);
extern uint32_t recon_gate(uint32_t, uint32_t);

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--cases") == 0) {
        unsigned function;
        uint32_t a, b;
        while (scanf("%u %" SCNu32 " %" SCNu32, &function, &a, &b) == 3) {
            if (function > 1u) return 2;
            uint32_t result = function == 0u ? recon_mix(a, b) : recon_gate(a, b);
            printf("%" PRIu32 "\n", result);
        }
        return ferror(stdin) ? 3 : 0;
    }
    if (argc == 3 && strcmp(argv[1], "--bench") == 0) {
        char *end;
        unsigned long count = strtoul(argv[2], &end, 10);
        if (*end || count == 0 || count > 100000000ul) return 2;
        uint32_t x = UINT32_C(0x12345678);
        for (unsigned long i = 0; i < count; ++i) {
            x = recon_mix(x, (uint32_t)i);
            x = recon_gate(x, (uint32_t)i ^ UINT32_C(0xfedcba98));
        }
        printf("%" PRIu32 "\n", x);
        return 0;
    }
    return 2;
}
