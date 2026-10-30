/* V5 / F4: touched memory is stopped by the job's memory limit; the VM survives. */
#define _GNU_SOURCE
#include <stdlib.h>
#include "canary.h"

int main(void) {
    for (;;) {
        char *p = malloc(1 << 20);
        if (!p) { printf("AEGIS-CANARY memory malloc=failed\n"); return 5; }
        memset(p, 0xA5, 1 << 20);
    }
}
