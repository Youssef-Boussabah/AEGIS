/* C0 positive control: compile, run, read one argument, report identity. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include "canary.h"

int main(int argc, char **argv) {
    unsigned long v = argc > 1 ? strtoul(argv[1], NULL, 10) : 0;
    printf("AEGIS-CANARY control value=%lu uid=%u\n", v + 1, (unsigned)getuid());
    return 0;
}
