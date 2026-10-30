/* V7: stdout and stderr are cut at limit + 1 bytes. argv[1] = 1 (stdout) or 2 (stderr). */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    static char buf[65536];
    int fd = argc > 1 ? atoi(argv[1]) : 1;
    for (unsigned i = 0; i < sizeof buf; i++) buf[i] = 'A' + (char)(i % 26);
    for (;;)
        if (write(fd, buf, sizeof buf) < 0) return 6;
}
