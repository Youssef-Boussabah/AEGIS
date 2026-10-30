/* V5: writes stop at the scratch bound (tmpfs size or RLIMIT_FSIZE). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include "canary.h"

int main(void) {
    static char buf[65536];
    long written = 0;
    int err = 0;
    signal(SIGXFSZ, SIG_IGN);
    memset(buf, 0x5A, sizeof buf);
    int fd = open("fill", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) err = errno;
    while (fd >= 0) {
        ssize_t n = write(fd, buf, sizeof buf);
        if (n <= 0) { err = n < 0 ? errno : ENOSPC; break; }
        written += n;
    }
    printf("AEGIS-CANARY scratch written=%ld errno=%s\n", written, aegis_errname(err));
    return 4;
}
