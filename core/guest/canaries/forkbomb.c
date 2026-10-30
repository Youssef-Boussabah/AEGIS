/* V4: process exhaustion stops at the job's pids limit. */
#define _GNU_SOURCE
#include <signal.h>
#include <unistd.h>
#include "canary.h"

int main(void) {
    long forks = 0;
    int err = 0;
    for (;;) {
        pid_t pid = fork();
        if (pid == 0) { for (;;) pause(); }
        if (pid < 0) { err = errno; break; }
        if (++forks > 100000) break;
    }
    printf("AEGIS-CANARY forkbomb forks=%ld errno=%s\n", forks, aegis_errname(err));
    fflush(stdout);
    return 3; /* non-zero: the agent attributes it to the pids limit */
}
