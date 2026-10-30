/* V11: a detached background process does not outlive the job or the VM. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include "canary.h"

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        if (fork() != 0) _exit(0);
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0); dup2(null, 1); dup2(null, 2);
        for (;;) sleep(1);
    }
    printf("AEGIS-CANARY orphan spawned=%s\n", pid > 0 ? "yes" : "no");
    return 0;
}
