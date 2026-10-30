/* V8: unprivileged, capability-free, no_new_privs. */
#define _GNU_SOURCE
#include <grp.h>
#include <stdlib.h>
#include <unistd.h>
#include "canary.h"

static void field(const char *key, char *out, size_t size) {
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    snprintf(out, size, "unknown");
    while (f && fgets(line, sizeof line, f)) {
        if (!strncmp(line, key, strlen(key))) {
            char *v = line + strlen(key);
            while (*v == ' ' || *v == '\t') v++;
            v[strcspn(v, "\n")] = 0;
            snprintf(out, size, "%s", v);
        }
    }
    if (f) fclose(f);
}

int main(void) {
    char cap[64], bnd[64], nnp[16], sec[16];
    field("CapEff:", cap, sizeof cap);
    field("CapBnd:", bnd, sizeof bnd);
    field("NoNewPrivs:", nnp, sizeof nnp);
    field("Seccomp:", sec, sizeof sec);
    printf("AEGIS-CANARY identity uid=%u euid=%u gid=%u egid=%u groups=%d capeff=%s nnp=%s\n",
           (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(), (unsigned)getegid(),
           getgroups(0, NULL), cap, nnp);
    (void)bnd; (void)sec;
    return 0;
}
