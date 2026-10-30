/* V2 / V3: no host files, read-only system image, no device or mount escape, no setuid files. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include "canary.h"

static int open_err(const char *path, int flags) {
    int fd = open(path, flags, 0600);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

static const char *presence(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 ? "present" : "absent";
}

static long setid_files(const char *dir, int depth) {
    long n = 0;
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[4096];
    struct stat st;
    if (!d || depth > 8) { if (d) closedir(d); return 0; }
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (lstat(path, &st) != 0) continue;
        if (S_ISREG(st.st_mode) && (st.st_mode & (S_ISUID | S_ISGID))) n++;
        if (S_ISDIR(st.st_mode)) n += setid_files(path, depth + 1);
    }
    closedir(d);
    return n;
}

int main(void) {
    int mnt = mount("tmpfs", "/tmp", "tmpfs", 0, NULL) == 0 ? 0 : errno;
    int chr = chroot("/") == 0 ? 0 : errno;
    int userns = unshare(CLONE_NEWUSER) == 0 ? 0 : errno;
    printf("AEGIS-CANARY fs home=%s host_root=%s kvm=%s write_root=%s write_usr=%s write_etc=%s "
           "vda_rw=%s vda_ro=%s proc1_environ=%s proc1_mem=%s mount=%s chroot=%s userns=%s "
           "setid=%ld scratch=%s\n",
           presence("/home"), presence("/root/.ssh"), presence("/dev/kvm"),
           aegis_errname(open_err("/aegis-probe", O_WRONLY | O_CREAT)),
           aegis_errname(open_err("/usr/bin/aegis-probe", O_WRONLY | O_CREAT)),
           aegis_errname(open_err("/etc/aegis-probe", O_WRONLY | O_CREAT)),
           aegis_errname(open_err("/dev/vda", O_RDWR)), aegis_errname(open_err("/dev/vda", O_RDONLY)),
           aegis_errname(open_err("/proc/1/environ", O_RDONLY)), aegis_errname(open_err("/proc/1/mem", O_RDONLY)),
           aegis_errname(mnt), aegis_errname(chr), aegis_errname(userns), setid_files("/usr", 0),
           aegis_errname(open_err("probe", O_WRONLY | O_CREAT)));
    return 0;
}
