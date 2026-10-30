/* V1 / F2-guest: no network path out of the guest. Every attempt must fail. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "canary.h"

static int try_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (fd < 0) return errno;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    int rc = connect(fd, addr, len), err = rc == 0 ? 0 : errno;
    if (rc != 0 && err == EINPROGRESS) {
        struct pollfd p = {fd, POLLOUT, 0};
        if (poll(&p, 1, 1000) == 1) {
            socklen_t sl = sizeof err;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &sl);
        } else {
            err = ETIMEDOUT;
        }
    }
    close(fd);
    return err;
}

static int inet4(int type) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(80)};
    inet_pton(AF_INET, "192.0.2.1", &a.sin_addr); /* TEST-NET-1, never routable */
    int fd = socket(AF_INET, type, 0);
    if (type == SOCK_DGRAM && fd >= 0) {
        int rc = (int)sendto(fd, "x", 1, 0, (struct sockaddr *)&a, sizeof a), err = rc < 0 ? errno : 0;
        close(fd);
        return err;
    }
    return try_connect(fd, (struct sockaddr *)&a, sizeof a);
}

static int inet6(void) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
    inet_pton(AF_INET6, "2001:db8::1", &a.sin6_addr);
    return try_connect(socket(AF_INET6, SOCK_STREAM, 0), (struct sockaddr *)&a, sizeof a);
}

static int vsock(unsigned cid, unsigned port) {
    struct sockaddr_vm a = {.svm_family = AF_VSOCK, .svm_cid = cid, .svm_port = port};
    return try_connect(socket(AF_VSOCK, SOCK_STREAM, 0), (struct sockaddr *)&a, sizeof a);
}

int main(void) {
    char ifaces[256] = "";
    DIR *d = opendir("/sys/class/net");
    struct dirent *e;
    while (d && (e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (ifaces[0]) strncat(ifaces, "+", sizeof ifaces - strlen(ifaces) - 1);
        strncat(ifaces, e->d_name, sizeof ifaces - strlen(ifaces) - 1);
    }
    if (d) closedir(d);
    int packet = socket(AF_PACKET, SOCK_RAW, 0), packet_err = packet < 0 ? errno : 0;
    if (packet >= 0) close(packet);
    printf("AEGIS-CANARY net inet=%s udp=%s inet6=%s vsock_host=%s vsock_host_agent_port=%s "
           "vsock_self_agent=%s packet=%s ifaces=%s\n",
           aegis_errname(inet4(SOCK_STREAM)), aegis_errname(inet4(SOCK_DGRAM)), aegis_errname(inet6()),
           aegis_errname(vsock(VMADDR_CID_HOST, 1234)), aegis_errname(vsock(VMADDR_CID_HOST, 10000)),
           aegis_errname(vsock(VMADDR_CID_LOCAL, 10000)), aegis_errname(packet_err), ifaces[0] ? ifaces : "none");
    return 0;
}
