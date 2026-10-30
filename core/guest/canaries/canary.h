/* Shared helpers for the AEGIS containment canaries (trusted fixtures, Role A).
 * Each canary prints exactly one line: "AEGIS-CANARY <name> key=value ...".
 * Results are errno names or fixed tokens, so output is deterministic. */
#ifndef AEGIS_CANARY_H
#define AEGIS_CANARY_H
#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *aegis_errname(int err) {
    switch (err) {
    case 0: return "OK";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EROFS: return "EROFS";
    case ENOENT: return "ENOENT";
    case ENETUNREACH: return "ENETUNREACH";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ECONNRESET: return "ECONNRESET";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EINVAL: return "EINVAL";
    case ENOSPC: return "ENOSPC";
    case EFBIG: return "EFBIG";
    case EAGAIN: return "EAGAIN";
    case ENODEV: return "ENODEV";
    case ENOSYS: return "ENOSYS";
    case EINPROGRESS: return "EINPROGRESS";
    default: return "EOTHER";
    }
}
#endif
