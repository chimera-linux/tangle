/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>
#include <linux/vm_sockets.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/un.h>

#include "errno-util.h"
#include "macro.h"

union sockaddr_union {
        /* The minimal, abstract version */
        struct sockaddr sa;

        /* The libc provided version that allocates "enough room" for every protocol */
        struct sockaddr_storage storage;

        /* Protoctol-specific implementations */
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
        struct sockaddr_nl nl;
        struct sockaddr_ll ll;
        struct sockaddr_vm vm;

        /* Ensure there is enough space to store Infiniband addresses */
        uint8_t ll_buffer[offsetof(struct sockaddr_ll, sll_addr) + CONST_MAX(ETH_ALEN, INFINIBAND_ALEN)];

        /* Ensure there is enough space after the AF_UNIX sun_path for one more NUL byte, just to be sure that the path
         * component is always followed by at least one NUL byte. */
        uint8_t un_buffer[sizeof(struct sockaddr_un) + 1];
};

typedef struct SocketAddress {
        union sockaddr_union sockaddr;

        /* We store the size here explicitly due to the weird
         * sockaddr_un semantics for abstract sockets */
        socklen_t size;

        /* Socket type, i.e. SOCK_STREAM, SOCK_DGRAM, ... */
        int type;

        /* Socket protocol, IPPROTO_xxx, usually 0, except for netlink */
        int protocol;
} SocketAddress;

const char* socket_address_type_to_string(int t) _const_;
int socket_address_type_from_string(const char *s) _pure_;

int fd_set_sndbuf(int fd, size_t n, bool increase);
static inline int fd_inc_sndbuf(int fd, size_t n) {
        return fd_set_sndbuf(fd, n, true);
}
int fd_set_rcvbuf(int fd, size_t n, bool increase);
static inline int fd_increase_rxbuf(int fd, size_t n) {
        return fd_set_rcvbuf(fd, n, true);
}

int getpeercred(int fd, struct ucred *ucred);
int getpeersec(int fd, char **ret);
int getpeergroups(int fd, gid_t **ret);
int getpeerpidfd(int fd);

#define CMSG_FOREACH(cmsg, mh)                                          \
        for ((cmsg) = CMSG_FIRSTHDR(mh); (cmsg); (cmsg) = CMSG_NXTHDR((mh), (cmsg)))

/* Returns the cmsghdr's data pointer, but safely cast to the specified type. Does two alignment checks: one
 * at compile time, that the requested type has a smaller or same alignment as 'struct cmsghdr', and one
 * during runtime, that the actual pointer matches the alignment too. This is supposed to catch cases such as
 * 'struct timeval' is embedded into 'struct cmsghdr' on architectures where the alignment of the former is 8
 * bytes (because of a 64-bit time_t), but of the latter is 4 bytes (because size_t is 32 bits), such as
 * riscv32. */
#define CMSG_TYPED_DATA(cmsg, type)                                     \
        ({                                                              \
                struct cmsghdr *_cmsg = (cmsg);                         \
                assert_cc(alignof(type) <= alignof(struct cmsghdr));    \
                _cmsg ? CAST_ALIGN_PTR(type, CMSG_DATA(_cmsg)) : (type*) NULL; \
        })

/* Resolves to a type that can carry cmsghdr structures. Make sure things are properly aligned, i.e. the type
 * itself is placed properly in memory and the size is also aligned to what's appropriate for "cmsghdr"
 * structures. */
#define CMSG_BUFFER_TYPE(size)                                          \
        union {                                                         \
                struct cmsghdr cmsghdr;                                 \
                uint8_t buf[size];                                      \
                uint8_t align_check[(size) >= CMSG_SPACE(0) &&          \
                                    (size) == CMSG_ALIGN(size) ? 1 : -1]; \
        }

/* Covers only file system and abstract AF_UNIX socket addresses, but not unnamed socket addresses. */
#define SOCKADDR_UN_LEN(sa)                                             \
        ({                                                              \
                const struct sockaddr_un *_sa = &(sa);                  \
                assert(_sa->sun_family == AF_UNIX);                     \
                offsetof(struct sockaddr_un, sun_path) +                \
                        (_sa->sun_path[0] == 0 ?                        \
                         1 + strnlen(_sa->sun_path+1, sizeof(_sa->sun_path)-1) : \
                         strnlen(_sa->sun_path, sizeof(_sa->sun_path))+1); \
        })

int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path);

static inline int setsockopt_int(int fd, int level, int optname, int value) {
        if (setsockopt(fd, level, optname, &value, sizeof(value)) < 0)
                return -errno;

        return 0;
}

ssize_t recvmsg_safe(int sockfd, struct msghdr *msg, int flags);

/* an initializer for struct ucred that initialized all fields to the invalid value appropriate for each */
#define UCRED_INVALID { .pid = 0, .uid = UID_INVALID, .gid = GID_INVALID }

int connect_unix_path(int fd, int dir_fd, const char *path);

int sockaddr_port(const struct sockaddr *_sa, unsigned *port);

/* Parses AF_UNIX and AF_VSOCK addresses. AF_INET[6] require some netlink calls, so it cannot be in
 * src/basic/ and is done from 'socket_local_address from src/shared/. Return -EPROTO in case of
 * protocol mismatch. */
int socket_address_parse_unix(SocketAddress *ret_address, const char *s);
int socket_address_parse_vsock(SocketAddress *ret_address, const char *s);
