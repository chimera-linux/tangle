/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "memory-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

int fd_set_sndbuf(int fd, size_t n, bool increase) {
        int r, value;
        socklen_t l = sizeof(value);

        if (n > INT_MAX)
                return -ERANGE;

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 0;

        /* First, try to set the buffer size with SO_SNDBUF. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUF, n);
        if (r < 0)
                return r;

        /* SO_SNDBUF above may set to the kernel limit, instead of the requested size.
         * So, we need to check the actual buffer size here. */
        l = sizeof(value);
        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 1;

        /* If we have the privileges we will ignore the kernel limit. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_SNDBUFFORCE, n);
        if (r < 0)
                return r;

        return 1;
}

int fd_set_rcvbuf(int fd, size_t n, bool increase) {
        int r, value;
        socklen_t l = sizeof(value);

        if (n > INT_MAX)
                return -ERANGE;

        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 0;

        /* First, try to set the buffer size with SO_RCVBUF. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUF, n);
        if (r < 0)
                return r;

        /* SO_RCVBUF above may set to the kernel limit, instead of the requested size.
         * So, we need to check the actual buffer size here. */
        l = sizeof(value);
        r = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && increase ? (size_t) value >= n*2 : (size_t) value == n*2)
                return 1;

        /* If we have the privileges we will ignore the kernel limit. */
        r = setsockopt_int(fd, SOL_SOCKET, SO_RCVBUFFORCE, n);
        if (r < 0)
                return r;

        return 1;
}

int getpeercred(int fd, struct ucred *ucred) {
        socklen_t n = sizeof(struct ucred);
        struct ucred u;

        assert(fd >= 0);
        assert(ucred);

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &u, &n) < 0)
                return -errno;

        if (n != sizeof(struct ucred))
                return -EIO;

        /* Check if the data is actually useful and not suppressed due to namespacing issues */
        if (!pid_is_valid(u.pid))
                return -ENODATA;

        /* Note that we don't check UID/GID here, as namespace translation works differently there: instead of
         * receiving in "invalid" user/group we get the overflow UID/GID. */

        *ucred = u;
        return 0;
}

int getpeersec(int fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        socklen_t n = 64;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                s = new0(char, n+1);
                if (!s)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, s, &n) >= 0) {
                        s[n] = 0;
                        break;
                }

                if (errno != ERANGE)
                        return -errno;

                s = mfree(s);
        }

        if (isempty(s))
                return -EOPNOTSUPP;

        *ret = TAKE_PTR(s);

        return 0;
}

int getpeergroups(int fd, gid_t **ret) {
        socklen_t n = sizeof(gid_t) * 64U;
        _cleanup_free_ gid_t *d = NULL;

        assert(fd >= 0);
        assert(ret);

        long ngroups_max = sysconf(_SC_NGROUPS_MAX);
        if (ngroups_max > 0)
                n = MAX(n, sizeof(gid_t) * (socklen_t) ngroups_max);

        for (;;) {
                d = malloc(n);
                if (!d)
                        return -ENOMEM;

                if (getsockopt(fd, SOL_SOCKET, SO_PEERGROUPS, d, &n) >= 0)
                        break;

                if (errno != ERANGE)
                        return -errno;

                d = mfree(d);
        }

        assert_se(n % sizeof(gid_t) == 0);
        n /= sizeof(gid_t);

        if (n > INT_MAX)
                return -E2BIG;

        *ret = TAKE_PTR(d);

        return (int) n;
}

int getpeerpidfd(int fd) {
        socklen_t n = sizeof(int);
        int pidfd = -EBADF;

        assert(fd >= 0);

        if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &n) < 0)
                return -errno;

        if (n != sizeof(int))
                return -EIO;

        return pidfd;
}

static int connect_unix_path_simple(int fd, const char *path) {
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
        };
        size_t l;

        assert(fd >= 0);
        assert(path);

        l = strlen(path);
        assert(l > 0);
        assert(l < sizeof(sa.un.sun_path));

        memcpy(sa.un.sun_path, path, l + 1);
        return RET_NERRNO(connect(fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + l + 1));
}

static int connect_unix_inode(int fd, int inode_fd) {
        assert(fd >= 0);
        assert(inode_fd >= 0);

        return connect_unix_path_simple(fd, FORMAT_PROC_FD_PATH(inode_fd));
}

int connect_unix_path(int fd, int dir_fd, const char *path) {
        _cleanup_close_ int inode_fd = -EBADF;

        assert(fd >= 0);
        assert(dir_fd == AT_FDCWD || dir_fd >= 0);

        /* Connects to the specified AF_UNIX socket in the file system. Works around the 108 byte size limit
         * in sockaddr_un, by going via O_PATH if needed. This hence works for any kind of path. */

        if (!path)
                return connect_unix_inode(fd, dir_fd); /* If no path is specified, then dir_fd refers to the socket inode to connect to. */

        /* Refuse zero length path early, to make sure AF_UNIX stack won't mistake this for an abstract
         * namespace path, since first char is NUL */
        if (isempty(path))
                return -EINVAL;

        /* Shortcut for the simple case */
        if (dir_fd == AT_FDCWD && strlen(path) < sizeof_field(struct sockaddr_un, sun_path))
                return connect_unix_path_simple(fd, path);

        /* If dir_fd is specified, then we need to go the indirect O_PATH route, because connectat() does not
         * exist. If the path is too long, we also need to take the indirect route, since we can't fit this
         * into a sockaddr_un directly. */

        inode_fd = openat(dir_fd, path, O_PATH|O_CLOEXEC);
        if (inode_fd < 0)
                return -errno;

        return connect_unix_inode(fd, inode_fd);
}

ssize_t recvmsg_safe(int sockfd, struct msghdr *msg, int flags) {
        ssize_t n;

        /* A wrapper around recvmsg() that checks for MSG_CTRUNC, and turns it into an error, in a reasonably
         * safe way, closing any SCM_RIGHTS fds in the error path.
         *
         * Note that unlike our usual coding style this might modify *msg on failure. */

        n = recvmsg(sockfd, msg, flags);
        if (n < 0)
                return -errno;

        if (FLAGS_SET(msg->msg_flags, MSG_CTRUNC)) {
                cmsg_close_all(msg);
                return -EXFULL; /* a recognizable error code */
        }

        return n;
}

int sockaddr_un_set_path(struct sockaddr_un *ret, const char *path) {
        size_t l;

        assert(ret);
        assert(path);

        /* Initialize ret->sun_path from the specified argument. This will interpret paths starting with '@' as
         * abstract namespace sockets, and those starting with '/' as regular filesystem sockets. It won't accept
         * anything else (i.e. no relative paths), to avoid ambiguities. Note that this function cannot be used to
         * reference paths in the abstract namespace that include NUL bytes in the name. */

        l = strlen(path);
        if (l < 2)
                return -EINVAL;
        if (!IN_SET(path[0], '/', '@'))
                return -EINVAL;

        /* Don't allow paths larger than the space in sockaddr_un. Note that we are a tiny bit more restrictive than
         * the kernel is: we insist on NUL termination (both for abstract namespace and regular file system socket
         * addresses!), which the kernel doesn't. We do this to reduce chance of incompatibility with other apps that
         * do not expect non-NUL terminated file system path. */
        if (l+1 > sizeof(ret->sun_path))
                return path[0] == '@' ? -EINVAL : -ENAMETOOLONG; /* return a recognizable error if this is
                                                                  * too long to fit into a sockaddr_un, but
                                                                  * is a file system path, and thus might be
                                                                  * connectible via O_PATH indirection. */

        *ret = (struct sockaddr_un) {
                .sun_family = AF_UNIX,
        };

        if (path[0] == '@') {
                /* Abstract namespace socket */
                memcpy(ret->sun_path + 1, path + 1, l); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l); /* 🔥 *don't* 🔥 include trailing NUL in size */

        } else {
                assert(path[0] == '/');

                /* File system socket */
                memcpy(ret->sun_path, path, l + 1); /* copy *with* trailing NUL byte */
                return (int) (offsetof(struct sockaddr_un, sun_path) + l + 1); /* include trailing NUL in size */
        }
}
