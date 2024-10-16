/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "macro.h"
#include "stdio-util.h"

/* Make sure we can distinguish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd)+1)
#define PTR_TO_FD(p) (PTR_TO_INT(p)-1)

/* Useful helpers for initializing pipe(), socketpair() or stdio fd arrays */
#define EBADF_PAIR { -EBADF, -EBADF }
#define EBADF_TRIPLET { -EBADF, -EBADF, -EBADF }

int close_nointr(int fd);
int safe_close(int fd);
void safe_close_pair(int p[]);

static inline int safe_close_above_stdio(int fd) {
        if (fd < 3) /* Don't close stdin/stdout/stderr, but still invalidate the fd by returning -EBADF. */
                return -EBADF;

        return safe_close(fd);
}

int fclose_nointr(FILE *f);
FILE* safe_fclose(FILE *f);

void close_many(const int fds[], size_t n_fds);

static inline void closep(int *fd) {
        safe_close(*fd);
}

static inline void close_pairp(int (*p)[2]) {
        safe_close_pair(*p);
}

static inline void fclosep(FILE **f) {
        safe_fclose(*f);
}

static inline void* close_fd_ptr(void *p) {
        safe_close(PTR_TO_FD(p));
        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, pclose, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(DIR*, closedir, NULL);

#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)
#define _cleanup_close_pair_ _cleanup_(close_pairp)

int fd_nonblock(int fd, bool nonblock);
int stdio_disable_nonblock(void);

int fd_cloexec(int fd, bool cloexec);

int close_all_fds(const int except[], size_t n_except);

void cmsg_close_all(struct msghdr *mh);

int fd_get_path(int fd, char **ret);

int fd_move_above_stdio(int fd);

int rearrange_stdio(int original_input_fd, int original_output_fd, int original_error_fd);

static inline int make_null_stdio(void) {
        return rearrange_stdio(-EBADF, -EBADF, -EBADF);
}

/* Like TAKE_PTR() but for file descriptors, resetting them to -EBADF */
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

/* Like free_and_replace(), but for file descriptors */
#define close_and_replace(a, b)                 \
        ({                                      \
                int *_fdp_ = &(a);              \
                safe_close(*_fdp_);             \
                *_fdp_ = TAKE_FD(b);            \
                0;                              \
        })

int fd_reopen(int fd, int flags);

int fd_is_opath(int fd);

/* The maximum length a buffer for a /proc/self/fd/<fd> path needs */
#define PROC_FD_PATH_MAX \
        (STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int))

static inline char *format_proc_fd_path(char buf[static PROC_FD_PATH_MAX], int fd) {
        assert(buf);
        assert(fd >= 0);
        assert_se(snprintf_ok(buf, PROC_FD_PATH_MAX, "/proc/self/fd/%i", fd));
        return buf;
}

#define FORMAT_PROC_FD_PATH(fd) \
        format_proc_fd_path((char[PROC_FD_PATH_MAX]) {}, (fd))

bool stat_inode_same(const struct stat *a, const struct stat *b);

int inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);
static inline int inode_same(const char *filea, const char *fileb, int flags) {
        return inode_same_at(AT_FDCWD, filea, AT_FDCWD, fileb, flags);
}
static inline int fd_inode_same(int fda, int fdb) {
        return inode_same_at(fda, NULL, fdb, NULL, AT_EMPTY_PATH);
}

#define laccess(path, mode)                                             \
        RET_NERRNO(faccessat(AT_FDCWD, (path), (mode), AT_SYMLINK_NOFOLLOW))
