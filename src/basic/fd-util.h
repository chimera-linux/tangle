/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/file.h>

#include "macro.h"
#include "stdio-util.h"

/* Make sure we can distinguish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd)+1)
#define PTR_TO_FD(p) (PTR_TO_INT(p)-1)

int close_nointr(int fd);
int safe_close(int fd);

int fclose_nointr(FILE *f);
FILE* safe_fclose(FILE *f);

static inline void closep(int *fd) {
        safe_close(*fd);
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

int fd_get_path(int fd, char **ret);

int fd_move_above_stdio(int fd);

/* Like TAKE_PTR() but for file descriptors, resetting them to -EBADF */
#define TAKE_FD(fd) TAKE_GENERIC(fd, int, -EBADF)

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
