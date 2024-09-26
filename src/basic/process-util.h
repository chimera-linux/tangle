/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "format-util.h"
#include "macro.h"
#include "time-util.h"

#define procfs_file_alloca(pid, field)                                  \
        ({                                                              \
                pid_t _pid_ = (pid);                                    \
                const char *_field_ = (field);                          \
                char *_r_;                                              \
                if (_pid_ == 0) {                                       \
                        _r_ = newa(char, STRLEN("/proc/self/") + strlen(_field_) + 1); \
                        strcpy(stpcpy(_r_, "/proc/self/"), _field_);    \
                } else {                                                \
                        _r_ = newa(char, STRLEN("/proc/") + DECIMAL_STR_MAX(pid_t) + 1 + strlen(_field_) + 1); \
                        sprintf(_r_, "/proc/" PID_FMT "/%s", _pid_, _field_); \
                }                                                       \
                (const char*) _r_;                                      \
        })

int pid_get_comm(pid_t pid, char **ret);
int get_process_exe(pid_t pid, char **ret);

int container_get_leader(const char *machine, pid_t *pid);

typedef enum WaitFlags {
        WAIT_LOG_ABNORMAL             = 1 << 0,
        WAIT_LOG_NON_ZERO_EXIT_STATUS = 1 << 1,

        /* A shortcut for requesting the most complete logging */
        WAIT_LOG = WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS,
} WaitFlags;

int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags);

void sigterm_wait(pid_t pid);

int pid_is_unwaited(pid_t pid);

static inline bool pid_is_valid(pid_t p) {
        return p > 0;
}

pid_t getpid_cached(void);

typedef enum ForkFlags {
        FORK_RESET_SIGNALS      = 1 <<  0, /* Reset all signal handlers and signal mask */
        FORK_CLOSE_ALL_FDS      = 1 <<  1, /* Close all open file descriptors in the child, except for 0,1,2 */
        FORK_DEATHSIG_SIGTERM   = 1 <<  2, /* Set PR_DEATHSIG in the child to SIGTERM */
        FORK_DEATHSIG_SIGINT    = 1 <<  3, /* Set PR_DEATHSIG in the child to SIGINT */
        FORK_DEATHSIG_SIGKILL   = 1 <<  4, /* Set PR_DEATHSIG in the child to SIGKILL */
        FORK_REARRANGE_STDIO    = 1 <<  5, /* Connect 0,1,2 to specified fds or /dev/null */
        FORK_WAIT               = 1 <<  6, /* Wait until child exited */
        FORK_RLIMIT_NOFILE_SAFE = 1 <<  7, /* Set RLIMIT_NOFILE soft limit to 1K for select() compat */
} ForkFlags;

int safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid);

static inline int safe_fork(const char *name, ForkFlags flags, pid_t *ret_pid) {
        return safe_fork_full(name, NULL, NULL, 0, flags, ret_pid);
}

int namespace_fork(
                const char *outer_name,
                const char *inner_name,
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                int pidns_fd,
                int mntns_fd,
                int netns_fd,
                int userns_fd,
                int root_fd,
                pid_t *ret_pid);

/* Like TAKE_PTR() but for pid_t, resetting them to 0 */
#define TAKE_PID(pid) TAKE_GENERIC(pid, pid_t, 0)
