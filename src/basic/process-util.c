/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/oom.h>
#include <pthread.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <sched.h>

#ifndef TASK_COMM_LEN
#  define TASK_COMM_LEN 16
#endif

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "namespace-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "user-util.h"
#include "utf8.h"

/* The kernel limits userspace processes to TASK_COMM_LEN (16 bytes), but allows higher values for its own
 * workers, e.g. "kworker/u9:3-kcryptd/253:0". Let's pick a fixed smallish limit that will work for the kernel.
 */
#define COMM_MAX_LEN 128

int pid_get_comm(pid_t pid, char **ret) {
        _cleanup_free_ char *escaped = NULL, *comm = NULL;
        int r;

        assert(ret);
        assert(pid >= 0);

        if (pid == 0 || pid == getpid_cached()) {
                comm = new0(char, TASK_COMM_LEN + 1); /* Must fit in 16 byte according to prctl(2) */
                if (!comm)
                        return -ENOMEM;

                if (prctl(PR_GET_NAME, comm) < 0)
                        return -errno;
        } else {
                const char *p;

                p = procfs_file_alloca(pid, "comm");

                /* Note that process names of kernel threads can be much longer than TASK_COMM_LEN */
                r = read_one_line_file(p, &comm);
                if (r == -ENOENT)
                        return -ESRCH;
                if (r < 0)
                        return r;
        }

        escaped = new(char, COMM_MAX_LEN);
        if (!escaped)
                return -ENOMEM;

        /* Escape unprintable characters, just in case, but don't grow the string beyond the underlying size */
        cellescape(escaped, COMM_MAX_LEN, comm);

        *ret = TAKE_PTR(escaped);
        return 0;
}

int container_get_leader(const char *machine, pid_t *pid) {
        (void)machine;
        (void)pid;
        return -EHOSTDOWN;
}

static int get_process_link_contents(pid_t pid, const char *proc_file, char **ret) {
        const char *p;

        assert(proc_file);

        p = procfs_file_alloca(pid, proc_file);

        return readlink_malloc(p, ret);
}

int get_process_exe(pid_t pid, char **ret) {
        char *d;
        int r;

        assert(pid >= 0);

        r = get_process_link_contents(pid, "exe", ret);
        if (r < 0)
                return r;

        if (ret) {
                d = endswith(*ret, " (deleted)");
                if (d)
                        *d = '\0';
        }

        return 0;
}

static int wait_for_terminate(pid_t pid, siginfo_t *status) {
        siginfo_t dummy;

        assert(pid >= 1);

        if (!status)
                status = &dummy;

        for (;;) {
                zero(*status);

                if (waitid(P_PID, pid, status, WEXITED) < 0) {

                        if (errno == EINTR)
                                continue;

                        return negative_errno();
                }

                return 0;
        }
}

/*
 * Return values:
 * < 0 : wait_for_terminate() failed to get the state of the
 *       process, the process was terminated by a signal, or
 *       failed for an unknown reason.
 * >=0 : The process terminated normally, and its exit code is
 *       returned.
 *
 * That is, success is indicated by a return value of zero, and an
 * error is indicated by a non-zero value.
 *
 * A warning is emitted if the process terminates abnormally,
 * and also if it returns non-zero unless check_exit_code is true.
 */
int wait_for_terminate_and_check(const char *name, pid_t pid, WaitFlags flags) {
        _cleanup_free_ char *buffer = NULL;
        siginfo_t status;
        int r, prio;

        assert(pid > 1);

        if (!name) {
                r = pid_get_comm(pid, &buffer);
                if (r < 0)
                        log_debug_errno(r, "Failed to acquire process name of " PID_FMT ", ignoring: %m", pid);
                else
                        name = buffer;
        }

        prio = flags & WAIT_LOG_ABNORMAL ? LOG_ERR : LOG_DEBUG;

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return log_full_errno(prio, r, "Failed to wait for %s: %m", strna(name));

        if (status.si_code == CLD_EXITED) {
                if (status.si_status != EXIT_SUCCESS)
                        log_full(flags & WAIT_LOG_NON_ZERO_EXIT_STATUS ? LOG_ERR : LOG_DEBUG,
                                 "%s failed with exit status %i.", strna(name), status.si_status);
                else
                        log_debug("%s succeeded.", name);

                return status.si_status;

        } else if (IN_SET(status.si_code, CLD_KILLED, CLD_DUMPED)) {

                log_full(prio, "%s terminated by signal %s.", strna(name), signal_to_string(status.si_status));
                return -EPROTO;
        }

        log_full(prio, "%s failed due to unknown reason.", strna(name));
        return -EPROTO;
}

static int kill_and_sigcont(pid_t pid, int sig) {
        int r;

        r = RET_NERRNO(kill(pid, sig));

        /* If this worked, also send SIGCONT, unless we already just sent a SIGCONT, or SIGKILL was sent which isn't
         * affected by a process being suspended anyway. */
        if (r >= 0 && !IN_SET(sig, SIGCONT, SIGKILL))
                (void) kill(pid, SIGCONT);

        return r;
}

void sigterm_wait(pid_t pid) {
        assert(pid > 1);

        (void) kill_and_sigcont(pid, SIGTERM);
        (void) wait_for_terminate(pid, NULL);
}

int pid_is_unwaited(pid_t pid) {
        /* Checks whether a PID is still valid at all, including a zombie */

        if (pid < 0)
                return -ESRCH;

        if (pid <= 1) /* If we or PID 1 would be dead and have been waited for, this code would not be running */
                return true;

        if (pid == getpid_cached())
                return true;

        if (kill(pid, 0) >= 0)
                return true;

        return errno != ESRCH;
}

/* The cached PID, possible values:
 *
 *     == UNSET [0]  → cache not initialized yet
 *     == BUSY [-1]  → some thread is initializing it at the moment
 *     any other     → the cached PID
 */

#define CACHED_PID_UNSET ((pid_t) 0)
#define CACHED_PID_BUSY ((pid_t) -1)

static pid_t cached_pid = CACHED_PID_UNSET;

static void reset_cached_pid(void) {
        /* Invoked in the child after a fork(), i.e. at the first moment the PID changed */
        cached_pid = CACHED_PID_UNSET;
}

static inline pid_t raw_getpid(void) {
#if defined(__alpha__)
        return (pid_t) syscall(__NR_getxpid);
#else
        return (pid_t) syscall(__NR_getpid);
#endif
}

pid_t getpid_cached(void) {
        static bool installed = false;
        pid_t current_value = CACHED_PID_UNSET;

        /* getpid_cached() is much like getpid(), but caches the value in local memory, to avoid having to invoke a
         * system call each time. This restores glibc behaviour from before 2.24, when getpid() was unconditionally
         * cached. Starting with 2.24 getpid() started to become prohibitively expensive when used for detecting when
         * objects were used across fork()s. With this caching the old behaviour is somewhat restored.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=1443976
         * https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=c579f48edba88380635ab98cb612030e3ed8691e
         */

        (void) __atomic_compare_exchange_n(
                        &cached_pid,
                        &current_value,
                        CACHED_PID_BUSY,
                        false,
                        __ATOMIC_SEQ_CST,
                        __ATOMIC_SEQ_CST);

        switch (current_value) {

        case CACHED_PID_UNSET: { /* Not initialized yet, then do so now */
                pid_t new_pid;

                new_pid = raw_getpid();

                if (!installed) {
                        /* __register_atfork() either returns 0 or -ENOMEM, in its glibc implementation. Since it's
                         * only half-documented (glibc doesn't document it but LSB does — though only superficially)
                         * we'll check for errors only in the most generic fashion possible. */

                        if (pthread_atfork(NULL, NULL, reset_cached_pid) != 0) {
                                /* OOM? Let's try again later */
                                cached_pid = CACHED_PID_UNSET;
                                return new_pid;
                        }

                        installed = true;
                }

                cached_pid = new_pid;
                return new_pid;
        }

        case CACHED_PID_BUSY: /* Somebody else is currently initializing */
                return raw_getpid();

        default: /* Properly initialized */
                return current_value;
        }
}

static void restore_sigsetp(sigset_t **ssp) {
        if (*ssp)
                (void) sigprocmask(SIG_SETMASK, *ssp, NULL);
}

static int fork_flags_to_signal(ForkFlags flags) {
        return (flags & FORK_DEATHSIG_SIGTERM) ? SIGTERM :
                (flags & FORK_DEATHSIG_SIGINT) ? SIGINT :
                                                 SIGKILL;
}

static int read_nr_open(void) {
        _cleanup_free_ char *nr_open = NULL;
        int r;

        /* Returns the kernel's current fd limit, either by reading it of /proc/sys if that works, or using the
         * hard-coded default compiled-in value of current kernels (1M) if not. This call will never fail. */

        r = read_one_line_file("/proc/sys/fs/nr_open", &nr_open);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/fs/nr_open, ignoring: %m");
        else {
                long v;
                char *err = NULL;

                v = strtol(nr_open, &err, 10);
                if (!err || *err || v > INT_MAX) {
                        if (v > INT_MAX) errno = ERANGE;
                        log_debug_errno(r, "Failed to parse /proc/sys/fs/nr_open value '%s', ignoring: %m", nr_open);
                } else
                        return v;
        }

        /* If we fail, fall back to the hard-coded kernel limit of 1024 * 1024. */
        return 1024 * 1024;
}


static int rlimit_nofile_safe(void) {
        struct rlimit rl;

        /* Resets RLIMIT_NOFILE's soft limit FD_SETSIZE (i.e. 1024), for compatibility with software still using
         * select() */

        if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
                return log_debug_errno(errno, "Failed to query RLIMIT_NOFILE: %m");

        if (rl.rlim_cur <= FD_SETSIZE)
                return 0;

        /* So we might have inherited a hard limit that's larger than the kernel's maximum limit as stored in
         * /proc/sys/fs/nr_open. If we pass this hard limit unmodified to setrlimit(), we'll get EPERM. To
         * make sure that doesn't happen, let's limit our hard limit to the value from nr_open. */
        rl.rlim_max = MIN(rl.rlim_max, (rlim_t) read_nr_open());
        rl.rlim_cur = MIN((rlim_t) FD_SETSIZE, rl.rlim_max);
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
                return log_debug_errno(errno, "Failed to lower RLIMIT_NOFILE's soft limit to %ju: %m", (uintmax_t)rl.rlim_cur);

        return 1;
}

int safe_fork_full(
                const char *name,
                const int stdio_fds[3],
                int except_fds[],
                size_t n_except_fds,
                ForkFlags flags,
                pid_t *ret_pid) {

        pid_t original_pid, pid;
        sigset_t saved_ss, ss;
        _unused_ _cleanup_(restore_sigsetp) sigset_t *saved_ssp = NULL;
        bool block_signals = false, block_all = false, intermediary = false;
        int prio, r;

        assert(!ret_pid);

        /* A wrapper around fork(), that does a couple of important initializations in addition to mere forking. Always
         * returns the child's PID in *ret_pid. Returns == 0 in the child, and > 0 in the parent. */

        prio = LOG_DEBUG;

        original_pid = getpid_cached();

        if (flags & (FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGINT)) {
                /* We temporarily block all signals, so that the new child has them blocked initially. This
                 * way, we can be sure that SIGTERMs are not lost we might send to the child. (Note that for
                 * FORK_DEATHSIG_SIGKILL we don't bother, since it cannot be blocked anyway.) */

                assert_se(sigfillset(&ss) >= 0);
                block_signals = block_all = true;

        } else if (flags & FORK_WAIT) {
                /* Let's block SIGCHLD at least, so that we can safely watch for the child process */

                assert_se(sigemptyset(&ss) >= 0);
                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                block_signals = true;
        }

        if (block_signals) {
                if (sigprocmask(SIG_SETMASK, &ss, &saved_ss) < 0)
                        return log_full_errno(prio, errno, "Failed to set signal mask: %m");
                saved_ssp = &saved_ss;
        }

        pid = fork();
        if (pid < 0)
                return log_full_errno(prio, errno, "Failed to fork off '%s': %m", strna(name));
        if (pid > 0) {

                /* If we are in the intermediary process, exit now */
                if (intermediary)
                        _exit(EXIT_SUCCESS);

                /* We are in the parent process */
                log_debug("Successfully forked off '%s' as PID " PID_FMT ".", strna(name), pid);

                if (flags & FORK_WAIT) {
                        if (block_all) {
                                /* undo everything except SIGCHLD */
                                ss = saved_ss;
                                assert_se(sigaddset(&ss, SIGCHLD) >= 0);
                                (void) sigprocmask(SIG_SETMASK, &ss, NULL);
                        }

                        r = wait_for_terminate_and_check(name, pid, 0);
                        if (r < 0)
                                return r;
                        if (r != EXIT_SUCCESS) /* exit status > 0 should be treated as failure, too */
                                return -EPROTO;
                }

                if (ret_pid)
                        *ret_pid = pid;

                return 1;
        }

        /* We are in the child process */

        /* Restore signal mask manually */
        saved_ssp = NULL;

        if (flags & (FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGINT|FORK_DEATHSIG_SIGKILL))
                if (prctl(PR_SET_PDEATHSIG, fork_flags_to_signal(flags)) < 0) {
                        log_full_errno(prio, errno, "Failed to set death signal: %m");
                        _exit(EXIT_FAILURE);
                }

        if (flags & FORK_RESET_SIGNALS) {
                r = reset_all_signal_handlers();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to reset signal handlers: %m");
                        _exit(EXIT_FAILURE);
                }

                /* This implicitly undoes the signal mask stuff we did before the fork()ing above */
                r = reset_signal_mask();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to reset signal mask: %m");
                        _exit(EXIT_FAILURE);
                }
        } else if (block_signals) { /* undo what we did above */
                if (sigprocmask(SIG_SETMASK, &saved_ss, NULL) < 0) {
                        log_full_errno(prio, errno, "Failed to restore signal mask: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & (FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGKILL|FORK_DEATHSIG_SIGINT)) {
                pid_t ppid;
                /* Let's see if the parent PID is still the one we started from? If not, then the parent
                 * already died by the time we set PR_SET_PDEATHSIG, hence let's emulate the effect */

                ppid = getppid();
                if (ppid == 0)
                        /* Parent is in a different PID namespace. */;
                else if (ppid != original_pid) {
                        int sig = fork_flags_to_signal(flags);
                        log_debug("Parent died early, raising %s.", signal_to_string(sig));
                        (void) raise(sig);
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_REARRANGE_STDIO) {
                if (stdio_fds) {
                        r = rearrange_stdio(stdio_fds[0], stdio_fds[1], stdio_fds[2]);
                        if (r < 0) {
                                log_full_errno(prio, r, "Failed to rearrange stdio fds: %m");
                                _exit(EXIT_FAILURE);
                        }

                        /* Turn off O_NONBLOCK on the fdio fds, in case it was left on */
                        stdio_disable_nonblock();
                } else {
                        r = make_null_stdio();
                        if (r < 0) {
                                log_full_errno(prio, r, "Failed to connect stdin/stdout to /dev/null: %m");
                                _exit(EXIT_FAILURE);
                        }
                }
        }

        if (flags & FORK_CLOSE_ALL_FDS) {
                r = close_all_fds(except_fds, n_except_fds);
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to close all file descriptors: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (flags & FORK_RLIMIT_NOFILE_SAFE) {
                r = rlimit_nofile_safe();
                if (r < 0) {
                        log_full_errno(prio, r, "Failed to lower RLIMIT_NOFILE's soft limit to 1K: %m");
                        _exit(EXIT_FAILURE);
                }
        }

        if (ret_pid)
                *ret_pid = getpid_cached();

        return 0;
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
                pid_t *ret_pid) {

        int r;

        /* This is much like safe_fork(), but forks twice, and joins the specified namespaces in the middle
         * process. This ensures that we are fully a member of the destination namespace, with pidns an all, so that
         * /proc/self/fd works correctly. */

        r = safe_fork_full(outer_name,
                           NULL,
                           except_fds, n_except_fds,
                           flags|FORK_DEATHSIG_SIGINT|FORK_DEATHSIG_SIGTERM|FORK_DEATHSIG_SIGKILL, ret_pid);
        if (r < 0)
                return r;
        if (r == 0) {
                pid_t pid;

                /* Child */

                r = namespace_enter(pidns_fd, mntns_fd, netns_fd, userns_fd, root_fd);
                if (r < 0) {
                        log_full_errno(LOG_DEBUG, r, "Failed to join namespace: %m");
                        _exit(EXIT_FAILURE);
                }

                /* We mask a few flags here that either make no sense for the grandchild, or that we don't have to do again */
                r = safe_fork_full(inner_name,
                                   NULL,
                                   except_fds, n_except_fds,
                                   flags & ~(FORK_WAIT|FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO), &pid);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                if (r == 0) {
                        /* Child */
                        if (ret_pid)
                                *ret_pid = pid;
                        return 0;
                }

                r = wait_for_terminate_and_check(inner_name, pid, 0);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(r);
        }

        return 1;
}
