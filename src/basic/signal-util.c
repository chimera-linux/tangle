/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>

#include "errno-util.h"
#include "macro.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"

static const char *const static_signal_table[] = {
        [SIGHUP]    = "HUP",
        [SIGINT]    = "INT",
        [SIGQUIT]   = "QUIT",
        [SIGILL]    = "ILL",
        [SIGTRAP]   = "TRAP",
        [SIGABRT]   = "ABRT",
        [SIGBUS]    = "BUS",
        [SIGFPE]    = "FPE",
        [SIGKILL]   = "KILL",
        [SIGUSR1]   = "USR1",
        [SIGSEGV]   = "SEGV",
        [SIGUSR2]   = "USR2",
        [SIGPIPE]   = "PIPE",
        [SIGALRM]   = "ALRM",
        [SIGTERM]   = "TERM",
#ifdef SIGSTKFLT
        [SIGSTKFLT] = "STKFLT",  /* Linux on SPARC doesn't know SIGSTKFLT */
#endif
        [SIGCHLD]   = "CHLD",
        [SIGCONT]   = "CONT",
        [SIGSTOP]   = "STOP",
        [SIGTSTP]   = "TSTP",
        [SIGTTIN]   = "TTIN",
        [SIGTTOU]   = "TTOU",
        [SIGURG]    = "URG",
        [SIGXCPU]   = "XCPU",
        [SIGXFSZ]   = "XFSZ",
        [SIGVTALRM] = "VTALRM",
        [SIGPROF]   = "PROF",
        [SIGWINCH]  = "WINCH",
        [SIGIO]     = "IO",
        [SIGPWR]    = "PWR",
        [SIGSYS]    = "SYS"
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP(static_signal, int);

const char *signal_to_string(int signo) {
        static _Thread_local char buf[STRLEN("RTMIN+") + DECIMAL_STR_MAX(int)];
        const char *name;

        name = static_signal_to_string(signo);
        if (name)
                return name;

        if (signo >= SIGRTMIN && signo <= SIGRTMAX)
                xsprintf(buf, "RTMIN+%d", signo - SIGRTMIN);
        else
                xsprintf(buf, "%d", signo);

        return buf;
}

static int to_signum(const char *s, int *ret) {
        char *err = NULL;
        long x = strtol(s, &err, 10);
        if (!err || *err || x > INT_MAX || x < 0) {
                errno = ERANGE;
                return -1;
        }
        *ret = (int)x;
        return 0;
}

int signal_from_string(const char *s) {
        const char *p;
        int signo, r;

        /* Check that the input is a signal number. */
        if (to_signum(s, &signo) >= 0) {
                if (SIGNAL_VALID(signo))
                        return signo;
                else
                        return -ERANGE;
        }

        /* Drop "SIG" prefix. */
        if (startswith(s, "SIG"))
                s += 3;

        /* Check that the input is a signal name. */
        signo = static_signal_from_string(s);
        if (signo > 0)
                return signo;

        /* Check that the input is RTMIN or
         * RTMIN+n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMIN");
        if (p) {
                if (*p == '\0')
                        return SIGRTMIN;
                if (*p != '+')
                        return -EINVAL;

                r = to_signum(p, &signo);
                if (r < 0)
                        return r;

                if (signo < 0 || signo > SIGRTMAX - SIGRTMIN)
                        return -ERANGE;

                return signo + SIGRTMIN;
        }

        /* Check that the input is RTMAX or
         * RTMAX-n (0 <= n <= SIGRTMAX-SIGRTMIN). */
        p = startswith(s, "RTMAX");
        if (p) {
                if (*p == '\0')
                        return SIGRTMAX;
                if (*p != '-')
                        return -EINVAL;

                r = to_signum(p, &signo);
                if (r < 0)
                        return r;

                if (signo > 0 || signo < SIGRTMIN - SIGRTMAX)
                        return -ERANGE;

                return signo + SIGRTMAX;
        }

        return -EINVAL;
}

int signal_is_blocked(int sig) {
        sigset_t ss;
        int r;

        r = pthread_sigmask(SIG_SETMASK, NULL, &ss);
        if (r != 0)
                return -r;

        return RET_NERRNO(sigismember(&ss, sig));
}
