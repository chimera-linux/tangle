/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "constants.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "terminal-util.h"

bool isatty_safe(int fd) {
        assert(fd >= 0);

        if (isatty(fd))
                return true;

        /* Be resilient if we're working on stdio, since they're set up by parent process. */
        assert(errno != EBADF || IN_SET(fd, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO));

        return false;
}

static inline bool devnum_is_zero(dev_t d) {
        return major(d) == 0 && minor(d) == 0;
}

int get_ctty_devnr(pid_t pid, dev_t *d) {
        int r;
        _cleanup_free_ char *line = NULL;
        const char *p;
        unsigned long ttynr;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r < 0)
                return r;

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%lu ", /* ttynr */
                   &ttynr) != 1)
                return -EIO;

        if (devnum_is_zero(ttynr))
                return -ENXIO;

        if (d)
                *d = (dev_t) ttynr;

        return 0;
}

int get_ctty(pid_t pid, dev_t *ret_devnr, char **ret) {
        char pty[STRLEN("/dev/pts/") + DECIMAL_STR_MAX(dev_t) + 1];
        char devchar[STRLEN("/dev/char/") + DECIMAL_STR_MAX(dev_t) * 2 + 2];
        _cleanup_free_ char *buf = NULL;
        const char *fn = NULL, *w;
        struct stat st;
        dev_t devnr;
        int r;

        r = get_ctty_devnr(pid, &devnr);
        if (r < 0)
                return r;

        /* try this first */
        xsprintf(devchar, "/dev/char/%u:%u", major(devnr), minor(devnr));
        if (stat(devchar, &st) < 0) {
                if (errno != ENOENT)
                        return -errno;
                /* may be a pty... */
                xsprintf(pty, "/dev/pts/%u", minor(devnr));
                if (stat(pty, &st) < 0) {
                        if (errno != ENOENT)
                                return -errno;
                } else if (S_ISCHR(st.st_mode) && devnr == st.st_rdev)
                        fn = pty;
        }
        /* when it does not exist make up a vaguely useful string */
        if (!fn) fn = devchar;

        w = path_startswith(fn, "/dev/");
        if (!w)
                return -EINVAL;

        if (ret) {
                r = strdup_to(ret, w);
                if (r < 0)
                        return r;
        }

        if (ret_devnr)
                *ret_devnr = devnr;
        return 0;
}
