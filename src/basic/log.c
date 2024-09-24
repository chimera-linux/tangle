/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

/* An assert to use in logging functions that does not call recursively
 * into our logging functions (since that might lead to a loop). */
#define assert_raw(expr)                                                \
        do {                                                            \
                if (_unlikely_(!(expr))) {                              \
                        fputs(#expr "\n", stderr);                      \
                        abort();                                        \
                }                                                       \
        } while (false)

static int write_to_console(
                int level,
                int error,
                int line,
                const char *func,
                const char *buffer) {
        struct iovec iovec[2];
        size_t n = 0;

        iovec[n++] = (struct iovec){(void *)buffer, strlen(buffer)};

        /* When writing to a TTY we output an extra '\r' (i.e. CR) first, to generate CRNL rather than just
         * NL. This is a robustness thing in case the TTY is currently in raw mode (specifically: has the
         * ONLCR flag off). We want that subsequent output definitely starts at the beginning of the line
         * again, after all. If the TTY is not in raw mode the extra CR should not hurt. If we're writing to
         * a dumb terminal, only write NL as CRNL might be interpreted as a double newline. */
        iovec[n++] = (struct iovec){(void *)"\n", 1};

        if (writev(STDERR_FILENO, iovec, n) < 0) {
                return -errno;
        }

        return 1;
}

int log_dispatch_internal(
                int level,
                int error,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra_field,
                const char *extra,
                char *buffer) {

        assert_raw(buffer);

        /* Patch in LOG_DAEMON facility if necessary */
        if (LOG_FAC(level) == 0)
                level |= LOG_DAEMON;

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (k <= 0)
                        (void) write_to_console(level, error, line, func, buffer);

                buffer = e;
        } while (buffer);

        return -ERRNO_VALUE(error);
}

int log_internalv(
                int level,
                int error,
                int line,
                const char *func,
                const char *format,
                va_list ap) {

        if (_likely_(LOG_PRI(level) > LOG_INFO))
                return -ERRNO_VALUE(error);

        /* Make sure that %m maps to the specified error (or "Success"). */
        char buffer[LINE_MAX];
        LOCAL_ERRNO(ERRNO_VALUE(error));

        (void) vsnprintf(buffer, sizeof buffer, format, ap);

        return log_dispatch_internal(level, error, line, func, NULL, NULL, NULL, NULL, buffer);
}

int log_internal(
                int level,
                int error,
                int line,
                const char *func,
                const char *format, ...) {

        va_list ap;
        int r;

        va_start(ap, format);
        r = log_internalv(level, error, line, func, format, ap);
        va_end(ap);

        return r;
}

static void log_assert(
                int level,
                const char *text,
                int line,
                const char *func,
                const char *format) {

        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > LOG_INFO))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        (void) snprintf(buffer, sizeof buffer, format, text, line, func);
        REENABLE_WARNING;

        log_dispatch_internal(level, 0, line, func, NULL, NULL, NULL, NULL, buffer);
}

_noreturn_ void log_assert_failed(
                const char *text,
                int line,
                const char *func) {
        log_assert(LOG_CRIT, text, line, func,
                   "Assertion '%s' failed at %u, function %s(). Aborting.");
        abort();
}

_noreturn_ void log_assert_failed_unreachable(
                int line,
                const char *func) {
        log_assert(LOG_CRIT, "Code should not be reached", line, func,
                   "%s at %u, function %s(). Aborting. 💥");
        abort();
}

void log_assert_failed_return(
                const char *text,
                int line,
                const char *func) {
        PROTECT_ERRNO;
        log_assert(LOG_DEBUG, text, line, func,
                   "Assertion '%s' failed at %u, function %s(), ignoring.");
}


int log_get_max_level(void) {
        return LOG_INFO;
}
