/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "time-util.h"

static clockid_t map_clock_id(clockid_t c) {

        /* Some more exotic archs (s390, ppc, …) lack the "ALARM" flavour of the clocks. Thus,
         * clock_gettime() will fail for them. Since they are essentially the same as their non-ALARM
         * pendants (their only difference is when timers are set on them), let's just map them
         * accordingly. This way, we can get the correct time even on those archs. */

        switch (c) {

        case CLOCK_BOOTTIME_ALARM:
                return CLOCK_BOOTTIME;

        case CLOCK_REALTIME_ALARM:
                return CLOCK_REALTIME;

        default:
                return c;
        }
}

usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

        return timespec_load(&ts);
}

nsec_t now_nsec(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(map_clock_id(clock_id), &ts) == 0);

        return timespec_load_nsec(&ts);
}

dual_timestamp* dual_timestamp_now(dual_timestamp *ts) {
        assert(ts);

        ts->realtime = now(CLOCK_REALTIME);
        ts->monotonic = now(CLOCK_MONOTONIC);

        return ts;
}

triple_timestamp* triple_timestamp_now(triple_timestamp *ts) {
        assert(ts);

        ts->realtime = now(CLOCK_REALTIME);
        ts->monotonic = now(CLOCK_MONOTONIC);
        ts->boottime = now(CLOCK_BOOTTIME);

        return ts;
}

usec_t map_clock_usec_raw(usec_t from, usec_t from_base, usec_t to_base) {

        /* Maps the time 'from' between two clocks, based on a common reference point where the first clock
         * is at 'from_base' and the second clock at 'to_base'. Basically calculates:
         *
         *         from - from_base + to_base
         *
         * But takes care of overflows/underflows and avoids signed operations. */

        if (from >= from_base) { /* In the future */
                usec_t delta = from - from_base;

                if (to_base >= USEC_INFINITY - delta) /* overflow? */
                        return USEC_INFINITY;

                return to_base + delta;

        } else { /* In the past */
                usec_t delta = from_base - from;

                if (to_base <= delta) /* underflow? */
                        return 0;

                return to_base - delta;
        }
}

usec_t map_clock_usec(usec_t from, clockid_t from_clock, clockid_t to_clock) {

        /* Try to avoid any inaccuracy needlessly added in case we convert from effectively the same clock
         * onto itself */
        if (map_clock_id(from_clock) == map_clock_id(to_clock))
                return from;

        /* Keep infinity as is */
        if (from == USEC_INFINITY)
                return from;

        return map_clock_usec_raw(from, now(from_clock), now(to_clock));
}

dual_timestamp* dual_timestamp_from_realtime(dual_timestamp *ts, usec_t u) {
        assert(ts);

        if (!timestamp_is_set(u)) {
                ts->realtime = ts->monotonic = u;
                return ts;
        }

        ts->realtime = u;
        ts->monotonic = map_clock_usec(u, CLOCK_REALTIME, CLOCK_MONOTONIC);
        return ts;
}

triple_timestamp* triple_timestamp_from_realtime(triple_timestamp *ts, usec_t u) {
        usec_t nowr;

        assert(ts);

        if (!timestamp_is_set(u)) {
                ts->realtime = ts->monotonic = ts->boottime = u;
                return ts;
        }

        nowr = now(CLOCK_REALTIME);

        ts->realtime = u;
        ts->monotonic = map_clock_usec_raw(u, nowr, now(CLOCK_MONOTONIC));
        ts->boottime = map_clock_usec_raw(u, nowr, now(CLOCK_BOOTTIME));

        return ts;
}

triple_timestamp* triple_timestamp_from_boottime(triple_timestamp *ts, usec_t u) {
        usec_t nowb;

        assert(ts);

        if (u == USEC_INFINITY) {
                ts->realtime = ts->monotonic = ts->boottime = u;
                return ts;
        }

        nowb = now(CLOCK_BOOTTIME);

        ts->boottime = u;
        ts->monotonic = map_clock_usec_raw(u, nowb, now(CLOCK_MONOTONIC));
        ts->realtime = map_clock_usec_raw(u, nowb, now(CLOCK_REALTIME));

        return ts;
}

dual_timestamp* dual_timestamp_from_monotonic(dual_timestamp *ts, usec_t u) {
        assert(ts);

        if (u == USEC_INFINITY) {
                ts->realtime = ts->monotonic = USEC_INFINITY;
                return ts;
        }

        ts->monotonic = u;
        ts->realtime = map_clock_usec(u, CLOCK_MONOTONIC, CLOCK_REALTIME);
        return ts;
}

dual_timestamp* dual_timestamp_from_boottime(dual_timestamp *ts, usec_t u) {
        usec_t nowm;

        assert(ts);

        if (u == USEC_INFINITY) {
                ts->realtime = ts->monotonic = USEC_INFINITY;
                return ts;
        }

        nowm = now(CLOCK_BOOTTIME);
        ts->monotonic = map_clock_usec_raw(u, nowm, now(CLOCK_MONOTONIC));
        ts->realtime = map_clock_usec_raw(u, nowm, now(CLOCK_REALTIME));
        return ts;
}

usec_t triple_timestamp_by_clock(triple_timestamp *ts, clockid_t clock) {
        assert(ts);

        switch (clock) {

        case CLOCK_REALTIME:
        case CLOCK_REALTIME_ALARM:
                return ts->realtime;

        case CLOCK_MONOTONIC:
                return ts->monotonic;

        case CLOCK_BOOTTIME:
        case CLOCK_BOOTTIME_ALARM:
                return ts->boottime;

        default:
                return USEC_INFINITY;
        }
}

usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return USEC_INFINITY;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

nsec_t timespec_load_nsec(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec < 0 || ts->tv_nsec < 0)
                return NSEC_INFINITY;

        if ((nsec_t) ts->tv_sec >= (UINT64_MAX - ts->tv_nsec) / NSEC_PER_SEC)
                return NSEC_INFINITY;

        return (nsec_t) ts->tv_sec * NSEC_PER_SEC + (nsec_t) ts->tv_nsec;
}

struct timespec *timespec_store(struct timespec *ts, usec_t u) {
        assert(ts);

        if (u == USEC_INFINITY ||
            u / USEC_PER_SEC >= TIME_T_MAX) {
                ts->tv_sec = (time_t) -1;
                ts->tv_nsec = -1L;
                return ts;
        }

        ts->tv_sec = (time_t) (u / USEC_PER_SEC);
        ts->tv_nsec = (long) ((u % USEC_PER_SEC) * NSEC_PER_USEC);

        return ts;
}

struct timespec *timespec_store_nsec(struct timespec *ts, nsec_t n) {
        assert(ts);

        if (n == NSEC_INFINITY ||
            n / NSEC_PER_SEC >= TIME_T_MAX) {
                ts->tv_sec = (time_t) -1;
                ts->tv_nsec = -1L;
                return ts;
        }

        ts->tv_sec = (time_t) (n / NSEC_PER_SEC);
        ts->tv_nsec = (long) (n % NSEC_PER_SEC);

        return ts;
}

bool clock_supported(clockid_t clock) {
        struct timespec ts;

        switch (clock) {

        case CLOCK_MONOTONIC:
        case CLOCK_REALTIME:
        case CLOCK_BOOTTIME:
                /* These three are always available in our baseline, and work in timerfd, as of kernel 3.15 */
                return true;

        default:
                /* For everything else, check properly */
                return clock_gettime(clock, &ts) >= 0;
        }
}


int time_change_fd(void) {

        /* We only care for the cancellation event, hence we set the timeout to the latest possible value. */
        static const struct itimerspec its = {
                .it_value.tv_sec = TIME_T_MAX,
        };

        _cleanup_close_ int fd = -EBADF;

        assert_cc(sizeof(time_t) == sizeof(TIME_T_MAX));

        /* Uses TFD_TIMER_CANCEL_ON_SET to get notifications whenever CLOCK_REALTIME makes a jump relative to
         * CLOCK_MONOTONIC. */

        fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK|TFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (timerfd_settime(fd, TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET, &its, NULL) >= 0)
                return TAKE_FD(fd);

        /* So apparently there are systems where time_t is 64-bit, but the kernel actually doesn't support
         * 64-bit time_t. In that case configuring a timer to TIME_T_MAX will fail with EOPNOTSUPP or a
         * similar error. If that's the case let's try with INT32_MAX instead, maybe that works. It's a bit
         * of a black magic thing though, but what can we do?
         *
         * We don't want this code on x86-64, hence let's conditionalize this for systems with 64-bit time_t
         * but where "long" is shorter than 64-bit, i.e. 32-bit archs.
         *
         * See: https://github.com/systemd/systemd/issues/14362 */

#if SIZEOF_TIME_T == 8 && ULONG_MAX < UINT64_MAX
        if (ERRNO_IS_NOT_SUPPORTED(errno) || errno == EOVERFLOW) {
                static const struct itimerspec its32 = {
                        .it_value.tv_sec = INT32_MAX,
                };

                if (timerfd_settime(fd, TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET, &its32, NULL) >= 0)
                        return TAKE_FD(fd);
        }
#endif

        return -errno;
}
