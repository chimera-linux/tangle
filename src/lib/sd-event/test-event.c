/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/wait.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tests.h"

static int prepare_handler(sd_event_source *s, void *userdata) {
        log_info("preparing %c", PTR_TO_INT(userdata));
        return 1;
}

static bool got_a, got_b, got_c, got_unref;
static unsigned got_d;

static int unref_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_event_source_unref(s);
        got_unref = true;
        return 0;
}

static int io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {

        log_info("got IO on %c", PTR_TO_INT(userdata));

        if (userdata == INT_TO_PTR('a')) {
                assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);
                assert_se(!got_a);
                got_a = true;
        } else if (userdata == INT_TO_PTR('b')) {
                assert_se(!got_b);
                got_b = true;
        } else if (userdata == INT_TO_PTR('d')) {
                got_d++;
                if (got_d < 2)
                        assert_se(sd_event_source_set_enabled(s, SD_EVENT_ONESHOT) >= 0);
                else
                        assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);
        } else
                assert_not_reached();

        return 1;
}

static int child_handler(sd_event_source *s, const siginfo_t *si, void *userdata) {

        assert_se(s);
        assert_se(si);

        assert_se(si->si_uid == getuid());
        assert_se(si->si_signo == SIGCHLD);
        assert_se(si->si_code == CLD_EXITED);
        assert_se(si->si_status == 78);

        log_info("got child on %c", PTR_TO_INT(userdata));

        assert_se(userdata == INT_TO_PTR('f'));

        assert_se(sd_event_exit(sd_event_source_get_event(s), 0) >= 0);
        sd_event_source_unref(s);

        return 1;
}

static int signal_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        sd_event_source *p = NULL;
        pid_t pid;
        siginfo_t plain_si;

        assert_se(s);
        assert_se(si);

        log_info("got signal on %c", PTR_TO_INT(userdata));

        assert_se(userdata == INT_TO_PTR('e'));

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGUSR2) >= 0);

        pid = fork();
        assert_se(pid >= 0);

        if (pid == 0) {
                sigset_t ss;

                assert_se(sigemptyset(&ss) >= 0);
                assert_se(sigaddset(&ss, SIGUSR2) >= 0);

                zero(plain_si);
                assert_se(sigwaitinfo(&ss, &plain_si) >= 0);

                assert_se(plain_si.si_signo == SIGUSR2);
                assert_se(plain_si.si_value.sival_int == 4711);

                _exit(78);
        }

        assert_se(sd_event_add_child(sd_event_source_get_event(s), &p, pid, WEXITED, child_handler, INT_TO_PTR('f')) >= 0);
        assert_se(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT) >= 0);
        assert_se(sd_event_source_set_child_process_own(p, true) >= 0);

        /* We can't use structured initialization here, since the structure contains various unions and these
         * fields lie in overlapping (carefully aligned) unions that LLVM is allergic to allow assignments
         * to */
        zero(plain_si);
        plain_si.si_signo = SIGUSR2;
        plain_si.si_code = SI_QUEUE;
        plain_si.si_pid = getpid_cached();
        plain_si.si_uid = getuid();
        plain_si.si_value.sival_int = 4711;

        assert_se(sd_event_source_send_child_signal(p, SIGUSR2, &plain_si, 0) >= 0);

        sd_event_source_unref(s);

        return 1;
}

static int defer_handler(sd_event_source *s, void *userdata) {
        sd_event_source *p = NULL;

        assert_se(s);

        log_info("got defer on %c", PTR_TO_INT(userdata));

        assert_se(userdata == INT_TO_PTR('d'));

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGUSR1) >= 0);

        assert_se(sd_event_add_signal(sd_event_source_get_event(s), &p, SIGUSR1, signal_handler, INT_TO_PTR('e')) >= 0);
        assert_se(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT) >= 0);
        raise(SIGUSR1);

        sd_event_source_unref(s);

        return 1;
}

static bool do_quit;

static int time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        log_info("got timer on %c", PTR_TO_INT(userdata));

        if (userdata == INT_TO_PTR('c')) {

                if (do_quit) {
                        sd_event_source *p;

                        assert_se(sd_event_add_defer(sd_event_source_get_event(s), &p, defer_handler, INT_TO_PTR('d')) >= 0);
                        assert_se(sd_event_source_set_enabled(p, SD_EVENT_ONESHOT) >= 0);
                } else {
                        assert_se(!got_c);
                        got_c = true;
                }
        } else
                assert_not_reached();

        return 2;
}

static bool got_exit = false;

static int exit_handler(sd_event_source *s, void *userdata) {
        log_info("got quit handler on %c", PTR_TO_INT(userdata));

        got_exit = true;

        return 3;
}

static bool got_post = false;

static int post_handler(sd_event_source *s, void *userdata) {
        log_info("got post handler");

        got_post = true;

        return 2;
}

TEST(basic) {
        sd_event *e = NULL;
        sd_event_source *w = NULL, *x = NULL, *y = NULL, *z = NULL, *q = NULL, *t = NULL;
        static const char ch = 'x';
        int a[2] = EBADF_PAIR, b[2] = EBADF_PAIR,
            d[2] = EBADF_PAIR, k[2] = EBADF_PAIR;
        uint64_t event_now;
        int64_t priority;

        assert_se(pipe(a) >= 0);
        assert_se(pipe(b) >= 0);
        assert_se(pipe(d) >= 0);
        assert_se(pipe(k) >= 0);

        assert_se(sd_event_default(&e) >= 0);
        assert_se(sd_event_now(e, CLOCK_MONOTONIC, &event_now) > 0);

        assert_se(sd_event_set_watchdog(e, true) >= 0);

        /* Test whether we cleanly can destroy an io event source from its own handler */
        got_unref = false;
        assert_se(sd_event_add_io(e, &t, k[0], EPOLLIN, unref_handler, NULL) >= 0);
        assert_se(write(k[1], &ch, 1) == 1);
        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(got_unref);

        got_a = false, got_b = false, got_c = false, got_d = 0;

        /* Add a oneshot handler, trigger it, reenable it, and trigger it again. */
        assert_se(sd_event_add_io(e, &w, d[0], EPOLLIN, io_handler, INT_TO_PTR('d')) >= 0);
        assert_se(sd_event_source_set_enabled(w, SD_EVENT_ONESHOT) >= 0);
        assert_se(write(d[1], &ch, 1) >= 0);
        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(got_d == 1);
        assert_se(write(d[1], &ch, 1) >= 0);
        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(got_d == 2);

        assert_se(sd_event_add_io(e, &x, a[0], EPOLLIN, io_handler, INT_TO_PTR('a')) >= 0);
        assert_se(sd_event_add_io(e, &y, b[0], EPOLLIN, io_handler, INT_TO_PTR('b')) >= 0);

        do_quit = false;
        assert_se(sd_event_add_time(e, &z, CLOCK_MONOTONIC, 0, 0, time_handler, INT_TO_PTR('c')) >= 0);
        assert_se(sd_event_add_exit(e, &q, exit_handler, INT_TO_PTR('g')) >= 0);

        assert_se(sd_event_source_set_priority(x, 99) >= 0);
        assert_se(sd_event_source_get_priority(x, &priority) >= 0);
        assert_se(priority == 99);
        assert_se(sd_event_source_set_enabled(y, SD_EVENT_ONESHOT) >= 0);
        assert_se(sd_event_source_set_prepare(x, prepare_handler) >= 0);
        assert_se(sd_event_source_set_priority(z, 50) >= 0);
        assert_se(sd_event_source_set_enabled(z, SD_EVENT_ONESHOT) >= 0);
        assert_se(sd_event_source_set_prepare(z, prepare_handler) >= 0);

        /* Test for floating event sources */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGRTMIN+1) >= 0);
        assert_se(sd_event_add_signal(e, NULL, SIGRTMIN+1, NULL, NULL) >= 0);

        assert_se(write(a[1], &ch, 1) >= 0);
        assert_se(write(b[1], &ch, 1) >= 0);

        assert_se(!got_a && !got_b && !got_c);

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);

        assert_se(!got_a && got_b && !got_c);

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);

        assert_se(!got_a && got_b && got_c);

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);

        assert_se(got_a && got_b && got_c);

        sd_event_source_unref(x);
        sd_event_source_unref(y);

        do_quit = true;
        assert_se(sd_event_add_post(e, NULL, post_handler, NULL) >= 0);
        assert_se(sd_event_now(e, CLOCK_MONOTONIC, &event_now) == 0);
        assert_se(sd_event_source_set_time(z, event_now + 200 * USEC_PER_MSEC) >= 0);
        assert_se(sd_event_source_set_enabled(z, SD_EVENT_ONESHOT) >= 0);

        assert_se(sd_event_loop(e) >= 0);
        assert_se(got_post);
        assert_se(got_exit);

        sd_event_source_unref(z);
        sd_event_source_unref(q);

        sd_event_source_unref(w);

        sd_event_unref(e);

        safe_close_pair(a);
        safe_close_pair(b);
        safe_close_pair(d);
        safe_close_pair(k);
}

TEST(test_sd_event_now) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        uint64_t event_now;

        assert_se(sd_event_new(&e) >= 0);
        assert_se(sd_event_now(e, CLOCK_MONOTONIC, &event_now) > 0);
        assert_se(sd_event_now(e, CLOCK_REALTIME, &event_now) > 0);
        assert_se(sd_event_now(e, CLOCK_REALTIME_ALARM, &event_now) > 0);
        assert_se(sd_event_now(e, CLOCK_BOOTTIME, &event_now) > 0);
        assert_se(sd_event_now(e, CLOCK_BOOTTIME_ALARM, &event_now) > 0);
        assert_se(sd_event_now(e, -1, &event_now) == -EOPNOTSUPP);
        assert_se(sd_event_now(e, 900 /* arbitrary big number */, &event_now) == -EOPNOTSUPP);

        assert_se(sd_event_run(e, 0) == 0);

        assert_se(sd_event_now(e, CLOCK_MONOTONIC, &event_now) == 0);
        assert_se(sd_event_now(e, CLOCK_REALTIME, &event_now) == 0);
        assert_se(sd_event_now(e, CLOCK_REALTIME_ALARM, &event_now) == 0);
        assert_se(sd_event_now(e, CLOCK_BOOTTIME, &event_now) == 0);
        assert_se(sd_event_now(e, CLOCK_BOOTTIME_ALARM, &event_now) == 0);
        assert_se(sd_event_now(e, -1, &event_now) == -EOPNOTSUPP);
        assert_se(sd_event_now(e, 900 /* arbitrary big number */, &event_now) == -EOPNOTSUPP);
}

static int last_rtqueue_sigval = 0;
static int n_rtqueue = 0;

static int rtqueue_handler(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        last_rtqueue_sigval = si->ssi_int;
        n_rtqueue++;
        return 0;
}

TEST(rtqueue) {
        sd_event_source *u = NULL, *v = NULL, *s = NULL;
        sd_event *e = NULL;

        assert_se(sd_event_default(&e) >= 0);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGRTMIN+2, SIGRTMIN+3, SIGUSR2) >= 0);
        assert_se(sd_event_add_signal(e, &u, SIGRTMIN+2, rtqueue_handler, NULL) >= 0);
        assert_se(sd_event_add_signal(e, &v, SIGRTMIN+3, rtqueue_handler, NULL) >= 0);
        assert_se(sd_event_add_signal(e, &s, SIGUSR2, rtqueue_handler, NULL) >= 0);

        assert_se(sd_event_source_set_priority(v, -10) >= 0);

        assert_se(sigqueue(getpid_cached(), SIGRTMIN+2, (union sigval) { .sival_int = 1 }) >= 0);
        assert_se(sigqueue(getpid_cached(), SIGRTMIN+3, (union sigval) { .sival_int = 2 }) >= 0);
        assert_se(sigqueue(getpid_cached(), SIGUSR2, (union sigval) { .sival_int = 3 }) >= 0);
        assert_se(sigqueue(getpid_cached(), SIGRTMIN+3, (union sigval) { .sival_int = 4 }) >= 0);
        assert_se(sigqueue(getpid_cached(), SIGUSR2, (union sigval) { .sival_int = 5 }) >= 0);

        assert_se(n_rtqueue == 0);
        assert_se(last_rtqueue_sigval == 0);

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(n_rtqueue == 1);
        assert_se(last_rtqueue_sigval == 2); /* first SIGRTMIN+3 */

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(n_rtqueue == 2);
        assert_se(last_rtqueue_sigval == 4); /* second SIGRTMIN+3 */

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(n_rtqueue == 3);
        assert_se(last_rtqueue_sigval == 3); /* first SIGUSR2 */

        assert_se(sd_event_run(e, UINT64_MAX) >= 1);
        assert_se(n_rtqueue == 4);
        assert_se(last_rtqueue_sigval == 1); /* SIGRTMIN+2 */

        assert_se(sd_event_run(e, 0) == 0); /* the other SIGUSR2 is dropped, because the first one was still queued */
        assert_se(n_rtqueue == 4);
        assert_se(last_rtqueue_sigval == 1);

        sd_event_source_unref(u);
        sd_event_source_unref(v);
        sd_event_source_unref(s);

        sd_event_unref(e);
}

static int ratelimit_io_handler(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        unsigned *c = (unsigned*) userdata;
        *c += 1;
        return 0;
}

static int ratelimit_time_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        int r;

        r = sd_event_source_set_enabled(s, SD_EVENT_ON);
        if (r < 0)
                log_warning_errno(r, "Failed to turn on notify event source: %m");

        r = sd_event_source_set_time(s, usec + 1000);
        if (r < 0)
                log_error_errno(r, "Failed to restart watchdog event source: %m");

        unsigned *c = (unsigned*) userdata;
        *c += 1;

        return 0;
}

static int expired = -1;
static int ratelimit_expired(sd_event_source *s, void *userdata) {
        return ++expired;
}

TEST(ratelimit) {
        _cleanup_close_pair_ int p[2] = EBADF_PAIR;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        uint64_t interval;
        unsigned count, burst;

        assert_se(sd_event_default(&e) >= 0);
        assert_se(pipe2(p, O_CLOEXEC|O_NONBLOCK) >= 0);

        assert_se(sd_event_add_io(e, &s, p[0], EPOLLIN, ratelimit_io_handler, &count) >= 0);
        assert_se(sd_event_source_set_description(s, "test-ratelimit-io") >= 0);
        assert_se(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 5) >= 0);
        assert_se(sd_event_source_get_ratelimit(s, &interval, &burst) >= 0);
        assert_se(interval == 1 * USEC_PER_SEC && burst == 5);

        assert_se(write(p[1], "1", 1) == 1);

        count = 0;
        for (unsigned i = 0; i < 10; i++) {
                log_debug("slow loop iteration %u", i);
                assert_se(sd_event_run(e, UINT64_MAX) >= 0);
                assert_se(usleep_safe(250 * USEC_PER_MSEC) >= 0);
        }

        assert_se(sd_event_source_is_ratelimited(s) == 0);
        assert_se(count == 10);
        log_info("ratelimit_io_handler: called %u times, event source not ratelimited", count);

        assert_se(sd_event_source_set_ratelimit(s, 0, 0) >= 0);
        assert_se(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 5) >= 0);

        count = 0;
        for (unsigned i = 0; i < 10; i++) {
                log_debug("fast event loop iteration %u", i);
                assert_se(sd_event_run(e, UINT64_MAX) >= 0);
                assert_se(usleep_safe(10) >= 0);
        }
        log_info("ratelimit_io_handler: called %u times, event source got ratelimited", count);
        assert_se(count < 10);

        s = sd_event_source_unref(s);
        safe_close_pair(p);

        count = 0;
        assert_se(sd_event_add_time_relative(e, &s, CLOCK_MONOTONIC, 1000, 1, ratelimit_time_handler, &count) >= 0);
        assert_se(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 10) == 0);

        do {
                assert_se(sd_event_run(e, UINT64_MAX) >= 0);
        } while (!sd_event_source_is_ratelimited(s));

        log_info("ratelimit_time_handler: called %u times, event source got ratelimited", count);
        assert_se(count == 10);

        /* In order to get rid of active rate limit client needs to disable it explicitly */
        assert_se(sd_event_source_set_ratelimit(s, 0, 0) >= 0);
        assert_se(!sd_event_source_is_ratelimited(s));

        assert_se(sd_event_source_set_ratelimit(s, 1 * USEC_PER_SEC, 10) >= 0);

        /* Set callback that will be invoked when we leave rate limited state. */
        assert_se(sd_event_source_set_ratelimit_expire_callback(s, ratelimit_expired) >= 0);

        do {
                assert_se(sd_event_run(e, UINT64_MAX) >= 0);
        } while (!sd_event_source_is_ratelimited(s));

        log_info("ratelimit_time_handler: called 10 more times, event source got ratelimited");
        assert_se(count == 20);

        /* Dispatch the event loop once more and check that ratelimit expiration callback got called */
        assert_se(sd_event_run(e, UINT64_MAX) >= 0);
        assert_se(expired == 0);
}

TEST(simple_timeout) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        usec_t f, t, some_time;

        some_time = USEC_PER_SEC;

        assert_se(sd_event_default(&e) >= 0);

        assert_se(sd_event_prepare(e) == 0);

        f = now(CLOCK_MONOTONIC);
        assert_se(sd_event_wait(e, some_time) >= 0);
        t = now(CLOCK_MONOTONIC);

        /* The event loop may sleep longer than the specified time (timer accuracy, scheduling latencies, …),
         * but never shorter. Let's check that. */
        assert_se(t >= usec_add(f, some_time));
}

TEST(test_sd_event_source_set_io_fd) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int pfd_a[2] = EBADF_PAIR, pfd_b[2] = EBADF_PAIR;

        assert_se(sd_event_default(&e) >= 0);

        assert_se(pipe2(pfd_a, O_CLOEXEC) >= 0);
        assert_se(pipe2(pfd_b, O_CLOEXEC) >= 0);

        assert_se(sd_event_add_io(e, &s, pfd_a[0], EPOLLIN, NULL, INT_TO_PTR(-ENOANO)) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);
        TAKE_FD(pfd_a[0]);

        assert_se(sd_event_source_set_io_fd(s, pfd_b[0]) >= 0);
        TAKE_FD(pfd_b[0]);
}

static int hup_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        unsigned *c = userdata;

        assert_se(revents == EPOLLHUP);

        (*c)++;
        return 0;
}

TEST(leave_ratelimit) {
        bool expect_ratelimit = false, manually_left_ratelimit = false;
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        unsigned c = 0;
        int r;

        assert_se(sd_event_default(&e) >= 0);

        /* Create an event source that will continuously fire by creating a pipe whose write side is closed,
         * and which hence will only see EOF and constant EPOLLHUP */
        assert_se(pipe2(pfd, O_CLOEXEC) >= 0);
        assert_se(sd_event_add_io(e, &s, pfd[0], EPOLLIN, hup_callback, &c) >= 0);
        assert_se(sd_event_source_set_io_fd_own(s, true) >= 0);
        assert_se(sd_event_source_set_ratelimit(s, 5*USEC_PER_MINUTE, 5) >= 0);

        pfd[0] = -EBADF;
        pfd[1] = safe_close(pfd[1]); /* Trigger continuous EOF */

        for (;;) {
                r = sd_event_prepare(e);
                assert_se(r >= 0);

                if (r == 0) {
                        r = sd_event_wait(e, UINT64_MAX);
                        assert_se(r > 0);
                }

                r = sd_event_dispatch(e);
                assert_se(r > 0);

                r = sd_event_source_is_ratelimited(s);
                assert_se(r >= 0);

                if (c < 5)
                        /* First four dispatches should just work */
                        assert_se(!r);
                else if (c == 5) {
                        /* The fifth dispatch should still work, but we now expect the ratelimit to be hit subsequently */
                        if (!expect_ratelimit) {
                                assert_se(!r);
                                assert_se(sd_event_source_leave_ratelimit(s) == 0); /* this should be a NOP, and return 0 hence */
                                expect_ratelimit = true;
                        } else {
                                /* We expected the ratelimit, let's leave it manually, and verify it */
                                assert_se(r);
                                assert_se(sd_event_source_leave_ratelimit(s) > 0); /* we are ratelimited, hence should return > 0 */
                                assert_se(sd_event_source_is_ratelimited(s) == 0);

                                manually_left_ratelimit = true;
                        }

                } else if (c == 6)
                        /* On the sixth iteration let's just exit */
                        break;
        }

        /* Verify we definitely hit the ratelimit and left it manually again */
        assert_se(manually_left_ratelimit);
}

int main(void) {
        basic();
        test_sd_event_now();
        rtqueue();
        ratelimit();
        simple_timeout();
        test_sd_event_source_set_io_fd();
        leave_ratelimit();
}
