/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "cap-list.h"
#include "fileio.h"
#include "log.h"
#include "logarithm.h"
#include "macro.h"
#include "user-util.h"

int have_effective_cap(int value) {
        _cleanup_cap_free_ cap_t cap = NULL;
        cap_flag_value_t fv = CAP_CLEAR; /* To avoid false-positive use-of-uninitialized-value error reported
                                          * by fuzzers. */

        cap = cap_get_proc();
        if (!cap)
                return -errno;

        if (cap_get_flag(cap, value, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        return fv == CAP_SET;
}

unsigned cap_last_cap(void) {
        static atomic_int saved = INT_MAX;
        int r, c;

        c = saved;
        if (c != INT_MAX)
                return c;

        /* Available since linux-3.2 */
        _cleanup_free_ char *content = NULL;
        r = read_one_line_file("/proc/sys/kernel/cap_last_cap", &content);
        if (r < 0)
                log_debug_errno(r, "Failed to read /proc/sys/kernel/cap_last_cap, ignoring: %m");
        else {
                char *end = NULL;
                long lc = strtol(content, &end, 10);
                if (!end || *end || lc > INT_MAX) {
                        if (lc > INT_MAX) errno = ERANGE;
                        log_debug_errno(r, "Failed to parse /proc/sys/kernel/cap_last_cap, ignoring: %m");
                } else {
                        if (c > CAP_LIMIT) /* Safety for the future: if one day the kernel learns more than
                                            * 64 caps, then we are in trouble (since we, as much userspace
                                            * and kernel space store capability masks in uint64_t types). We
                                            * also want to use UINT64_MAX as marker for "unset". Hence let's
                                            * hence protect ourselves against that and always cap at 62 for
                                            * now. */
                                c = CAP_LIMIT;

                        saved = c;
                        return c;
                }
        }

        /* Fall back to syscall-probing for pre linux-3.2, or where /proc/ is not mounted */
        unsigned long p = (unsigned long) MIN(CAP_LAST_CAP, CAP_LIMIT);

        if (prctl(PR_CAPBSET_READ, p) < 0) {

                /* Hmm, look downwards, until we find one that works */
                for (p--; p > 0; p--)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;

        } else {

                /* Hmm, look upwards, until we find one that doesn't work */
                for (; p < CAP_LIMIT; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        c = (int) p;
        saved = c;
        return c;
}

int capability_update_inherited_set(cap_t caps, uint64_t set) {
        /* Add capabilities in the set to the inherited caps, drops capabilities not in the set.
         * Do not apply them yet. */

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                cap_flag_value_t flag = set & (UINT64_C(1) << i) ? CAP_SET : CAP_CLEAR;
                cap_value_t v;

                v = (cap_value_t) i;

                if (cap_set_flag(caps, CAP_INHERITABLE, 1, &v, flag) < 0)
                        return -errno;
        }

        return 0;
}

int capability_ambient_set_apply(uint64_t set, bool also_inherit) {
        _cleanup_cap_free_ cap_t caps = NULL;
        int r;

        /* Remove capabilities requested in ambient set, but not in the bounding set */
        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                if (set == 0)
                        break;

                if (FLAGS_SET(set, (UINT64_C(1) << i)) && prctl(PR_CAPBSET_READ, i) != 1) {
                        log_debug("Ambient capability %s requested but missing from bounding set,"
                                        " suppressing automatically.", capability_to_name(i));
                        set &= ~(UINT64_C(1) << i);
                }
        }

        /* Add the capabilities to the ambient set (an possibly also the inheritable set) */

        /* Check that we can use PR_CAP_AMBIENT or quit early. */
        if (!ambient_capabilities_supported())
                return (set & all_capabilities()) == 0 ?
                        0 : -EOPNOTSUPP; /* if actually no ambient caps are to be set, be silent,
                                          * otherwise fail recognizably */

        if (also_inherit) {
                caps = cap_get_proc();
                if (!caps)
                        return -errno;

                r = capability_update_inherited_set(caps, set);
                if (r < 0)
                        return -errno;

                if (cap_set_proc(caps) < 0)
                        return -errno;
        }

        for (unsigned i = 0; i <= cap_last_cap(); i++) {

                if (set & (UINT64_C(1) << i)) {

                        /* Add the capability to the ambient set. */
                        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0) < 0)
                                return -errno;
                } else {

                        /* Drop the capability so we don't inherit capabilities we didn't ask for. */
                        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0);
                        if (r < 0)
                                return -errno;

                        if (r)
                                if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, i, 0, 0) < 0)
                                        return -errno;

                }
        }

        return 0;
}

int capability_gain_cap_setpcap(cap_t *ret_before_caps) {
        _cleanup_cap_free_ cap_t caps = NULL;
        cap_flag_value_t fv;
        caps = cap_get_proc();
        if (!caps)
                return -errno;

        if (cap_get_flag(caps, CAP_SETPCAP, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        if (fv != CAP_SET) {
                _cleanup_cap_free_ cap_t temp_cap = NULL;
                static const cap_value_t v = CAP_SETPCAP;

                temp_cap = cap_dup(caps);
                if (!temp_cap)
                        return -errno;

                if (cap_set_flag(temp_cap, CAP_EFFECTIVE, 1, &v, CAP_SET) < 0)
                        return -errno;

                if (cap_set_proc(temp_cap) < 0)
                        log_debug_errno(errno, "Can't acquire effective CAP_SETPCAP bit, ignoring: %m");

                /* If we didn't manage to acquire the CAP_SETPCAP bit, we continue anyway, after all this just means
                 * we'll fail later, when we actually intend to drop some capabilities or try to set securebits. */
        }
        if (ret_before_caps)
                /* Return the capabilities as they have been before setting CAP_SETPCAP */
                *ret_before_caps = TAKE_PTR(caps);

        return 0;
}

int capability_bounding_set_drop(uint64_t keep, bool right_now) {
        _cleanup_cap_free_ cap_t before_cap = NULL, after_cap = NULL;
        int r;

        /* If we are run as PID 1 we will lack CAP_SETPCAP by default
         * in the effective set (yes, the kernel drops that when
         * executing init!), so get it back temporarily so that we can
         * call PR_CAPBSET_DROP. */

        r = capability_gain_cap_setpcap(&before_cap);
        if (r < 0)
                return r;

        after_cap = cap_dup(before_cap);
        if (!after_cap)
                return -errno;

        for (unsigned i = 0; i <= cap_last_cap(); i++) {
                cap_value_t v;

                if ((keep & (UINT64_C(1) << i)))
                        continue;

                /* Drop it from the bounding set */
                if (prctl(PR_CAPBSET_DROP, i) < 0) {
                        r = -errno;

                        /* If dropping the capability failed, let's see if we didn't have it in the first place. If so,
                         * continue anyway, as dropping a capability we didn't have in the first place doesn't really
                         * matter anyway. */
                        if (prctl(PR_CAPBSET_READ, i) != 0)
                                goto finish;
                }
                v = (cap_value_t) i;

                /* Also drop it from the inheritable set, so
                 * that anything we exec() loses the
                 * capability for good. */
                if (cap_set_flag(after_cap, CAP_INHERITABLE, 1, &v, CAP_CLEAR) < 0) {
                        r = -errno;
                        goto finish;
                }

                /* If we shall apply this right now drop it
                 * also from our own capability sets. */
                if (right_now) {
                        if (cap_set_flag(after_cap, CAP_PERMITTED, 1, &v, CAP_CLEAR) < 0 ||
                            cap_set_flag(after_cap, CAP_EFFECTIVE, 1, &v, CAP_CLEAR) < 0) {
                                r = -errno;
                                goto finish;
                        }
                }
        }

        r = 0;

finish:
        if (cap_set_proc(after_cap) < 0) {
                /* If there are no actual changes anyway then let's ignore this error. */
                if (cap_compare(before_cap, after_cap) != 0)
                        r = -errno;
        }

        return r;
}

static int change_capability(cap_value_t cv, cap_flag_value_t flag) {
        _cleanup_cap_free_ cap_t tmp_cap = NULL;

        tmp_cap = cap_get_proc();
        if (!tmp_cap)
                return -errno;

        if ((cap_set_flag(tmp_cap, CAP_INHERITABLE, 1, &cv, flag) < 0) ||
            (cap_set_flag(tmp_cap, CAP_PERMITTED, 1, &cv, flag) < 0) ||
            (cap_set_flag(tmp_cap, CAP_EFFECTIVE, 1, &cv, flag) < 0))
                return -errno;

        if (cap_set_proc(tmp_cap) < 0)
                return -errno;

        return 0;
}

int drop_capability(cap_value_t cv) {
        return change_capability(cv, CAP_CLEAR);
}

int keep_capability(cap_value_t cv) {
        return change_capability(cv, CAP_SET);
}

bool ambient_capabilities_supported(void) {
        static int cache = -1;

        if (cache >= 0)
                return cache;

        /* If PR_CAP_AMBIENT returns something valid, or an unexpected error code we assume that ambient caps are
         * available. */

        cache = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_KILL, 0, 0) >= 0 ||
                !IN_SET(errno, EINVAL, EOPNOTSUPP, ENOSYS);

        return cache;
}
