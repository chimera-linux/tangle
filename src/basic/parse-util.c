/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "macro.h"
#include "parse-util.h"
#include "string-util.h"
#include "user-util.h"

int parse_pid(const char *s, pid_t* ret_pid) {
        unsigned long ul = 0;
        char *err = NULL;
        pid_t pid;

        assert(s);

        ul = strtoul(s, &err, 10);
        if (!err || *err)
                return -ERANGE;

        pid = (pid_t) ul;

        if ((unsigned long) pid != ul)
                return -ERANGE;

        if (pid <= 0)
                return -ERANGE;

        if (ret_pid)
                *ret_pid = pid;
        return 0;
}

int parse_uid(const char *s, uid_t *ret) {
        unsigned long uid = 0;
        char *end = NULL;

        assert(s);

        assert_cc(sizeof(uid_t) == sizeof(uint32_t));

        uid = strtoul(s, &end, 10);
        if (!end || *end)
                return -errno;

        if (uid > INT_MAX)
                return -ERANGE;

        if (!uid_is_valid((uid_t)uid))
                return -ENXIO; /* we return ENXIO instead of EINVAL
                                * here, to make it easy to distinguish
                                * invalid numeric uids from invalid
                                * strings. */

        if (ret)
                *ret = (uid_t)uid;

        return 0;
}
