/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"

int parse_pid(const char *s, pid_t* ret_pid);

int parse_uid(const char *s, uid_t* ret_uid);

static inline int parse_gid(const char *s, gid_t *ret_gid) {
        return parse_uid(s, (uid_t*) ret_gid);
}
