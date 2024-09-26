/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>

#include "macro.h"

assert_cc(sizeof(pid_t) == sizeof(int32_t));
#define PID_PRI PRIi32
#define PID_FMT "%" PID_PRI

assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define UID_FMT "%" PRIu32

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define GID_FMT "%" PRIu32

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define FORMAT_UID(uid) \
        snprintf_ok((char[DECIMAL_STR_MAX(uid_t)]){}, DECIMAL_STR_MAX(uid_t), UID_FMT, uid)
#define FORMAT_GID(gid) \
        snprintf_ok((char[DECIMAL_STR_MAX(gid_t)]){}, DECIMAL_STR_MAX(gid_t), GID_FMT, gid)

