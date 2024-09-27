/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

bool uid_is_valid(uid_t uid);

static inline bool gid_is_valid(gid_t gid) {
        return uid_is_valid((uid_t) gid);
}

char* uid_to_name(uid_t uid);

char* getusername_malloc(void);

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

typedef enum ValidUserFlags {
        VALID_USER_RELAX         = 1 << 0,
        VALID_USER_ALLOW_NUMERIC = 1 << 2,
} ValidUserFlags;

bool valid_user_group_name(const char *u, ValidUserFlags flags);

int maybe_setgroups(size_t size, const gid_t *list);

int fully_set_uid_gid(uid_t uid, gid_t gid, const gid_t supplementary_gids[], size_t n_supplementary_gids);
