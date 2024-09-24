/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "macro.h"
#include "string-util.h"
#include "time-util.h"

static inline bool path_is_absolute(const char *p) {
        if (!p) /* A NULL pointer is definitely not an absolute path */
                return false;

        return p[0] == '/';
}

int safe_getcwd(char **ret);

int path_compare(const char *a, const char *b) _pure_;
static inline bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);

int path_extract_directory(const char *path, char **ret);

bool path_is_valid_full(const char *p, bool accept_dot_dot) _pure_;

static inline bool path_is_valid(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ true);
}
static inline bool path_is_safe(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ false);
}

bool path_is_normalized(const char *p) _pure_;
