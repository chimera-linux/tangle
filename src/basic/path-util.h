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
int path_make_absolute_cwd(const char *p, char **ret);

int path_compare(const char *a, const char *b) _pure_;
static inline bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

char* path_extend_internal(char **x, ...);
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, POINTER_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, POINTER_MAX)

char* path_startswith(const char *path, const char *prefix);

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

static inline const char* empty_to_root(const char *path) {
        return isempty(path) ? "/" : path;
}

bool dot_or_dot_dot(const char *path);
