/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"

#define MODE_INVALID ((mode_t) -1)

int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **r);

int open_parent_at(int dir_fd, const char *path, int flags, mode_t mode);
static inline int open_parent(const char *path, int flags, mode_t mode) {
        return open_parent_at(AT_FDCWD, path, flags, mode);
}

int xopenat(int dir_fd, const char *path, int open_flags, mode_t mode);
