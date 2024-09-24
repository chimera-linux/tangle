/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "macro.h"

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size);
int read_virtual_file_at(int dir_fd, const char *filename, size_t max_size, char **ret_contents, size_t *ret_size);
static inline int read_virtual_file(const char *filename, size_t max_size, char **ret_contents, size_t *ret_size) {
        return read_virtual_file_at(AT_FDCWD, filename, max_size, ret_contents, ret_size);
}
static inline int read_full_virtual_file(const char *filename, char **ret_contents, size_t *ret_size) {
        return read_virtual_file(filename, SIZE_MAX, ret_contents, ret_size);
}
