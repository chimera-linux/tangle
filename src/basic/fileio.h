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

#define LONG_LINE_MAX (1U*1024U*1024U)

typedef enum ReadLineFlags {
        READ_LINE_ONLY_NUL  = 1 << 0,
        READ_LINE_IS_A_TTY  = 1 << 1,
        READ_LINE_NOT_A_TTY = 1 << 2,
} ReadLineFlags;

int read_line_full(FILE *f, size_t limit, ReadLineFlags flags, char **ret);

static inline int read_line(FILE *f, size_t limit, char **ret) {
        return read_line_full(f, limit, 0, ret);
}

int read_one_line_file(const char *filename, char **ret);

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size);
int read_virtual_file_at(int dir_fd, const char *filename, size_t max_size, char **ret_contents, size_t *ret_size);
static inline int read_virtual_file(const char *filename, size_t max_size, char **ret_contents, size_t *ret_size) {
        return read_virtual_file_at(AT_FDCWD, filename, max_size, ret_contents, ret_size);
}
static inline int read_full_virtual_file(const char *filename, char **ret_contents, size_t *ret_size) {
        return read_virtual_file(filename, SIZE_MAX, ret_contents, ret_size);
}

int fflush_and_check(FILE *f);

int fputs_with_separator(FILE *f, const char *s, const char *separator, bool *space);

FILE* open_memstream_unlocked(char **ptr, size_t *sizeloc);
