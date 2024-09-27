/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

#include "macro.h"

#define UTF8_REPLACEMENT_CHARACTER "\xef\xbf\xbd"

char *utf8_is_valid_n(const char *str, size_t len_bytes) _pure_;
static inline char *utf8_is_valid(const char *s) {
        return utf8_is_valid_n(s, SIZE_MAX);
}

char *utf8_escape_invalid(const char *s);
int utf8_encoded_valid_unichar(const char *str, size_t length);
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar);

size_t utf8_console_width(const char *str);
