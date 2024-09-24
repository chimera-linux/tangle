/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

_printf_(3, 4)
static inline char* snprintf_ok(char *buf, size_t len, const char *format, ...) {
        va_list ap;
        int r;

        va_start(ap, format);
        r = vsnprintf(buf, len, format, ap);
        va_end(ap);

        return r >= 0 && (size_t) r < len ? buf : NULL;
}

#define xsprintf(buf, fmt, ...) \
        assert_message_se(snprintf_ok(buf, ELEMENTSOF(buf), fmt, ##__VA_ARGS__), "xsprintf: " #buf "[] must be big enough")
