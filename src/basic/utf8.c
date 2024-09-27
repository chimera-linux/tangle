/* SPDX-License-Identifier: LGPL-2.0-or-later */

/* Parts of this file are based on the GLIB utf8 validation functions. The original copyright follows.
 *
 * gutf8.c - Operations on UTF-8 strings.
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "gunicode.h"
#include "hexdecoct.h"
#include "macro.h"
#include "string-util.h"
#include "utf8.h"

static bool unichar_is_valid(char32_t ch) {

        if (ch >= 0x110000) /* End of unicode space */
                return false;
        if ((ch & 0xFFFFF800) == 0xD800) /* Reserved area for UTF-16 */
                return false;
        if ((ch >= 0xFDD0) && (ch <= 0xFDEF)) /* Reserved */
                return false;
        if ((ch & 0xFFFE) == 0xFFFE) /* BOM (Byte Order Mark) */
                return false;

        return true;
}

/* count of characters used to encode one unicode char */
static size_t utf8_encoded_expected_len(uint8_t c) {
        if (c < 0x80)
                return 1;
        if ((c & 0xe0) == 0xc0)
                return 2;
        if ((c & 0xf0) == 0xe0)
                return 3;
        if ((c & 0xf8) == 0xf0)
                return 4;
        if ((c & 0xfc) == 0xf8)
                return 5;
        if ((c & 0xfe) == 0xfc)
                return 6;

        return 0;
}

/* decode one unicode char */
int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar) {
        char32_t unichar;
        size_t len;

        assert(str);

        len = utf8_encoded_expected_len(str[0]);

        switch (len) {
        case 1:
                *ret_unichar = (char32_t)str[0];
                return 1;
        case 2:
                unichar = str[0] & 0x1f;
                break;
        case 3:
                unichar = (char32_t)str[0] & 0x0f;
                break;
        case 4:
                unichar = (char32_t)str[0] & 0x07;
                break;
        case 5:
                unichar = (char32_t)str[0] & 0x03;
                break;
        case 6:
                unichar = (char32_t)str[0] & 0x01;
                break;
        default:
                return -EINVAL;
        }

        for (size_t i = 1; i < len; i++) {
                if (((char32_t)str[i] & 0xc0) != 0x80)
                        return -EINVAL;

                unichar <<= 6;
                unichar |= (char32_t)str[i] & 0x3f;
        }

        *ret_unichar = unichar;
        return len;
}

char *utf8_is_valid_n(const char *str, size_t len_bytes) {
        /* Check if the string is composed of valid utf8 characters. If length len_bytes is given, stop after
         * len_bytes. Otherwise, stop at NUL. */

        assert(str);

        for (const char *p = str; len_bytes != SIZE_MAX ? (size_t) (p - str) < len_bytes : *p != '\0'; ) {
                int len;

                if (_unlikely_(*p == '\0') && len_bytes != SIZE_MAX)
                        return NULL; /* embedded NUL */

                len = utf8_encoded_valid_unichar(p,
                                                 len_bytes != SIZE_MAX ? len_bytes - (p - str) : SIZE_MAX);
                if (_unlikely_(len < 0))
                        return NULL; /* invalid character */

                p += len;
        }

        return (char*) str;
}

char *utf8_escape_invalid(const char *str) {
        char *p, *s;

        assert(str);

        p = s = malloc(strlen(str) * 4 + 1);
        if (!p)
                return NULL;

        while (*str) {
                int len;

                len = utf8_encoded_valid_unichar(str, SIZE_MAX);
                if (len > 0) {
                        s = mempcpy(s, str, len);
                        str += len;
                } else {
                        s = stpcpy(s, UTF8_REPLACEMENT_CHARACTER);
                        str += 1;
                }
        }

        *s = '\0';
        return str_realloc(p);
}

static int utf8_char_console_width(const char *str) {
        char32_t c;
        int r;

        r = utf8_encoded_to_unichar(str, &c);
        if (r < 0)
                return r;

        /* TODO: we should detect combining characters */

        return unichar_iswide(c) ? 2 : 1;
}

size_t utf8_console_width(const char *str) {
        size_t n = 0;

        /* Returns the approximate width a string will take on screen when printed on a character cell
         * terminal/console. */

        while (*str) {
                int w;

                w = utf8_char_console_width(str);
                if (w < 0)
                        return SIZE_MAX;

                n += w;
                str = utf8_next_char(str);
        }

        return n;
}

/* expected size used to encode one unicode char */
static int utf8_unichar_to_encoded_len(char32_t unichar) {

        if (unichar < 0x80)
                return 1;
        if (unichar < 0x800)
                return 2;
        if (unichar < 0x10000)
                return 3;
        if (unichar < 0x200000)
                return 4;
        if (unichar < 0x4000000)
                return 5;

        return 6;
}

/* validate one encoded unicode char and return its length */
int utf8_encoded_valid_unichar(const char *str, size_t length /* bytes */) {
        char32_t unichar;
        size_t len;
        int r;

        assert(str);
        assert(length > 0);

        /* We read until NUL, at most length bytes. SIZE_MAX may be used to disable the length check. */

        len = utf8_encoded_expected_len(str[0]);
        if (len == 0)
                return -EINVAL;

        /* Do we have a truncated multi-byte character? */
        if (len > length)
                return -EINVAL;

        /* ascii is valid */
        if (len == 1)
                return 1;

        /* check if expected encoded chars are available */
        for (size_t i = 0; i < len; i++)
                if ((str[i] & 0x80) != 0x80)
                        return -EINVAL;

        r = utf8_encoded_to_unichar(str, &unichar);
        if (r < 0)
                return r;

        /* check if encoded length matches encoded value */
        if (utf8_unichar_to_encoded_len(unichar) != (int) len)
                return -EINVAL;

        /* check if value has valid range */
        if (!unichar_is_valid(unichar))
                return -EINVAL;

        return (int) len;
}
