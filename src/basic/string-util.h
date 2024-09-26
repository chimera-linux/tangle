/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "macro.h"
#include "string-util-fundamental.h"

/* What is interpreted as whitespace? */
#define WHITESPACE          " \t\n\r"
#define NEWLINE             "\n\r"
#define QUOTES              "\"\'"
#define COMMENTS            "#;"
#define GLOB_CHARS          "*?["
#define DIGITS              "0123456789"
#define LOWERCASE_LETTERS   "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS             LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL      LETTERS DIGITS
#define HEXDIGITS           DIGITS "abcdefABCDEF"
#define LOWERCASE_HEXDIGITS DIGITS "abcdef"
#define URI_RESERVED        ":/?#[]@!$&'()*+;="         /* [RFC3986] */
#define URI_UNRESERVED      ALPHANUMERICAL "-._~"       /* [RFC3986] */
#define URI_VALID           URI_RESERVED URI_UNRESERVED /* [RFC3986] */

static inline char* strstr_ptr(const char *haystack, const char *needle) {
        if (!haystack || !needle)
                return NULL;
        return strstr(haystack, needle);
}

static inline char *strstrafter(const char *haystack, const char *needle) {
        char *p;

        /* Returns NULL if not found, or pointer to first character after needle if found */

        p = strstr_ptr(haystack, needle);
        if (!p)
                return NULL;

        return p + strlen(needle);
}

static inline const char* strnull(const char *s) {
        return s ?: "(null)";
}

static inline const char *strna(const char *s) {
        return s ?: "n/a";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* plus_minus(bool b) {
        return b ? "+" : "-";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

static inline const char* enable_disable(bool b) {
        return b ? "enable" : "disable";
}

static inline const char* enabled_disabled(bool b) {
        return b ? "enabled" : "disabled";
}

static inline bool _pure_ in_charset(const char *s, const char* charset) {
        assert(s);
        assert(charset);
        return s[strspn(s, charset)] == '\0';
}

static inline bool char_is_cc(char p) {
        /* char is unsigned on some architectures, e.g. aarch64. So, compiler may warn the condition
         * p >= 0 is always true. See #19543. Hence, let's cast to unsigned before the comparison. Note
         * that the cast in the right hand side is redundant, as according to the C standard, compilers
         * automatically cast a signed value to unsigned when comparing with an unsigned variable. Just
         * for safety and readability. */
        return (uint8_t) p < (uint8_t) ' ' || p == 127;
}
bool string_has_cc(const char *p, const char *ok) _pure_;

char *cellescape(char *buf, size_t len, const char *s);

int free_and_strdup(char **p, const char *s);
int free_and_strndup(char **p, const char *s, size_t l);

int strdup_to_full(char **ret, const char *src);
static inline int strdup_to(char **ret, const char *src) {
        int r = strdup_to_full(ASSERT_PTR(ret), src);
        return r < 0 ? r : 0;  /* Suppress return value of 1. */
}

char *find_line_startswith(const char *haystack, const char *needle);

typedef enum MakeCStringMode {
        MAKE_CSTRING_REFUSE_TRAILING_NUL,
        MAKE_CSTRING_ALLOW_TRAILING_NUL,
        MAKE_CSTRING_REQUIRE_TRAILING_NUL,
        _MAKE_CSTRING_MODE_MAX,
        _MAKE_CSTRING_MODE_INVALID = -1,
} MakeCStringMode;

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret);

char *strjoin_real(const char *x, ...) _sentinel_;
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                size_t _len_ = 0;                                       \
                size_t _i_;                                             \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = newa(char, _len_ + 1);                      \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

char *strextend_with_separator_internal(char **x, const char *separator, ...) _sentinel_;
#define strextend_with_separator(x, separator, ...) strextend_with_separator_internal(x, separator, __VA_ARGS__, NULL)
#define strextend(x, ...) strextend_with_separator_internal(x, NULL, __VA_ARGS__, NULL)

char* strshorten(char *s, size_t l);

static inline char* str_realloc(char *p) {
        /* Reallocate *p to actual size. Ignore failure, and return the original string on error. */

        if (!p)
                return NULL;

        return realloc(p, strlen(p) + 1) ?: p;
}
