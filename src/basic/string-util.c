/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"

static int cescape_char(char c, char *buf) {
        char *buf_old = buf;

        /* Needs space for 4 characters in the buffer */

        switch (c) {

                case '\a':
                        *(buf++) = '\\';
                        *(buf++) = 'a';
                        break;
                case '\b':
                        *(buf++) = '\\';
                        *(buf++) = 'b';
                        break;
                case '\f':
                        *(buf++) = '\\';
                        *(buf++) = 'f';
                        break;
                case '\n':
                        *(buf++) = '\\';
                        *(buf++) = 'n';
                        break;
                case '\r':
                        *(buf++) = '\\';
                        *(buf++) = 'r';
                        break;
                case '\t':
                        *(buf++) = '\\';
                        *(buf++) = 't';
                        break;
                case '\v':
                        *(buf++) = '\\';
                        *(buf++) = 'v';
                        break;
                case '\\':
                        *(buf++) = '\\';
                        *(buf++) = '\\';
                        break;
                case '"':
                        *(buf++) = '\\';
                        *(buf++) = '"';
                        break;
                case '\'':
                        *(buf++) = '\\';
                        *(buf++) = '\'';
                        break;

                default:
                        /* For special chars we prefer octal over
                         * hexadecimal encoding, simply because glib's
                         * g_strescape() does the same */
                        if ((c < ' ') || (c >= 127)) {
                                *(buf++) = '\\';
                                *(buf++) = octchar((unsigned char) c >> 6);
                                *(buf++) = octchar((unsigned char) c >> 3);
                                *(buf++) = octchar((unsigned char) c);
                        } else
                                *(buf++) = c;
                        break;
        }

        return buf - buf_old;
}

char* cescape_length(const char *s, size_t n) {
        const char *f;
        char *r, *t;

        assert(s || n == 0);

        /* Does C style string escaping. May be reversed with
         * cunescape(). */

        r = new(char, n*4 + 1);
        if (!r)
                return NULL;

        for (f = s, t = r; f < s + n; f++)
                t += cescape_char(*f, t);

        *t = 0;

        return r;
}

char* cescape(const char *s) {
        assert(s);

        return cescape_length(s, strlen(s));
}

char *cellescape(char *buf, size_t len, const char *s) {
        /* Escape and ellipsize s into buffer buf of size len. Only non-control ASCII
         * characters are copied as they are, everything else is escaped. The result
         * is different then if escaping and ellipsization was performed in two
         * separate steps, because each sequence is either stored in full or skipped.
         * 
         * This function should be used for logging about strings which expected to
         * be plain ASCII in a safe way.
         *
         * An ellipsis will be used if s is too long. It was always placed at the
         * very end.
         */

        size_t i = 0, last_char_width[4] = {}, k = 0;

        assert(buf);
        assert(len > 0); /* at least a terminating NUL */
        assert(s);

        for (;;) {
                char four[4];
                int w;

                if (*s == 0) /* terminating NUL detected? then we are done! */
                        goto done;

                w = cescape_char(*s, four);
                if (i + w + 1 > len) /* This character doesn't fit into the buffer anymore? In that case let's
                                      * ellipsize at the previous location */
                        break;

                /* OK, there was space, let's add this escaped character to the buffer */
                memcpy(buf + i, four, w);
                i += w;

                /* And remember its width in the ring buffer */
                last_char_width[k] = w;
                k = (k + 1) % 4;

                s++;
        }

        /* Ellipsation is necessary. This means we might need to truncate the string again to make space for 4
         * characters ideally, but the buffer is shorter than that in the first place take what we can get */
        for (size_t j = 0; j < ELEMENTSOF(last_char_width); j++) {

                if (i + 4 <= len) /* nice, we reached our space goal */
                        break;

                k = k == 0 ? 3 : k - 1;
                if (last_char_width[k] == 0) /* bummer, we reached the beginning of the strings */
                        break;

                assert(i >= last_char_width[k]);
                i -= last_char_width[k];
        }

        if (i + 4 <= len) { /* yay, enough space */
                buf[i++] = '.';
                buf[i++] = '.';
                buf[i++] = '.';
        } else if (i + 3 <= len) { /* only space for ".." */
                buf[i++] = '.';
                buf[i++] = '.';
        } else if (i + 2 <= len) /* only space for a single "." */
                buf[i++] = '.';
        else
                assert(i + 1 <= len);

done:
        buf[i] = '\0';
        return buf;
}

char* strshorten(char *s, size_t l) {
        assert(s);

        if (l >= SIZE_MAX-1) /* Would not change anything */
                return s;

        if (strnlen(s, l+1) > l)
                s[l] = 0;

        return s;
}

int free_and_strdup(char **p, const char *s) {
        char *t;

        assert(p);

        /* Replaces a string pointer with a strdup()ed new string,
         * possibly freeing the old one. */

        if (streq_ptr(*p, s))
                return 0;

        if (s) {
                t = strdup(s);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);

        return 1;
}

int free_and_strndup(char **p, const char *s, size_t l) {
        char *t;

        assert(p);
        assert(s || l == 0);

        /* Replaces a string pointer with a strndup()ed new string,
         * freeing the old one. */

        if (!*p && !s)
                return 0;

        if (*p && s && strneq(*p, s, l) && (l > strlen(*p) || (*p)[l] == '\0'))
                return 0;

        if (s) {
                t = strndup(s, l);
                if (!t)
                        return -ENOMEM;
        } else
                t = NULL;

        free_and_replace(*p, t);
        return 1;
}

int strdup_to_full(char **ret, const char *src) {
        if (!src) {
                if (ret)
                        *ret = NULL;

                return 0;
        } else {
                if (ret) {
                        char *t = strdup(src);
                        if (!t)
                                return -ENOMEM;
                        *ret = t;
                }

                return 1;
        }
};

char *find_line_startswith(const char *haystack, const char *needle) {
        char *p;

        assert(haystack);
        assert(needle);

        /* Finds the first line in 'haystack' that starts with the specified string. Returns a pointer to the
         * first character after it */

        p = strstr(haystack, needle);
        if (!p)
                return NULL;

        if (p > haystack)
                while (p[-1] != '\n') {
                        p = strstr(p + 1, needle);
                        if (!p)
                                return NULL;
                }

        return p + strlen(needle);
}

int make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret) {
        char *b;

        assert(s || n == 0);
        assert(mode >= 0);
        assert(mode < _MAKE_CSTRING_MODE_MAX);

        /* Converts a sized character buffer into a NUL-terminated NUL string, refusing if there are embedded
         * NUL bytes. Whether to expect a trailing NUL byte can be specified via 'mode' */

        if (n == 0) {
                if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = new0(char, 1);
        } else {
                const char *nul;

                nul = memchr(s, 0, n);
                if (nul) {
                        if (nul < s + n - 1 || /* embedded NUL? */
                            mode == MAKE_CSTRING_REFUSE_TRAILING_NUL)
                                return -EINVAL;

                        n--;
                } else if (mode == MAKE_CSTRING_REQUIRE_TRAILING_NUL)
                        return -EINVAL;

                if (!ret)
                        return 0;

                b = memdup_suffix0(s, n);
        }
        if (!b)
                return -ENOMEM;

        *ret = b;
        return 0;
}

char *strjoin_real(const char *x, ...) {
        va_list ap;
        size_t l = 1;
        char *r, *p;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *)) {
                size_t n;

                n = strlen(t);
                if (n > SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }
                l += n;
        }
        va_end(ap);

        p = r = new(char, l);
        if (!r)
                return NULL;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *))
                p = stpcpy(p, t);
        va_end(ap);

        *p = 0;

        return r;
}

bool string_has_cc(const char *p, const char *ok) {
        assert(p);

        /*
         * Check if a string contains control characters. If 'ok' is
         * non-NULL it may be a string containing additional CCs to be
         * considered OK.
         */

        for (const char *t = p; *t; t++) {
                if (ok && strchr(ok, *t))
                        continue;

                if (char_is_cc(*t))
                        return true;
        }

        return false;
}

char *ellipsize_mem(const char *s, size_t old_length, size_t new_length, unsigned percent) {
        size_t x, suffix_len;
        char *t;

        assert(s);
        assert(percent <= 100);
        assert(new_length != SIZE_MAX);

        if (old_length <= new_length)
                return strndup(s, old_length);

        /* Special case short ellipsations */
        switch (new_length) {

        case 0:
                return strdup("");

        case 1:
                return strdup(".");

        case 2:
                return strdup("..");

        default:
                break;
        }

        t = new(char, new_length+3);
        if (!t)
                return NULL;

        x = ((new_length - 3) * percent + 50) / 100;
        assert(x <= new_length - 3);

        memcpy(mempcpy(t, s, x), "...", 3);
        suffix_len = new_length - x - 3;
        memcpy(t + x + 3, s + old_length - suffix_len, suffix_len);
        *(t + x + 3 + suffix_len) = '\0';

        return t;
}

char *strextend_with_separator_internal(char **x, const char *separator, ...) {
        size_t f, l, l_separator;
        bool need_separator;
        char *nr, *p;
        va_list ap;

        assert(x);

        l = f = strlen_ptr(*x);

        need_separator = !isempty(*x);
        l_separator = strlen_ptr(separator);

        va_start(ap, separator);
        for (;;) {
                const char *t;
                size_t n;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                n = strlen(t);

                if (need_separator)
                        n += l_separator;

                if (n >= SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }

                l += n;
                need_separator = true;
        }
        va_end(ap);

        need_separator = !isempty(*x);

        nr = realloc(*x, GREEDY_ALLOC_ROUND_UP(l+1));
        if (!nr)
                return NULL;

        *x = nr;
        p = nr + f;

        va_start(ap, separator);
        for (;;) {
                const char *t;

                t = va_arg(ap, const char *);
                if (!t)
                        break;

                if (need_separator && separator)
                        p = stpcpy(p, separator);

                p = stpcpy(p, t);

                need_separator = true;
        }
        va_end(ap);

        assert(p == nr + l);

        *p = 0;

        return p;
}

char *delete_trailing_chars(char *s, const char *bad) {
        char *c = s;

        /* Drops all specified bad characters, at the end of the string */

        if (!s)
                return NULL;

        if (!bad)
                bad = WHITESPACE;

        for (char *p = s; *p; p++)
                if (!strchr(bad, *p))
                        c = p + 1;

        *c = 0;

        return s;
}

int string_truncate_lines(const char *s, size_t n_lines, char **ret) {
        const char *p = s, *e = s;
        bool truncation_applied = false;
        char *copy;
        size_t n = 0;

        assert(s);

        /* Truncate after the specified number of lines. Returns > 0 if a truncation was applied or == 0 if
         * there were fewer lines in the string anyway. Trailing newlines on input are ignored, and not
         * generated either. */

        for (;;) {
                size_t k;

                k = strcspn(p, "\n");

                if (p[k] == 0) {
                        if (k == 0) /* final empty line */
                                break;

                        if (n >= n_lines) /* above threshold */
                                break;

                        e = p + k; /* last line to include */
                        break;
                }

                assert(p[k] == '\n');

                if (n >= n_lines)
                        break;

                if (k > 0)
                        e = p + k;

                p += k + 1;
                n++;
        }

        /* e points after the last character we want to keep */
        if (isempty(e))
                copy = strdup(s);
        else {
                if (!in_charset(e, "\n")) /* We only consider things truncated if we remove something that
                                           * isn't a new-line or a series of them */
                        truncation_applied = true;

                copy = strndup(s, e - s);
        }
        if (!copy)
                return -ENOMEM;

        *ret = copy;
        return truncation_applied;
}

int string_extract_line(const char *s, size_t i, char **ret) {
        const char *p = s;
        size_t c = 0;

        /* Extract the i'nth line from the specified string. Returns > 0 if there are more lines after that,
         * and == 0 if we are looking at the last line or already beyond the last line. As special
         * optimization, if the first line is requested and the string only consists of one line we return
         * NULL, indicating the input string should be used as is, and avoid a memory allocation for a very
         * common case. */

        for (;;) {
                const char *q;

                q = strchr(p, '\n');
                if (i == c) {
                        /* The line we are looking for! */

                        if (q) {
                                char *m;

                                m = strndup(p, q - p);
                                if (!m)
                                        return -ENOMEM;

                                *ret = m;
                                return !isempty(q + 1); /* More coming? */
                        } else
                                /* Tell the caller to use the input string if equal */
                                return strdup_to(ret, p != s ? p : NULL);
                }

                if (!q)
                        /* No more lines, return empty line */
                        return strdup_to(ret, "");

                p = q + 1;
                c++;
        }
}
