/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"

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
