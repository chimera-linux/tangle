/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "string-util.h"
#include "time-util.h"

int safe_getcwd(char **ret) {
        _cleanup_free_ char *cwd = NULL;

        cwd = get_current_dir_name();
        if (!cwd)
                return negative_errno();

        /* Let's make sure the directory is really absolute, to protect us from the logic behind
         * CVE-2018-1000001 */
        if (cwd[0] != '/')
                return -ENOMEDIUM;

        if (ret)
                *ret = TAKE_PTR(cwd);

        return 0;
}

char* path_startswith(const char *path, const char *prefix) {
        assert(path);
        assert(prefix);

        /* Returns a pointer to the start of the first component after the parts matched by
         * the prefix, iff
         * - both paths are absolute or both paths are relative,
         * and
         * - each component in prefix in turn matches a component in path at the same position.
         * An empty string will be returned when the prefix and path are equivalent.
         *
         * Returns NULL otherwise.
         */

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                const char *p, *q;
                int r, k;

                r = path_find_first_component(&path, true, &p);
                if (r < 0)
                        return NULL;

                k = path_find_first_component(&prefix, true, &q);
                if (k < 0)
                        return NULL;

                if (k == 0)
                        return (char*) (p ?: path);

                if (r != k)
                        return NULL;

                if (!strneq(p, q, r))
                        return NULL;
        }
}

static char* path_simplify(char *path) {
        bool add_slash = false, absolute, beginning = true;
        char *f = path;
        int r;

        /* Removes redundant inner and trailing slashes. Also removes unnecessary dots.
         * Modifies the passed string in-place.
         *
         * ///foo//./bar/.   becomes /foo/bar
         * .//./foo//./bar/. becomes foo/bar
         * /../foo/bar       becomes /foo/bar
         * /../foo/bar/..    becomes /foo/bar/..
         */

        if (isempty(path))
                return path;

        absolute = path_is_absolute(path);
        f += absolute;  /* Keep leading /, if present. */

        for (const char *p = f;;) {
                const char *e;

                r = path_find_first_component(&p, true, &e);
                if (r == 0)
                        break;

                if (r > 0 && absolute && beginning && path_startswith(e, ".."))
                        /* If we're at the beginning of an absolute path, we can safely skip ".." */
                        continue;

                beginning = false;

                if (add_slash)
                        *f++ = '/';

                if (r < 0) {
                        /* if path is invalid, then refuse to simplify the remaining part. */
                        memmove(f, p, strlen(p) + 1);
                        return path;
                }

                memmove(f, e, r);
                f += r;

                add_slash = true;
        }

        /* Special rule, if we stripped everything, we need a "." for the current directory. */
        if (f == path)
                *f++ = '.';

        *f = '\0';
        return path;
}

int path_compare(const char *a, const char *b) {
        int r;

        /* Order NULL before non-NULL */
        r = CMP(!!a, !!b);
        if (r != 0)
                return r;

        /* A relative path and an absolute path must not compare as equal.
         * Which one is sorted before the other does not really matter.
         * Here a relative path is ordered before an absolute path. */
        r = CMP(path_is_absolute(a), path_is_absolute(b));
        if (r != 0)
                return r;

        for (;;) {
                const char *aa, *bb;
                int j, k;

                j = path_find_first_component(&a, true, &aa);
                k = path_find_first_component(&b, true, &bb);

                if (j < 0 || k < 0) {
                        /* When one of paths is invalid, order invalid path after valid one. */
                        r = CMP(j < 0, k < 0);
                        if (r != 0)
                                return r;

                        /* fallback to use strcmp() if both paths are invalid. */
                        return strcmp(a, b);
                }

                /* Order prefixes first: "/foo" before "/foo/bar" */
                if (j == 0) {
                        if (k == 0)
                                return 0;
                        return -1;
                }
                if (k == 0)
                        return 1;

                /* Alphabetical sort: "/foo/aaa" before "/foo/b" */
                r = memcmp(aa, bb, MIN(j, k));
                if (r != 0)
                        return r;

                /* Sort "/foo/a" before "/foo/aaa" */
                r = CMP(j, k);
                if (r != 0)
                        return r;
        }
}

static const char* skip_slash_or_dot(const char *p) {
        for (; !isempty(p); p++) {
                if (*p == '/')
                        continue;
                if (startswith(p, "./")) {
                        p++;
                        continue;
                }
                break;
        }
        return p;
}

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret) {
        const char *q, *first, *end_first, *next;
        size_t len;

        assert(p);

        /* When a path is input, then returns the pointer to the first component and its length, and
         * move the input pointer to the next component or nul. This skips both over any '/'
         * immediately *before* and *after* the first component before returning.
         *
         * Examples
         *   Input:  p: "//.//aaa///bbbbb/cc"
         *   Output: p: "bbbbb///cc"
         *           ret: "aaa///bbbbb/cc"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "aaa//"
         *   Output: p: (pointer to NUL)
         *           ret: "aaa//"
         *           return value: 3 (== strlen("aaa"))
         *
         *   Input:  p: "/", ".", ""
         *   Output: p: (pointer to NUL)
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: NULL
         *   Output: p: NULL
         *           ret: NULL
         *           return value: 0
         *
         *   Input:  p: "(too long component)"
         *   Output: return value: -EINVAL
         *
         *   (when accept_dot_dot is false)
         *   Input:  p: "//..//aaa///bbbbb/cc"
         *   Output: return value: -EINVAL
         */

        q = *p;

        first = skip_slash_or_dot(q);
        if (isempty(first)) {
                *p = first;
                if (ret)
                        *ret = NULL;
                return 0;
        }
        if (streq(first, ".")) {
                *p = first + 1;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        end_first = strchrnul(first, '/');
        len = end_first - first;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && first[0] == '.' && first[1] == '.')
                return -EINVAL;

        next = skip_slash_or_dot(end_first);

        *p = next + streq(next, ".");
        if (ret)
                *ret = first;
        return len;
}

static const char* skip_slash_or_dot_backward(const char *path, const char *q) {
        assert(path);
        assert(!q || q >= path);

        for (; q; q = PTR_SUB1(q, path)) {
                if (*q == '/')
                        continue;
                if (q > path && strneq(q - 1, "/.", 2))
                        continue;
                if (q == path && *q == '.')
                        continue;
                break;
        }
        return q;
}

int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret) {
        const char *q, *last_end, *last_begin;
        size_t len;

        /* Similar to path_find_first_component(), but search components from the end.
        *
        * Examples
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: NULL
        *   Output: next: "/cc//././"
        *           ret: "cc//././"
        *           return value: 2 (== strlen("cc"))
        *
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: "/cc//././"
        *   Output: next: "///bbbbb/cc//././"
        *           ret: "bbbbb/cc//././"
        *           return value: 5 (== strlen("bbbbb"))
        *
        *   Input:  path: "//.//aaa///bbbbb/cc//././"
        *           next: "///bbbbb/cc//././"
        *   Output: next: "//.//aaa///bbbbb/cc//././" (next == path)
        *           ret: "aaa///bbbbb/cc//././"
        *           return value: 3 (== strlen("aaa"))
        *
        *   Input:  path: "/", ".", "", or NULL
        *   Output: next: equivalent to path
        *           ret: NULL
        *           return value: 0
        *
        *   Input:  path: "(too long component)"
        *   Output: return value: -EINVAL
        *
        *   (when accept_dot_dot is false)
        *   Input:  path: "//..//aaa///bbbbb/cc/..//"
        *   Output: return value: -EINVAL
        */

        if (isempty(path)) {
                if (next)
                        *next = path;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        if (next && *next) {
                if (*next < path || *next > path + strlen(path))
                        return -EINVAL;
                if (*next == path) {
                        if (ret)
                                *ret = NULL;
                        return 0;
                }
                if (!IN_SET(**next, '\0', '/'))
                        return -EINVAL;
                q = *next - 1;
        } else
                q = path + strlen(path) - 1;

        q = skip_slash_or_dot_backward(path, q);
        if (!q || /* the root directory */
            (q == path && *q == '.')) { /* path is "." or "./" */
                if (next)
                        *next = path;
                if (ret)
                        *ret = NULL;
                return 0;
        }

        last_end = q + 1;

        while (q && *q != '/')
                q = PTR_SUB1(q, path);

        last_begin = q ? q + 1 : path;
        len = last_end - last_begin;

        if (len > NAME_MAX)
                return -EINVAL;
        if (!accept_dot_dot && len == 2 && strneq(last_begin, "..", 2))
                return -EINVAL;

        if (next) {
                q = skip_slash_or_dot_backward(path, q);
                *next = q ? q + 1 : path;
        }

        if (ret)
                *ret = last_begin;
        return len;
}

int path_extract_directory(const char *path, char **ret) {
        const char *c, *next = NULL;
        int r;

        /* The inverse of path_extract_filename(), i.e. returns the directory path prefix. Returns:
         *
         * -EINVAL        → if the path is not valid
         * -EDESTADDRREQ  → if no directory was specified in the passed in path, i.e. only a filename was passed
         * -EADDRNOTAVAIL → if the passed in parameter had no filename but did have a directory, i.e.
         *                   the root dir itself or "." was specified
         * -ENOMEM        → no memory (surprise!)
         *
         * This function guarantees to return a fully valid path, i.e. one that passes path_is_valid().
         */

        r = path_find_last_component(path, false, &next, &c);
        if (r < 0)
                return r;
        if (r == 0) /* empty or root */
                return isempty(path) ? -EINVAL : -EADDRNOTAVAIL;
        if (next == path) {
                if (*path != '/') /* filename only */
                        return -EDESTADDRREQ;

                return strdup_to(ret, "/");
        }

        _cleanup_free_ char *a = strndup(path, next - path);
        if (!a)
                return -ENOMEM;

        path_simplify(a);

        if (!path_is_valid(a))
                return -EINVAL;

        if (ret)
                *ret = TAKE_PTR(a);

        return 0;
}

bool path_is_valid_full(const char *p, bool accept_dot_dot) {
        if (isempty(p))
                return false;

        for (const char *e = p;;) {
                int r;

                r = path_find_first_component(&e, accept_dot_dot, NULL);
                if (r < 0)
                        return false;

                if (e - p >= PATH_MAX) /* Already reached the maximum length for a path? (PATH_MAX is counted
                                        * *with* the trailing NUL byte) */
                        return false;
                if (*e == 0)           /* End of string? Yay! */
                        return true;
        }
}

bool path_is_normalized(const char *p) {
        if (!path_is_safe(p))
                return false;

        if (streq(p, ".") || startswith(p, "./") || endswith(p, "/.") || strstr(p, "/./"))
                return false;

        if (strstr(p, "//"))
                return false;

        return true;
}

bool dot_or_dot_dot(const char *path) {
        if (!path)
                return false;
        if (path[0] != '.')
                return false;
        if (path[1] == 0)
                return true;
        if (path[1] != '.')
                return false;

        return path[2] == 0;
}

int path_make_absolute_cwd(const char *p, char **ret) {
        char *c;
        int r;

        assert(p);
        assert(ret);

        /* Similar to path_make_absolute(), but prefixes with the
         * current working directory. */

        if (path_is_absolute(p))
                c = strdup(p);
        else {
                _cleanup_free_ char *cwd = NULL;

                r = safe_getcwd(&cwd);
                if (r < 0)
                        return r;

                c = path_join(cwd, p);
        }
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

char* path_extend_internal(char **x, ...) {
        size_t sz, old_sz;
        char *q, *nx;
        const char *p;
        va_list ap;
        bool slash;

        /* Joins all listed strings until the sentinel and places a "/" between them unless the strings
         * end/begin already with one so that it is unnecessary. Note that slashes which are already
         * duplicate won't be removed. The string returned is hence always equal to or longer than the sum of
         * the lengths of the individual strings.
         *
         * The first argument may be an already allocated string that is extended via realloc() if
         * non-NULL. path_extend() and path_join() are macro wrappers around this function, making use of the
         * first parameter to distinguish the two operations.
         *
         * Note: any listed empty string is simply skipped. This can be useful for concatenating strings of
         * which some are optional.
         *
         * Examples:
         *
         * path_join("foo", "bar") → "foo/bar"
         * path_join("foo/", "bar") → "foo/bar"
         * path_join("", "foo", "", "bar", "") → "foo/bar" */

        sz = old_sz = x ? strlen_ptr(*x) : 0;
        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                size_t add;

                if (isempty(p))
                        continue;

                add = 1 + strlen(p);
                if (sz > SIZE_MAX - add) { /* overflow check */
                        va_end(ap);
                        return NULL;
                }

                sz += add;
        }
        va_end(ap);

        nx = realloc(x ? *x : NULL, GREEDY_ALLOC_ROUND_UP(sz+1));
        if (!nx)
                return NULL;
        if (x)
                *x = nx;

        if (old_sz > 0)
                slash = nx[old_sz-1] == '/';
        else {
                nx[old_sz] = 0;
                slash = true; /* no need to generate a slash anymore */
        }

        q = nx + old_sz;

        va_start(ap, x);
        while ((p = va_arg(ap, char*)) != POINTER_MAX) {
                if (isempty(p))
                        continue;

                if (!slash && p[0] != '/')
                        *(q++) = '/';

                q = stpcpy(q, p);
                slash = endswith(p, "/");
        }
        va_end(ap);

        return nx;
}
