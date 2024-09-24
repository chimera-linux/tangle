/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/file.h>
#include <linux/falloc.h>
#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "random-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"
#include "umask-util.h"

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = PATH_MAX;

        assert(fd >= 0 || fd == AT_FDCWD);

        if (fd < 0 && isempty(p))
                return -EISDIR; /* In this case, the fd points to the current working directory, and is
                                 * definitely not a symlink. Let's return earlier. */

        for (;;) {
                _cleanup_free_ char *c = NULL;
                ssize_t n;

                c = new(char, l+1);
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, strempty(p), c, l);
                if (n < 0)
                        return -errno;

                if ((size_t) n < l) {
                        c[n] = 0;

                        if (ret)
                                *ret = TAKE_PTR(c);

                        return 0;
                }

                if (l > (SSIZE_MAX-1)/2) /* readlinkat() returns an ssize_t, and we want an extra byte for a
                                          * trailing NUL, hence do an overflow check relative to SSIZE_MAX-1
                                          * here */
                        return -EFBIG;

                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

int open_parent_at(int dir_fd, const char *path, int flags, mode_t mode) {
        _cleanup_free_ char *parent = NULL;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(path);

        r = path_extract_directory(path, &parent);
        if (r == -EDESTADDRREQ) {
                parent = strdup(".");
                if (!parent)
                        return -ENOMEM;
        } else if (r == -EADDRNOTAVAIL) {
                parent = strdup(path);
                if (!parent)
                        return -ENOMEM;
        } else if (r < 0)
                return r;

        /* Let's insist on O_DIRECTORY since the parent of a file or directory is a directory. Except if we open an
         * O_TMPFILE file, because in that case we are actually create a regular file below the parent directory. */

        if (FLAGS_SET(flags, O_PATH))
                flags |= O_DIRECTORY;
        else if (!FLAGS_SET(flags, O_TMPFILE))
                flags |= O_DIRECTORY|O_RDONLY;

        return RET_NERRNO(openat(dir_fd, parent, flags, mode));
}


int xopenat(int dir_fd, const char *path, int open_flags, mode_t mode) {
        _cleanup_close_ int fd = -EBADF;
        bool made = false;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        /* This is like openat(), but has a few tricks up its sleeves, extending behaviour:
         *
         *   • O_DIRECTORY|O_CREAT is supported, which causes a directory to be created, and immediately
         *     opened. When used with the XO_SUBVOLUME flag this will even create a btrfs subvolume.
         *
         *   • If the path is specified NULL or empty, behaves like fd_reopen().
         */

        if (isempty(path)) {
                assert(!FLAGS_SET(open_flags, O_CREAT|O_EXCL));
                return fd_reopen(dir_fd, open_flags & ~O_NOFOLLOW);
        }

        if (FLAGS_SET(open_flags, O_DIRECTORY|O_CREAT)) {
                r = RET_NERRNO(mkdirat(dir_fd, path, mode));
                if (r == -EEXIST) {
                        if (FLAGS_SET(open_flags, O_EXCL))
                                return -EEXIST;

                        made = false;
                } else if (r < 0)
                        return r;
                else
                        made = true;

                open_flags &= ~(O_EXCL|O_CREAT);
        }

        fd = RET_NERRNO(openat(dir_fd, path, open_flags, mode));
        if (fd < 0) {
                if (IN_SET(fd,
                           /* We got ENOENT? then someone else immediately removed it after we
                           * created it. In that case let's return immediately without unlinking
                           * anything, because there simply isn't anything to unlink anymore. */
                           -ENOENT,
                           /* is a symlink? exists already → created by someone else, don't unlink */
                           -ELOOP,
                           /* not a directory? exists already → created by someone else, don't unlink */
                           -ENOTDIR))
                        return fd;

                if (made)
                        (void) unlinkat(dir_fd, path, AT_REMOVEDIR);

                return fd;
        }

        return TAKE_FD(fd);
}

