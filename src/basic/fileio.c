/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "stdio-util.h"
#include "string-util.h"

/* The maximum size of the file we'll read in one go in read_full_file() (64M). */
#define READ_FULL_BYTES_MAX (64U * U64_MB - UINT64_C(1))
/* Used when a size is specified for read_full_file() with READ_FULL_FILE_UNBASE64 or _UNHEX */
#define READ_FULL_FILE_ENCODED_STRING_AMPLIFICATION_BOUNDARY 3

/* The maximum size of virtual files (i.e. procfs, sysfs, and other virtual "API" files) we'll read in one go
 * in read_virtual_file(). Note that this limit is different (and much lower) than the READ_FULL_BYTES_MAX
 * limit. This reflects the fact that we use different strategies for reading virtual and regular files:
 * virtual files we generally have to read in a single read() syscall since the kernel doesn't support
 * continuation read()s for them. Thankfully they are somewhat size constrained. Thus we can allocate the
 * full potential buffer in advance. Regular files OTOH can be much larger, and there we grow the allocations
 * exponentially in a loop. We use a size limit of 4M-2 because 4M-1 is the maximum buffer that /proc/sys/
 * allows us to read() (larger reads will fail with ENOMEM), and we want to read one extra byte so that we
 * can detect EOFs. */
#define READ_VIRTUAL_BYTES_MAX (4U * U64_MB - UINT64_C(2))

int read_virtual_file_fd(int fd, size_t max_size, char **ret_contents, size_t *ret_size) {
        _cleanup_free_ char *buf = NULL;
        size_t n, size;
        int n_retries;
        bool truncated = false;

        /* Virtual filesystems such as sysfs or procfs use kernfs, and kernfs can work with two sorts of
         * virtual files. One sort uses "seq_file", and the results of the first read are buffered for the
         * second read. The other sort uses "raw" reads which always go direct to the device. In the latter
         * case, the content of the virtual file must be retrieved with a single read otherwise a second read
         * might get the new value instead of finding EOF immediately. That's the reason why the usage of
         * fread(3) is prohibited in this case as it always performs a second call to read(2) looking for
         * EOF. See issue #13585.
         *
         * max_size specifies a limit on the bytes read. If max_size is SIZE_MAX, the full file is read. If
         * the full file is too large to read, an error is returned. For other values of max_size, *partial
         * contents* may be returned. (Though the read is still done using one syscall.) Returns 0 on
         * partial success, 1 if untruncated contents were read. */

        assert(fd >= 0);
        assert(max_size <= READ_VIRTUAL_BYTES_MAX || max_size == SIZE_MAX);

        /* Limit the number of attempts to read the number of bytes returned by fstat(). */
        n_retries = 3;

        for (;;) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return -errno;

                if (!S_ISREG(st.st_mode))
                        return -EBADF;

                /* Be prepared for files from /proc which generally report a file size of 0. */
                assert_cc(READ_VIRTUAL_BYTES_MAX < SSIZE_MAX);
                if (st.st_size > 0 && n_retries > 1) {
                        /* Let's use the file size if we have more than 1 attempt left. On the last attempt
                         * we'll ignore the file size */

                        if (st.st_size > SSIZE_MAX) { /* Avoid overflow with 32-bit size_t and 64-bit off_t. */

                                if (max_size == SIZE_MAX)
                                        return -EFBIG;

                                size = max_size;
                        } else {
                                size = MIN((size_t) st.st_size, max_size);

                                if (size > READ_VIRTUAL_BYTES_MAX)
                                        return -EFBIG;
                        }

                        n_retries--;
                } else if (n_retries > 1) {
                        /* Files in /proc are generally smaller than the page size so let's start with
                         * a page size buffer from malloc and only use the max buffer on the final try. */
                        size = MIN3(page_size() - 1, READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 1;
                } else {
                        size = MIN(READ_VIRTUAL_BYTES_MAX, max_size);
                        n_retries = 0;
                }

                buf = malloc(size + 1);
                if (!buf)
                        return -ENOMEM;

                /* Use a bigger allocation if we got it anyway, but not more than the limit. */
                size = MIN3(MALLOC_SIZEOF_SAFE(buf) - 1, max_size, READ_VIRTUAL_BYTES_MAX);

                for (;;) {
                        ssize_t k;

                        /* Read one more byte so we can detect whether the content of the
                         * file has already changed or the guessed size for files from /proc
                         * wasn't large enough . */
                        k = read(fd, buf, size + 1);
                        if (k >= 0) {
                                n = k;
                                break;
                        }

                        if (errno != EINTR)
                                return -errno;
                }

                /* Consider a short read as EOF */
                if (n <= size)
                        break;

                /* If a maximum size is specified and we already read more we know the file is larger, and
                 * can handle this as truncation case. Note that if the size of what we read equals the
                 * maximum size then this doesn't mean truncation, the file might or might not end on that
                 * byte. We need to rerun the loop in that case, with a larger buffer size, so that we read
                 * at least one more byte to be able to distinguish EOF from truncation. */
                if (max_size != SIZE_MAX && n > max_size) {
                        n = size; /* Make sure we never use more than what we sized the buffer for (so that
                                   * we have one free byte in it for the trailing NUL we add below). */
                        truncated = true;
                        break;
                }

                /* We have no further attempts left? Then the file is apparently larger than our limits. Give up. */
                if (n_retries <= 0)
                        return -EFBIG;

                /* Hmm... either we read too few bytes from /proc or less likely the content of the file
                 * might have been changed (and is now bigger) while we were processing, let's try again
                 * either with the new file size. */

                if (lseek(fd, 0, SEEK_SET) < 0)
                        return -errno;

                buf = mfree(buf);
        }

        if (ret_contents) {

                /* Safety check: if the caller doesn't want to know the size of what we just read it will
                 * rely on the trailing NUL byte. But if there's an embedded NUL byte, then we should refuse
                 * operation as otherwise there'd be ambiguity about what we just read. */
                if (!ret_size && memchr(buf, 0, n))
                        return -EBADMSG;

                if (n < size) {
                        char *p;

                        /* Return rest of the buffer to libc */
                        p = realloc(buf, n + 1);
                        if (!p)
                                return -ENOMEM;
                        buf = p;
                }

                buf[n] = 0;
                *ret_contents = TAKE_PTR(buf);
        }

        if (ret_size)
                *ret_size = n;

        return !truncated;
}

int read_virtual_file_at(
                int dir_fd,
                const char *filename,
                size_t max_size,
                char **ret_contents,
                size_t *ret_size) {

        _cleanup_close_ int fd = -EBADF;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        if (!filename) {
                if (dir_fd == AT_FDCWD)
                        return -EBADF;

                return read_virtual_file_fd(dir_fd, max_size, ret_contents, ret_size);
        }

        fd = openat(dir_fd, filename, O_RDONLY | O_NOCTTY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return read_virtual_file_fd(fd, max_size, ret_contents, ret_size);
}

