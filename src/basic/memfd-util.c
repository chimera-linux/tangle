/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "macro.h"
#include "memfd-util.h"
#include "string-util.h"

int memfd_add_seals(int fd, unsigned int seals) {
        assert(fd >= 0);

        return RET_NERRNO(fcntl(fd, F_ADD_SEALS, seals));
}

int memfd_get_seals(int fd, unsigned int *ret_seals) {
        int r;

        assert(fd >= 0);

        r = RET_NERRNO(fcntl(fd, F_GET_SEALS));
        if (r < 0)
                return r;

        if (ret_seals)
                *ret_seals = r;
        return 0;
}

int memfd_map(int fd, uint64_t offset, size_t size, void **p) {
        unsigned int seals;
        void *q;
        int r;

        assert(fd >= 0);
        assert(size > 0);
        assert(p);

        r = memfd_get_seals(fd, &seals);
        if (r < 0)
                return r;

        if (seals & F_SEAL_WRITE)
                q = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, offset);
        else
                q = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
        if (q == MAP_FAILED)
                return -errno;

        *p = q;
        return 0;
}

int memfd_set_sealed(int fd) {
        return memfd_add_seals(fd, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int memfd_get_sealed(int fd) {
        unsigned int seals;
        int r;

        r = memfd_get_seals(fd, &seals);
        if (r < 0)
                return r;

        /* We ignore F_SEAL_EXEC here to support older kernels. */
        return FLAGS_SET(seals, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
}

int memfd_get_size(int fd, uint64_t *sz) {
        struct stat stat;

        assert(fd >= 0);
        assert(sz);

        if (fstat(fd, &stat) < 0)
                return -errno;

        *sz = stat.st_size;
        return 0;
}

int memfd_set_size(int fd, uint64_t sz) {
        assert(fd >= 0);

        return RET_NERRNO(ftruncate(fd, sz));
}
