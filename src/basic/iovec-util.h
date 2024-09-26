/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "alloc-util.h"
#include "macro.h"

size_t iovec_total_size(const struct iovec *iovec, size_t n);

/* This accepts both const and non-const pointers */
#define IOVEC_MAKE(base, len)                                           \
        (struct iovec) {                                                \
                .iov_base = (void*) (base),                             \
                .iov_len = (len),                                       \
        }

static inline struct iovec* iovec_make_string(struct iovec *iovec, const char *s) {
        assert(iovec);
        /* We don't use strlen_ptr() here, because we don't want to include string-util.h for now */
        *iovec = IOVEC_MAKE(s, s ? strlen(s) : 0);
        return iovec;
}

#define IOVEC_MAKE_STRING(s) \
        *iovec_make_string(&(struct iovec) {}, s)
