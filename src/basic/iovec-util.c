/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"

size_t iovec_total_size(const struct iovec *iovec, size_t n) {
        size_t sum = 0;

        assert(iovec || n == 0);

        FOREACH_ARRAY(j, iovec, n)
                sum += j->iov_len;

        return sum;
}
