/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "macro.h"
#include "time-util.h"

ssize_t loop_read(int fd, void *buf, size_t nbytes, bool do_poll);
int loop_read_exact(int fd, void *buf, size_t nbytes, bool do_poll);

int loop_write_full(int fd, const void *buf, size_t nbytes, usec_t timeout);
static inline int loop_write(int fd, const void *buf, size_t nbytes) {
        return loop_write_full(fd, buf, nbytes, 0);
}

int ppoll_usec(struct pollfd *fds, size_t nfds, usec_t timeout);
int fd_wait_for_event(int fd, int event, usec_t timeout);
