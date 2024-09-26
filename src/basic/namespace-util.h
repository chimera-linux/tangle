/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int namespace_open(
                pid_t pid,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);
