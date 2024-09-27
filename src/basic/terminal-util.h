/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <termios.h>

#include "macro.h"

bool isatty_safe(int fd);

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int fd_columns(int fd);
unsigned columns(void);
