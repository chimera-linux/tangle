/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <signal.h>

#include "macro.h"

int reset_all_signal_handlers(void);
int reset_signal_mask(void);

int sigprocmask_many_internal(int how, sigset_t *old, ...);
#define sigprocmask_many(...) sigprocmask_many_internal(__VA_ARGS__, -1)

const char *signal_to_string(int i) _const_;
int signal_from_string(const char *s) _pure_;

static inline bool SIGNAL_VALID(int signo) {
        return signo > 0 && signo < _NSIG;
}

int signal_is_blocked(int sig);
