/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include "macro.h"

typedef enum ValidHostnameFlags {
        VALID_HOSTNAME_TRAILING_DOT = 1 << 0,   /* Accept trailing dot on multi-label names */
        VALID_HOSTNAME_DOT_HOST     = 1 << 1,   /* Accept ".host" as valid hostname */
} ValidHostnameFlags;

bool hostname_is_valid(const char *s, ValidHostnameFlags flags) _pure_;
