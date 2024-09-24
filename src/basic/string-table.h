/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"
#include "string-util.h"

ssize_t string_table_lookup(const char * const *table, size_t len, const char *key);

/* For basic lookup tables with strictly enumerated entries */
#define _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        scope const char *name##_to_string(type i) {                    \
                if (i < 0 || i >= (type) ELEMENTSOF(name##_table))      \
                        return NULL;                                    \
                return name##_table[i];                                 \
        }

#define _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)        \
        scope type name##_from_string(const char *s) {                  \
                return (type) string_table_lookup(name##_table, ELEMENTSOF(name##_table), s); \
        }

#define _DEFINE_STRING_TABLE_LOOKUP(name,type,scope)                    \
        _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,scope)          \
        _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,scope)

#define DEFINE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,)
#define DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,)
#define DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP(name,type) _DEFINE_STRING_TABLE_LOOKUP(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_TO_STRING(name,type,static)
#define DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(name,type) _DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(name,type,static)

#define DUMP_STRING_TABLE(name,type,max)                                \
        do {                                                            \
                flockfile(stdout);                                      \
                for (type _k = 0; _k < (max); _k++) {                   \
                        const char *_t;                                 \
                        _t = name##_to_string(_k);                      \
                        if (!_t)                                        \
                                continue;                               \
                        fputs_unlocked(_t, stdout);                     \
                        fputc_unlocked('\n', stdout);                   \
                }                                                       \
                funlockfile(stdout);                                    \
        } while (false)
