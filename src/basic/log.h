/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "list.h"
#include "macro.h"
#include "stdio-util.h"

#define SYNTHETIC_ERRNO(num)                (abs(num) | (1 << 30))
#define IS_SYNTHETIC_ERRNO(val)             (((val) >> 30) == 1)
#define ERRNO_VALUE(val)                    (abs(val) & ~(1 << 30))

int log_get_max_level(void) _pure_;

/* Functions below that open and close logs or configure logging based on the
 * environment should not be called from library code — this is always a job
 * for the application itself. */

int log_dispatch_internal(
                int level,
                int error,
                int line,
                const char *func,
                const char *object_field,
                const char *object,
                const char *extra,
                const char *extra_field,
                char *buffer);

int log_internal(
                int level,
                int error,
                int line,
                const char *func,
                const char *format, ...) _printf_(5,6);

int log_internalv(
                int level,
                int error,
                int line,
                const char *func,
                const char *format,
                va_list ap) _printf_(5,0);

/* Logging for various assertions */
_noreturn_ void log_assert_failed(
                const char *text,
                int line,
                const char *func);

_noreturn_ void log_assert_failed_unreachable(
                int line,
                const char *func);

void log_assert_failed_return(
                const char *text,
                int line,
                const char *func);

#define log_dispatch(level, error, buffer)                              \
        log_dispatch_internal(level, error, __LINE__, __func__, NULL, NULL, NULL, NULL, buffer)

/* Logging with level */
#define log_full_errno_zerook(level, error, ...)                        \
        ({                                                              \
                int _level = (level), _e = (error);                     \
                _e = (log_get_max_level() >= LOG_PRI(_level))           \
                        ? log_internal(_level, _e, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
                _e < 0 ? _e : -ESTRPIPE;                                \
        })

#define ASSERT_NON_ZERO(x)

#define log_full_errno(level, error, ...)                               \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_full_errno_zerook(level, _error, __VA_ARGS__);      \
        })

#define log_full(level, fmt, ...)                                      \
        ({                                                             \
                (void) log_full_errno_zerook(level, 0, fmt, ##__VA_ARGS__); \
        })

/* Normal logging */
#define log_debug(...)     log_full(LOG_DEBUG,   __VA_ARGS__)
#define log_info(...)      log_full(LOG_INFO,    __VA_ARGS__)
#define log_notice(...)    log_full(LOG_NOTICE,  __VA_ARGS__)
#define log_warning(...)   log_full(LOG_WARNING, __VA_ARGS__)
#define log_error(...)     log_full(LOG_ERR,     __VA_ARGS__)
#define log_emergency(...) log_full(log_emergency_level(), __VA_ARGS__)

/* Logging triggered by an errno-like error */
#define log_debug_errno(error, ...)     log_full_errno(LOG_DEBUG,   error, __VA_ARGS__)
#define log_info_errno(error, ...)      log_full_errno(LOG_INFO,    error, __VA_ARGS__)
#define log_notice_errno(error, ...)    log_full_errno(LOG_NOTICE,  error, __VA_ARGS__)
#define log_warning_errno(error, ...)   log_full_errno(LOG_WARNING, error, __VA_ARGS__)
#define log_error_errno(error, ...)     log_full_errno(LOG_ERR,     error, __VA_ARGS__)
#define log_emergency_errno(error, ...) log_full_errno(log_emergency_level(), error, __VA_ARGS__)

