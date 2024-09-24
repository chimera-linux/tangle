/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "time-util.h"

typedef enum PressureType {
        PRESSURE_TYPE_SOME,
        PRESSURE_TYPE_FULL,
} PressureType;

/* Averages are stored in fixed-point with 11 bit fractions */
typedef struct ResourcePressure {
        unsigned long avg10;
        unsigned long avg60;
        unsigned long avg300;
        usec_t total;
} ResourcePressure;

/* Was the kernel compiled with CONFIG_PSI=y? 1 if yes, 0 if not, negative on error. */
int is_pressure_supported(void);

/* Default parameters for memory pressure watch logic in sd-event and PID 1 */
#define MEMORY_PRESSURE_DEFAULT_TYPE "some"
#define MEMORY_PRESSURE_DEFAULT_THRESHOLD_USEC (200 * USEC_PER_MSEC)
#define MEMORY_PRESSURE_DEFAULT_WINDOW_USEC (2 * USEC_PER_SEC)
