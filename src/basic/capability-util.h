/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <linux/capability.h>

#include "macro.h"

/* Special marker used when storing a capabilities mask as "unset" */
#define CAP_MASK_UNSET UINT64_MAX

/* All possible capabilities bits on */
#define CAP_MASK_ALL UINT64_C(0x7fffffffffffffff)

/* The largest capability we can deal with, given we want to be able to store cap masks in uint64_t but still
 * be able to use UINT64_MAX as indicator for "not set". The latter makes capability 63 unavailable. */
#define CAP_LIMIT 62

unsigned cap_last_cap(void);
int have_effective_cap(int value);
int capability_gain_cap_setpcap(cap_t *return_caps);
int capability_bounding_set_drop(uint64_t keep, bool right_now);

int capability_ambient_set_apply(uint64_t set, bool also_inherit);
int capability_update_inherited_set(cap_t caps, uint64_t ambient_set);

int drop_capability(cap_value_t cv);
int keep_capability(cap_value_t cv);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(cap_t, cap_free, NULL);
#define _cleanup_cap_free_ _cleanup_(cap_freep)

static inline void cap_free_charpp(char **p) {
        if (*p)
                cap_free(*p);
}
#define _cleanup_cap_free_charp_ _cleanup_(cap_free_charpp)

static inline uint64_t all_capabilities(void) {
        return UINT64_MAX >> (63 - cap_last_cap());
}

static inline bool cap_test_all(uint64_t caps) {
        return FLAGS_SET(caps, all_capabilities());
}

bool ambient_capabilities_supported(void);

/* Identical to linux/capability.h's CAP_TO_MASK(), but uses an unsigned 1U instead of a signed 1 for shifting left, in
 * order to avoid complaints about shifting a signed int left by 31 bits, which would make it negative. */
#define CAP_TO_MASK_CORRECTED(x) (1U << ((x) & 31U))
