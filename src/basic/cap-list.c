/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <string.h>

#include "alloc-util.h"
#include "capability-util.h"
#include "cap-list.h"
#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

static const struct capability_name* lookup_capability(register const char *str, register GPERF_LEN_TYPE len);

#include "cap-from-name.h"
#include "cap-to-name.h"

const char *capability_to_name(int id) {
        if (id < 0)
                return NULL;
        if (id >= capability_list_length())
                return NULL;

        return capability_names[id];
}

const char *capability_to_string(int id, char buf[static CAPABILITY_TO_STRING_MAX]) {
        const char *p;

        if (id < 0)
                return NULL;
        if (id > CAP_LIMIT) /* refuse caps > 62 since we can't store them in a uint64_t mask anymore, and still retain UINT64_MAX as marker for "unset" */
                return NULL;

        p = capability_to_name(id);
        if (p)
                return p;

        sprintf(buf, "0x%x", (unsigned) id); /* numerical fallback */
        return buf;
}

int capability_from_name(const char *name) {
        const struct capability_name *sc;
        long l;
        char *err = NULL;

        assert(name);

        /* Try to parse numeric capability */
        l = strtol(name, &err, 10);
        if (err && !*err) {
                if (l < 0 || l > CAP_LIMIT)
                        return -EINVAL;

                return (int)l;
        }

        /* Try to parse string capability */
        sc = lookup_capability(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}

/* This is the number of capability names we are *compiled* with.  For the max capability number of the
 * currently-running kernel, use cap_last_cap(). Note that this one returns the size of the array, i.e. one
 * value larger than the last known capability. This is different from cap_last_cap() which returns the
 * highest supported capability. Hence with everyone agreeing on the same capabilities list, this function
 * will return one higher than cap_last_cap(). */
int capability_list_length(void) {
        return MIN((int) ELEMENTSOF(capability_names), CAP_LIMIT + 1);
}
