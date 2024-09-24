/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "psi-util.h"
#include "string-util.h"

static char const *pfiles[] = {"/proc/pressure/cpu", "/proc/pressure/io", "/proc/pressure/memory", NULL};

int is_pressure_supported(void) {
        static _Thread_local int cached = -1;
        char const **strs = NULL;
        int r;

        /* The pressure files, both under /proc/ and in cgroups, will exist even if the kernel has PSI
         * support disabled; we have to read the file to make sure it doesn't return -EOPNOTSUPP */

        if (cached >= 0)
                return cached;

        for (strs = pfiles; *strs; ++strs) {
                r = read_virtual_file(*strs, 0, NULL, NULL);
                if (r == -ENOENT || ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return (cached = false);
                if (r < 0)
                        return r;
        }

        return (cached = true);
}
