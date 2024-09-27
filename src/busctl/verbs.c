/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "process-util.h"
#include "string-util.h"
#include "verbs.h"

const Verb* verbs_find_verb(const char *name, const Verb verbs[]) {
        assert(verbs);

        for (size_t i = 0; verbs[i].dispatch; i++)
                if (name ? streq(name, verbs[i].verb) : FLAGS_SET(verbs[i].flags, VERB_DEFAULT))
                        return verbs + i;

        /* At the end of the list? */
        return NULL;
}

int dispatch_verb(int argc, char *argv[], const Verb verbs[], void *userdata) {
        const Verb *verb;
        const char *name;
        int left;

        assert(verbs);
        assert(verbs[0].dispatch);
        assert(argc >= 0);
        assert(argv);
        assert(argc >= optind);

        left = argc - optind;
        argv += optind;
        optind = 0;
        name = argv[0];

        verb = verbs_find_verb(name, verbs);
        if (!verb) {
                if (name) {
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command verb '%s'.", name);
                }

                _cleanup_free_ char *verb_list = NULL;
                size_t i;

                for (i = 0; verbs[i].dispatch; i++)
                        if (!strextend_with_separator(&verb_list, ", ", verbs[i].verb))
                                abort(); /* oom */

                if (i > 2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Command verb required (one of %s).", verb_list);

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Command verb required.");
        }

        if (!name)
                left = 1;

        if (verb->min_args != VERB_ANY &&
            (unsigned) left < verb->min_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments.");

        if (verb->max_args != VERB_ANY &&
            (unsigned) left > verb->max_args)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many arguments.");

        if (!name)
                return verb->dispatch(1, STRV_MAKE(verb->verb), userdata);

        return verb->dispatch(left, argv, userdata);
}
