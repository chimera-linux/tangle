/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdlib.h>

#include "log.h"
#include "macro.h"
#include "tests.h"

void test_setup_logging(int level) {
}

int log_tests_skipped(const char *message) {
        log_notice("%s: %s, skipping tests.",
                   program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}

int log_tests_skipped_errno(int r, const char *message) {
        log_notice_errno(r, "%s: %s, skipping tests: %m",
                         program_invocation_short_name, message);
        return EXIT_TEST_SKIP;
}
