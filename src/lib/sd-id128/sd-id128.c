/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "id128-util.h"
#include "io-util.h"
#include "macro.h"
#include "path-util.h"
#include "random-util.h"

_public_ char *sd_id128_to_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_STRING_MAX]) {
        size_t k = 0;

        assert_return(s, NULL);

        for (size_t n = 0; n < sizeof(sd_id128_t); n++) {
                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == SD_ID128_STRING_MAX - 1);
        s[k] = 0;

        return s;
}

_public_ char *sd_id128_to_uuid_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_UUID_STRING_MAX]) {
        size_t k = 0;

        assert_return(s, NULL);

        /* Similar to sd_id128_to_string() but formats the result as UUID instead of plain hex chars */

        for (size_t n = 0; n < sizeof(sd_id128_t); n++) {

                if (IN_SET(n, 4, 6, 8, 10))
                        s[k++] = '-';

                s[k++] = hexchar(id.bytes[n] >> 4);
                s[k++] = hexchar(id.bytes[n] & 0xF);
        }

        assert(k == SD_ID128_UUID_STRING_MAX - 1);
        s[k] = 0;

        return s;
}

_public_ int sd_id128_from_string(const char *s, sd_id128_t *ret) {
        size_t n, i;
        sd_id128_t t;
        bool is_guid = false;

        assert_return(s, -EINVAL);

        for (n = 0, i = 0; n < sizeof(sd_id128_t);) {
                int a, b;

                if (s[i] == '-') {
                        /* Is this a GUID? Then be nice, and skip over
                         * the dashes */

                        if (i == 8)
                                is_guid = true;
                        else if (IN_SET(i, 13, 18, 23)) {
                                if (!is_guid)
                                        return -EINVAL;
                        } else
                                return -EINVAL;

                        i++;
                        continue;
                }

                a = unhexchar(s[i++]);
                if (a < 0)
                        return -EINVAL;

                b = unhexchar(s[i++]);
                if (b < 0)
                        return -EINVAL;

                t.bytes[n++] = (a << 4) | b;
        }

        if (i != (is_guid ? SD_ID128_UUID_STRING_MAX : SD_ID128_STRING_MAX) - 1)
                return -EINVAL;

        if (s[i] != 0)
                return -EINVAL;

        if (ret)
                *ret = t;
        return 0;
}

_public_ int sd_id128_string_equal(const char *s, sd_id128_t id) {
        sd_id128_t parsed;
        int r;

        if (!s)
                return false;

        /* Checks if the specified string matches a valid string representation of the specified 128 bit ID/uuid */

        r = sd_id128_from_string(s, &parsed);
        if (r < 0)
                return r;

        return sd_id128_equal(parsed, id);
}

_public_ int sd_id128_get_machine(sd_id128_t *ret) {
        static _Thread_local sd_id128_t saved_machine_id = {};
        int r;

        if (sd_id128_is_null(saved_machine_id)) {
                r = id128_read("/etc/machine-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, &saved_machine_id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = saved_machine_id;
        return 0;
}

int id128_get_boot(sd_id128_t *ret) {
        assert(ret);

        return id128_read("/proc/sys/kernel/random/boot_id", ID128_FORMAT_UUID | ID128_REFUSE_NULL, ret);
}

_public_ int sd_id128_get_boot(sd_id128_t *ret) {
        static _Thread_local sd_id128_t saved_boot_id = {};
        int r;

        if (sd_id128_is_null(saved_boot_id)) {
                r = id128_get_boot(&saved_boot_id);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = saved_boot_id;
        return 0;
}

_public_ int sd_id128_randomize(sd_id128_t *ret) {
        sd_id128_t t;

        assert_return(ret, -EINVAL);

        random_bytes(&t, sizeof(t));

        /* Turn this into a valid v4 UUID, to be nice. Note that we
         * only guarantee this for newly generated UUIDs, not for
         * pre-existing ones. */

        *ret = id128_make_v4_uuid(t);
        return 0;
}

_public_ int sd_id128_get_app_specific(sd_id128_t base, sd_id128_t app_id, sd_id128_t *ret) {
        assert_cc(sizeof(sd_id128_t) < SHA256_DIGEST_SIZE); /* Check that we don't need to pad with zeros. */
        union {
                uint8_t hmac[SHA256_DIGEST_SIZE];
                sd_id128_t result;
        } buf;

        assert_return(ret, -EINVAL);
        assert_return(!sd_id128_is_null(app_id), -ENXIO);

        hmac_sha256(&base, sizeof(base), &app_id, sizeof(app_id), buf.hmac);

        /* Take only the first half. */
        *ret = id128_make_v4_uuid(buf.result);
        return 0;
}

_public_ int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

_public_ int sd_id128_get_boot_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        assert_return(ret, -EINVAL);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

