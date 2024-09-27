/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmp.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "user-util.h"
#include "utf8.h"

bool uid_is_valid(uid_t uid) {

        /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.436. */

        /* Some libc APIs use UID_INVALID as special placeholder */
        if (uid == (uid_t) UINT32_C(0xFFFFFFFF))
                return false;

        /* A long time ago UIDs where 16 bit, hence explicitly avoid the 16-bit -1 too */
        if (uid == (uid_t) UINT32_C(0xFFFF))
                return false;

        return true;
}

int maybe_setgroups(size_t size, const gid_t *list) {
        int r;

        /* Check if setgroups is allowed before we try to drop all the auxiliary groups */
        if (size == 0) { /* Dropping all aux groups? */
                _cleanup_free_ char *setgroups_content = NULL;
                bool can_setgroups;

                r = read_one_line_file("/proc/self/setgroups", &setgroups_content);
                if (r == -ENOENT)
                        /* Old kernels don't have /proc/self/setgroups, so assume we can use setgroups */
                        can_setgroups = true;
                else if (r < 0)
                        return r;
                else
                        can_setgroups = streq(setgroups_content, "allow");

                if (!can_setgroups) {
                        log_debug("Skipping setgroups(), /proc/self/setgroups is set to 'deny'");
                        return 0;
                }
        }

        return RET_NERRNO(setgroups(size, list));
}

int fully_set_uid_gid(uid_t uid, gid_t gid, const gid_t supplementary_gids[], size_t n_supplementary_gids) {
        int r;

        assert(supplementary_gids || n_supplementary_gids == 0);

        /* Sets all UIDs and all GIDs to the specified ones. Drops all auxiliary GIDs */

        r = maybe_setgroups(n_supplementary_gids, supplementary_gids);
        if (r < 0)
                return r;

        if (gid_is_valid(gid))
                if (setresgid(gid, gid, gid) < 0)
                        return -errno;

        if (uid_is_valid(uid))
                if (setresuid(uid, uid, uid) < 0)
                        return -errno;

        return 0;
}

bool valid_user_group_name(const char *u, ValidUserFlags flags) {
        const char *i;

        /* Checks if the specified name is a valid user/group name. There are two flavours of this call:
         * strict mode is the default which is POSIX plus some extra rules; and relaxed mode where we accept
         * pretty much everything except the really worst offending names.
         *
         * Whenever we synthesize users ourselves we should use the strict mode. But when we process users
         * created by other stuff, let's be more liberal. */

        if (isempty(u)) /* An empty user name is never valid */
                return false;

        if (parse_uid(u, NULL) >= 0) /* Something that parses as numeric UID string is valid exactly when the
                                      * flag for it is set */
                return FLAGS_SET(flags, VALID_USER_ALLOW_NUMERIC);

        if (FLAGS_SET(flags, VALID_USER_RELAX)) {

                /* In relaxed mode we just check very superficially. Apparently SSSD and other stuff is
                 * extremely liberal (way too liberal if you ask me, even inserting "@" in user names, which
                 * is bound to cause problems for example when used with an MTA), hence only filter the most
                 * obvious cases, or where things would result in an invalid entry if such a user name would
                 * show up in /etc/passwd (or equivalent getent output).
                 *
                 * Note that we stepped far out of POSIX territory here. It's not our fault though, but
                 * SSSD's, Samba's and everybody else who ignored POSIX on this. (I mean, I am happy to step
                 * outside of POSIX' bounds any day, but I must say in this case I probably wouldn't
                 * have...) */

                if (startswith(u, " ") || endswith(u, " ")) /* At least expect whitespace padding is removed
                                                             * at front and back (accept in the middle, since
                                                             * that's apparently a thing on Windows). Note
                                                             * that this also blocks usernames consisting of
                                                             * whitespace only. */
                        return false;

                if (!utf8_is_valid(u)) /* We want to synthesize JSON from this, hence insist on UTF-8 */
                        return false;

                if (string_has_cc(u, NULL)) /* CC characters are just dangerous (and \n in particular is the
                                             * record separator in /etc/passwd), so we can't allow that. */
                        return false;

                if (strpbrk(u, ":/")) /* Colons are the field separator in /etc/passwd, we can't allow
                                       * that. Slashes are special to file systems paths and user names
                                       * typically show up in the file system as home directories, hence
                                       * don't allow slashes. */
                        return false;

                if (in_charset(u, "0123456789")) /* Don't allow fully numeric strings, they might be confused
                                                  * with UIDs (note that this test is more broad than
                                                  * the parse_uid() test above, as it will cover more than
                                                  * the 32-bit range, and it will detect 65535 (which is in
                                                  * invalid UID, even though in the unsigned 32 bit range) */
                        return false;

                if (u[0] == '-' && in_charset(u + 1, "0123456789")) /* Don't allow negative fully numeric
                                                                     * strings either. After all some people
                                                                     * write 65535 as -1 (even though that's
                                                                     * not even true on 32-bit uid_t
                                                                     * anyway) */
                        return false;

                if (dot_or_dot_dot(u)) /* User names typically become home directory names, and these two are
                                        * special in that context, don't allow that. */
                        return false;

                /* Note that we make no restrictions on the length in relaxed mode! */
        } else {
                long sz;
                size_t l;

                /* Also see POSIX IEEE Std 1003.1-2008, 2016 Edition, 3.437. We are a bit stricter here
                 * however. Specifically we deviate from POSIX rules:
                 *
                 * - We don't allow empty user names (see above)
                 * - We require that names fit into the appropriate utmp field
                 * - We don't allow any dots (this conflicts with chown syntax which permits dots as user/group name separator)
                 * - We don't allow dashes or digit as the first character
                 *
                 * Note that other systems are even more restrictive, and don't permit underscores or uppercase characters.
                 */

                if (!ascii_isalpha(u[0]) &&
                    u[0] != '_')
                        return false;

                for (i = u+1; *i; i++)
                        if (!ascii_isalpha(*i) &&
                            !ascii_isdigit(*i) &&
                            !IN_SET(*i, '_', '-'))
                                return false;

                l = i - u;

                sz = sysconf(_SC_LOGIN_NAME_MAX);
                assert_se(sz > 0);

                if (l > (size_t) sz) /* glibc: 256 */
                        return false;
                if (l > NAME_MAX) /* must fit in a filename: 255 */
                        return false;
                if (l > UT_NAMESIZE - 1) /* must fit in utmp: 31 */
                        return false;
        }

        return true;
}

static size_t getpw_buffer_size(void) {
        long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        return bufsize <= 0 ? 4096U : (size_t) bufsize;
}

static bool errno_is_user_doesnt_exist(int error) {
        /* See getpwnam(3) and getgrnam(3): those codes and others can be returned if the user or group are
         * not found. */
        return IN_SET(abs(error), ENOENT, ESRCH, EBADF, EPERM);
}

static int getpwuid_malloc(uid_t uid, struct passwd **ret) {
        size_t bufsize = getpw_buffer_size();
        int r;

        if (!uid_is_valid(uid))
                return -EINVAL;

        for (;;) {
                _cleanup_free_ void *buf = NULL;

                buf = malloc(ALIGN(sizeof(struct passwd)) + bufsize);
                if (!buf)
                        return -ENOMEM;

                struct passwd *pw = NULL;
                r = getpwuid_r(uid, buf, (char*) buf + ALIGN(sizeof(struct passwd)), (size_t) bufsize, &pw);
                if (r == 0) {
                        if (pw) {
                                if (ret)
                                        *ret = TAKE_PTR(buf);
                                return 0;
                        }

                        return -ESRCH;
                }

                assert(r > 0);

                if (errno_is_user_doesnt_exist(r))
                        return -ESRCH;
                if (r != ERANGE)
                        return -r;

                if (bufsize > SIZE_MAX/2 - ALIGN(sizeof(struct passwd)))
                        return -ENOMEM;
                bufsize *= 2;
        }
}


char* uid_to_name(uid_t uid) {
        char *ret;
        int r;

        /* Shortcut things to avoid NSS lookups */
        if (uid == 0)
                return strdup("root");

        if (uid_is_valid(uid)) {
                _cleanup_free_ struct passwd *pw = NULL;

                r = getpwuid_malloc(uid, &pw);
                if (r >= 0)
                        return strdup(pw->pw_name);
        }

        if (asprintf(&ret, "%u", (unsigned int)uid) < 0)
                return NULL;

        return ret;
}

char* getusername_malloc(void) {
        const char *e;

        e = secure_getenv("USER");
        if (e)
                return strdup(e);

        return uid_to_name(getuid());
}
