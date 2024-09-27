/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "bus-common-errors.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "memstream-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "stdio-util.h"

static int name_owner_change_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = ASSERT_PTR(userdata);

        assert(m);

        sd_bus_close(sd_bus_message_get_bus(m));
        sd_event_exit(e, 0);

        return 1;
}

int bus_log_address_error(int r, BusTransport transport) {
        bool hint = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM;

        return log_error_errno(r,
                               hint ? "Failed to set bus address: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                      "Failed to set bus address: %m");
}

int bus_log_connect_error(int r, BusTransport transport) {
        bool hint_vars = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM,
             hint_addr = transport == BUS_TRANSPORT_LOCAL && ERRNO_IS_PRIVILEGE(r);

        return log_error_errno(r,
                               r == hint_vars ? "Failed to connect to bus: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                               r == hint_addr ? "Failed to connect to bus: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                                "Failed to connect to bus: %m");
}

int bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name) {
        const char *match;
        const char *unique;
        int r;

        assert(e);
        assert(bus);
        assert(name);

        /* We unregister the name here and then wait for the
         * NameOwnerChanged signal for this event to arrive before we
         * quit. We do this in order to make sure that any queued
         * requests are still processed before we really exit. */

        r = sd_bus_get_unique_name(bus, &unique);
        if (r < 0)
                return r;

        match = strjoina(
                        "sender='org.freedesktop.DBus',"
                        "type='signal',"
                        "interface='org.freedesktop.DBus',"
                        "member='NameOwnerChanged',"
                        "path='/org/freedesktop/DBus',"
                        "arg0='", name, "',",
                        "arg1='", unique, "',",
                        "arg2=''");

        r = sd_bus_add_match_async(bus, NULL, match, name_owner_change_callback, NULL, e);
        if (r < 0)
                return r;

        r = sd_bus_release_name_async(bus, NULL, name, NULL, NULL);
        if (r < 0)
                return r;

        return 0;
}

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *rep = NULL;
        int r, has_owner = 0;

        assert(c);
        assert(name);

        r = sd_bus_call_method(c,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/dbus",
                               "org.freedesktop.DBus",
                               "NameHasOwner",
                               error,
                               &rep,
                               "s",
                               name);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(rep, 'b', &has_owner);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return has_owner;
}

bool bus_error_is_unknown_service(const sd_bus_error *error) {
        return sd_bus_error_has_names(error,
                                      SD_BUS_ERROR_SERVICE_UNKNOWN,
                                      SD_BUS_ERROR_NAME_HAS_NO_OWNER,
                                      BUS_ERROR_NO_SUCH_UNIT);
}

int bus_check_peercred(sd_bus *c) {
        struct ucred ucred;
        int fd, r;

        assert(c);

        fd = sd_bus_get_fd(c);
        if (fd < 0)
                return fd;

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return r;

        if (ucred.uid != 0 && ucred.uid != geteuid())
                return -EPERM;

        return 1;
}

int bus_connect_system_systemd(sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        assert(ret_bus);

        if (geteuid() != 0)
                return sd_bus_default_system(ret_bus);

        /* If we are root then let's talk directly to the system
         * instance, instead of going via the bus */

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        r = sd_bus_set_address(bus, "unix:path=/run/systemd/private");
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return sd_bus_default_system(ret_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

int bus_connect_user_systemd(sd_bus **ret_bus) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *ee = NULL;
        const char *e;
        int r;

        assert(ret_bus);

        e = secure_getenv("XDG_RUNTIME_DIR");
        if (!e)
                return sd_bus_default_user(ret_bus);

        ee = bus_address_escape(e);
        if (!ee)
                return -ENOMEM;

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        bus->address = strjoin("unix:path=", ee, "/systemd/private");
        if (!bus->address)
                return -ENOMEM;

        r = sd_bus_start(bus);
        if (r < 0)
                return sd_bus_default_user(ret_bus);

        r = bus_check_peercred(bus);
        if (r < 0)
                return r;

        *ret_bus = TAKE_PTR(bus);
        return 0;
}

/**
 * bus_path_encode_unique() - encode unique object path
 * @b: bus connection or NULL
 * @prefix: object path prefix
 * @sender_id: unique-name of client, or NULL
 * @external_id: external ID to be chosen by client, or NULL
 * @ret_path: storage for encoded object path pointer
 *
 * Whenever we provide a bus API that allows clients to create and manage
 * server-side objects, we need to provide a unique name for these objects. If
 * we let the server choose the name, we suffer from a race condition: If a
 * client creates an object asynchronously, it cannot destroy that object until
 * it received the method reply. It cannot know the name of the new object,
 * thus, it cannot destroy it. Furthermore, it enforces a round-trip.
 *
 * Therefore, many APIs allow the client to choose the unique name for newly
 * created objects. There're two problems to solve, though:
 *    1) Object names are usually defined via dbus object paths, which are
 *       usually globally namespaced. Therefore, multiple clients must be able
 *       to choose unique object names without interference.
 *    2) If multiple libraries share the same bus connection, they must be
 *       able to choose unique object names without interference.
 * The first problem is solved easily by prefixing a name with the
 * unique-bus-name of a connection. The server side must enforce this and
 * reject any other name. The second problem is solved by providing unique
 * suffixes from within sd-bus.
 *
 * This helper allows clients to create unique object-paths. It uses the
 * template '/prefix/sender_id/external_id' and returns the new path in
 * @ret_path (must be freed by the caller).
 * If @sender_id is NULL, the unique-name of @b is used. If @external_id is
 * NULL, this function allocates a unique suffix via @b (by requesting a new
 * cookie). If both @sender_id and @external_id are given, @b can be passed as
 * NULL.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int bus_path_encode_unique(sd_bus *b, const char *prefix, const char *sender_id, const char *external_id, char **ret_path) {
        _cleanup_free_ char *sender_label = NULL, *external_label = NULL;
        char external_buf[DECIMAL_STR_MAX(uint64_t)], *p;
        int r;

        assert_return(b || (sender_id && external_id), -EINVAL);
        assert_return(sd_bus_object_path_is_valid(prefix), -EINVAL);
        assert_return(ret_path, -EINVAL);

        if (!sender_id) {
                r = sd_bus_get_unique_name(b, &sender_id);
                if (r < 0)
                        return r;
        }

        if (!external_id) {
                xsprintf(external_buf, "%"PRIu64, ++b->cookie);
                external_id = external_buf;
        }

        sender_label = bus_label_escape(sender_id);
        if (!sender_label)
                return -ENOMEM;

        external_label = bus_label_escape(external_id);
        if (!external_label)
                return -ENOMEM;

        p = path_join(prefix, sender_label, external_label);
        if (!p)
                return -ENOMEM;

        *ret_path = p;
        return 0;
}

/**
 * bus_path_decode_unique() - decode unique object path
 * @path: object path to decode
 * @prefix: object path prefix
 * @ret_sender: output parameter for sender-id label
 * @ret_external: output parameter for external-id label
 *
 * This does the reverse of bus_path_encode_unique() (see its description for
 * details). Both trailing labels, sender-id and external-id, are unescaped and
 * returned in the given output parameters (the caller must free them).
 *
 * Note that this function returns 0 if the path does not match the template
 * (see bus_path_encode_unique()), 1 if it matched.
 *
 * Returns: Negative error code on failure, 0 if the given object path does not
 *          match the template (return parameters are set to NULL), 1 if it was
 *          parsed successfully (return parameters contain allocated labels).
 */
int bus_path_decode_unique(const char *path, const char *prefix, char **ret_sender, char **ret_external) {
        const char *p, *q;
        char *sender, *external;

        assert(sd_bus_object_path_is_valid(path));
        assert(sd_bus_object_path_is_valid(prefix));
        assert(ret_sender);
        assert(ret_external);

        p = object_path_startswith(path, prefix);
        if (!p) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        q = strchr(p, '/');
        if (!q) {
                *ret_sender = NULL;
                *ret_external = NULL;
                return 0;
        }

        sender = bus_label_unescape_n(p, q - p);
        external = bus_label_unescape(q + 1);
        if (!sender || !external) {
                free(sender);
                free(external);
                return -ENOMEM;
        }

        *ret_sender = sender;
        *ret_external = external;
        return 1;
}

int bus_track_add_name_many(sd_bus_track *t, char **l) {
        int r = 0;

        assert(t);

        /* Continues adding after failure, and returns the first failure. */

        STRV_FOREACH(i, l)
                RET_GATHER(r, sd_bus_track_add_name(t, *i));
        return r;
}

int bus_open_system_watch_bind_with_description(sd_bus **ret, const char *description) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        const char *e;
        int r;

        assert(ret);

        /* Match like sd_bus_open_system(), but with the "watch_bind" feature and the Connected() signal
         * turned on. */

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        if (description) {
                r = sd_bus_set_description(bus, description);
                if (r < 0)
                        return r;
        }

        e = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");
        if (!e)
                e = DEFAULT_SYSTEM_BUS_ADDRESS;

        r = sd_bus_set_address(bus, e);
        if (r < 0)
                return r;

        r = sd_bus_set_bus_client(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_negotiate_creds(bus, true, SD_BUS_CREDS_UID|SD_BUS_CREDS_EUID|SD_BUS_CREDS_EFFECTIVE_CAPS);
        if (r < 0)
                return r;

        r = sd_bus_set_watch_bind(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_set_connected_signal(bus, true);
        if (r < 0)
                return r;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(bus);

        return 0;
}

static void bus_message_unref_wrapper(void *m) {
        sd_bus_message_unref(m);
}

const struct hash_ops bus_message_hash_ops = {
        .hash = trivial_hash_func,
        .compare = trivial_compare_func,
        .free_value = bus_message_unref_wrapper,
};

int bus_message_append_string_set(sd_bus_message *m, Set *set) {
        const char *s;
        int r;

        assert(m);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        SET_FOREACH(s, set) {
                r = sd_bus_message_append(m, "s", s);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(m);
}

int bus_property_get_string_set(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Set **s = ASSERT_PTR(userdata);

        assert(bus);
        assert(property);
        assert(reply);

        return bus_message_append_string_set(reply, *s);
}

int bus_creds_get_pidref(
                sd_bus_creds *c,
                PidRef *ret) {

        int pidfd = -EBADF;
        pid_t pid;
        int r;

        assert(c);
        assert(ret);

        r = sd_bus_creds_get_pid(c, &pid);
        if (r < 0)
                return r;

        r = sd_bus_creds_get_pidfd_dup(c, &pidfd);
        if (r < 0 && r != -ENODATA)
                return r;

        *ret = (PidRef) {
                .pid = pid,
                .fd = pidfd,
        };

        return 0;
}

int bus_query_sender_pidref(
                sd_bus_message *m,
                PidRef *ret) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        int r;

        assert(m);
        assert(ret);

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD, &creds);
        if (r < 0)
                return r;

        return bus_creds_get_pidref(creds, ret);
}

int bus_message_read_id128(sd_bus_message *m, sd_id128_t *ret) {
        const void *a;
        size_t sz;
        int r;

        assert(m);

        r = sd_bus_message_read_array(m, 'y', &a, &sz);
        if (r < 0)
                return r;

        switch (sz) {
        case 0:
                if (ret)
                        *ret = SD_ID128_NULL;
                return 0;

        case sizeof(sd_id128_t):
                if (ret)
                        memcpy(ret, a, sz);
                return !memeqzero(a, sz); /* This mimics sd_id128_is_null(), but ret may be NULL,
                                           * and a may be misaligned, so use memeqzero() here. */

        default:
                return -EINVAL;
        }
}
