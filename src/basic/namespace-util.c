/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "namespace-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"

typedef enum NamespaceType {
        NAMESPACE_CGROUP,
        NAMESPACE_IPC,
        NAMESPACE_NET,
        NAMESPACE_MOUNT,
        NAMESPACE_PID,
        NAMESPACE_USER,
        NAMESPACE_UTS,
        NAMESPACE_TIME,
        _NAMESPACE_TYPE_MAX,
        _NAMESPACE_TYPE_INVALID = -EINVAL,
} NamespaceType;

struct namespace_info {
        const char *proc_name;
        const char *proc_path;
        unsigned int clone_flag;
};

static const struct namespace_info namespace_info[] = {
        [NAMESPACE_CGROUP] =  { "cgroup", "ns/cgroup", CLONE_NEWCGROUP,                          },
        [NAMESPACE_IPC]    =  { "ipc",    "ns/ipc",    CLONE_NEWIPC,                             },
        [NAMESPACE_NET]    =  { "net",    "ns/net",    CLONE_NEWNET,                             },
        /* So, the mount namespace flag is called CLONE_NEWNS for historical
         * reasons. Let's expose it here under a more explanatory name: "mnt".
         * This is in-line with how the kernel exposes namespaces in /proc/$PID/ns. */
        [NAMESPACE_MOUNT]  =  { "mnt",    "ns/mnt",    CLONE_NEWNS,                              },
        [NAMESPACE_PID]    =  { "pid",    "ns/pid",    CLONE_NEWPID,                             },
        [NAMESPACE_USER]   =  { "user",   "ns/user",   CLONE_NEWUSER,                            },
        [NAMESPACE_UTS]    =  { "uts",    "ns/uts",    CLONE_NEWUTS,                             },
        [NAMESPACE_TIME]   =  { "time",   "ns/time",   CLONE_NEWTIME,                            },
        { /* Allow callers to iterate over the array without using _NAMESPACE_TYPE_MAX. */       },
};

#define pid_namespace_path(pid, type) procfs_file_alloca(pid, namespace_info[type].proc_path)

int namespace_open(
                pid_t pid,
                int *ret_pidns_fd,
                int *ret_mntns_fd,
                int *ret_netns_fd,
                int *ret_userns_fd,
                int *ret_root_fd) {

        _cleanup_close_ int pidns_fd = -EBADF, mntns_fd = -EBADF, netns_fd = -EBADF,
                userns_fd = -EBADF, root_fd = -EBADF;

        assert(pid >= 0);

        if (ret_pidns_fd) {
                const char *pidns;

                pidns = pid_namespace_path(pid, NAMESPACE_PID);
                pidns_fd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidns_fd < 0)
                        return -errno;
        }

        if (ret_mntns_fd) {
                const char *mntns;

                mntns = pid_namespace_path(pid, NAMESPACE_MOUNT);
                mntns_fd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntns_fd < 0)
                        return -errno;
        }

        if (ret_netns_fd) {
                const char *netns;

                netns = pid_namespace_path(pid, NAMESPACE_NET);
                netns_fd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netns_fd < 0)
                        return -errno;
        }

        if (ret_userns_fd) {
                const char *userns;

                userns = pid_namespace_path(pid, NAMESPACE_USER);
                userns_fd = open(userns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (userns_fd < 0 && errno != ENOENT)
                        return -errno;
        }

        if (ret_root_fd) {
                const char *root;

                root = procfs_file_alloca(pid, "root");
                root_fd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
                if (root_fd < 0)
                        return -errno;
        }

        if (ret_pidns_fd)
                *ret_pidns_fd = TAKE_FD(pidns_fd);

        if (ret_mntns_fd)
                *ret_mntns_fd = TAKE_FD(mntns_fd);

        if (ret_netns_fd)
                *ret_netns_fd = TAKE_FD(netns_fd);

        if (ret_userns_fd)
                *ret_userns_fd = TAKE_FD(userns_fd);

        if (ret_root_fd)
                *ret_root_fd = TAKE_FD(root_fd);

        return 0;
}

int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        int r;

        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could escalate from non-root to root in
                 * your own namespace, so check if namespaces are equal before attempting to enter. */

                r = inode_same_at(userns_fd, "", AT_FDCWD, "/proc/self/ns/user", AT_EMPTY_PATH);
                if (r < 0)
                        return r;
                if (r)
                        userns_fd = -EBADF;
        }

        if (pidns_fd >= 0)
                if (setns(pidns_fd, CLONE_NEWPID) < 0)
                        return -errno;

        if (mntns_fd >= 0)
                if (setns(mntns_fd, CLONE_NEWNS) < 0)
                        return -errno;

        if (netns_fd >= 0)
                if (setns(netns_fd, CLONE_NEWNET) < 0)
                        return -errno;

        if (userns_fd >= 0)
                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;

        if (root_fd >= 0) {
                if (fchdir(root_fd) < 0)
                        return -errno;

                if (chroot(".") < 0)
                        return -errno;
        }

        return fully_set_uid_gid(0, 0, NULL, 0);
}
