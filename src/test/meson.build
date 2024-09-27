# SPDX-License-Identifier: LGPL-2.1-or-later

libtest = static_library(
        'libtest',
        ['tests.c', 'tests.h'],
        install: false,
        include_directories : includes,
        dependencies : [userspace, threads, librt, libcap])

tests += [
        [
                'src/busctl/test-busctl-introspect.c',
                'src/busctl/busctl-introspect.c',
                'src/busctl/xml.c'
        ],
        ['src/lib/sd-event/test-event.c'],
        ['src/lib/sd-bus/test-bus-address.c'],
        ['src/lib/sd-bus/test-bus-chat.c'],
        ['src/lib/sd-bus/test-bus-cleanup.c'],
        ['src/lib/sd-bus/test-bus-creds.c'],
        ['src/lib/sd-bus/test-bus-error.c'],
        ['src/lib/sd-bus/test-bus-introspect.c'],
        ['src/lib/sd-bus/test-bus-marshal.c'],
        ['src/lib/sd-bus/test-bus-match.c'],
        ['src/lib/sd-bus/test-bus-objects.c'],
        ['src/lib/sd-bus/test-bus-peersockaddr.c'],
        ['src/lib/sd-bus/test-bus-queue-ref-cycle.c'],
        ['src/lib/sd-bus/test-bus-server.c'],
        ['src/lib/sd-bus/test-bus-signature.c'],
        ['src/lib/sd-bus/test-bus-track.c'],
        ['src/lib/sd-bus/test-bus-vtable.c'],
]
