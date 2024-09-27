# SPDX-License-Identifier: LGPL-2.1-or-later

busctl_sources = files(
        'bus-util.c',
        'format-table.c',
        'json.c',
        'verbs.c',
        'xml.c',
        'busctl-introspect.c',
        'busctl.c',
)

executable('busctl', busctl_sources,
           include_directories : [basic_includes, lib_includes],
           dependencies : [userspace],
           link_with : [lib_static],
           install : true)
