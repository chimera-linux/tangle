# SPDX-License-Identifier: LGPL-2.1-or-later

basic_sources = files(
        'MurmurHash2.c',
        'af-list.c',
        'alloc-util.c',
        'bus-label.c',
        'cap-list.c',
        'capability-util.c',
        'errno-list.c',
        'fd-util.c',
        'fileio.c',
        'fs-util.c',
        'gunicode.c',
        'hash-funcs.c',
        'hashmap.c',
        'hexdecoct.c',
        'hmac.c',
        'hostname-util.c',
        'inotify-util.c',
        'io-util.c',
        'iovec-util.c',
        'log.c',
        'memfd-util.c',
        'memory-util.c',
        'memstream-util.c',
        'namespace-util.c',
        'nulstr-util.c',
        'ordered-set.c',
        'parse-util.c',
        'path-util.c',
        'pidref.c',
        'prioq.c',
        'process-util.c',
        'psi-util.c',
        'random-util.c',
        'ratelimit.c',
        'runtime-scope.c',
        'signal-util.c',
        'siphash24.c',
        'socket-util.c',
        'string-table.c',
        'string-util.c',
        'strv.c',
        'sync-util.c',
        'terminal-util.c',
        'time-util.c',
        'user-util.c',
        'utf8.c',
)

generate_af_list = find_program('generate-af-list.sh')
af_list_txt = custom_target(
        'af-list.txt',
        output : 'af-list.txt',
        command : [generate_af_list, cpp, config_h],
        capture : true)

generate_cap_list = find_program('generate-cap-list.sh')
cap_list_txt = custom_target(
        'cap-list.txt',
        output : 'cap-list.txt',
        command : [generate_cap_list, cpp, config_h],
        capture : true)

generate_errno_list = find_program('generate-errno-list.sh')
errno_list_txt = custom_target(
        'errno-list.txt',
        output : 'errno-list.txt',
        command : [generate_errno_list, cpp],
        capture : true)


generated_gperf_headers = []
foreach item : [['af',     af_list_txt,     'af',         ''],
                ['cap',    cap_list_txt,    'capability', ''],
                ['errno',  errno_list_txt,  'errno',      '']]

        fname = '@0@-from-name.gperf'.format(item[0])
        gperf_file = custom_target(
                fname,
                input : item[1],
                output : fname,
                command : [generate_gperfs, item[2], item[3], '@INPUT@'],
                capture : true)

        fname = '@0@-from-name.h'.format(item[0])
        target1 = custom_target(
                fname,
                input : gperf_file,
                output : fname,
                command : [gperf,
                           '-L', 'ANSI-C', '-t', '--ignore-case',
                           '-N', 'lookup_@0@'.format(item[2]),
                           '-H', 'hash_@0@_name'.format(item[2]),
                           '-p', '-C',
                           '@INPUT@'],
                capture : true)

        fname = '@0@-to-name.h'.format(item[0])
        awkscript = '@0@-to-name.awk'.format(item[0])
        target2 = custom_target(
                fname,
                input : [awkscript, item[1]],
                output : fname,
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target1, target2]
endforeach

basic_sources += generated_gperf_headers

libbasic_static = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        dependencies : [libm,
                        librt,
                        libcap,
                        threads,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
