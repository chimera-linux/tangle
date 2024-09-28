# SPDX-License-Identifier: LGPL-2.1-or-later

project('tangle', 'c',
        version : '0.1.0',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
                'warning_level=2',
        ],
        meson_version : '>= 0.60.0',
       )

project_major_version = meson.project_version().split('.')[0].split('~')[0]
if meson.project_version().contains('.')
        project_minor_version = meson.project_version().split('.')[-1].split('~')[0]
else
        project_minor_version = '0'
endif

conf = configuration_data()
conf.set_quoted('PROJECT_URL', 'https://chimera-linux.org')
conf.set('PROJECT_VERSION', project_major_version)
conf.set_quoted('PROJECT_VERSION_FULL', meson.project_version())

prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif

libdir = prefixdir / get_option('libdir')
includedir = prefixdir / get_option('includedir')
pkgconfiglibdir = get_option('pkgconfiglibdir') != '' ? get_option('pkgconfiglibdir') : libdir / 'pkgconfig'

conf.set_quoted('INCLUDE_DIR', includedir)
conf.set_quoted('LIBDIR', libdir)
conf.set_quoted('PREFIX', prefixdir)

#####################################################################

cc = meson.get_compiler('c')
userspace_c_args = []
userspace_c_ld_args = []

# Those generate many false positives, and we do not want to change the code to
# avoid them.
basic_disabled_warnings = [
        '-Wno-missing-field-initializers',
        '-Wno-unused-parameter',
        '-Wno-nonnull-compare',
]

possible_common_cc_flags = [
        '-Warray-bounds',     # clang
        '-Warray-bounds=2',
        '-Wdate-time',
        '-Wendif-labels',
        '-Werror=format=2',
        '-Werror=format-signedness',
        '-Werror=implicit-function-declaration',
        '-Werror=implicit-int',
        '-Werror=incompatible-pointer-types',
        '-Werror=int-conversion',
        '-Werror=missing-declarations',
        '-Werror=missing-prototypes',
        '-Werror=overflow',
        '-Werror=override-init',
        '-Werror=return-type',
        '-Werror=shift-count-overflow',
        '-Werror=shift-overflow=2',
        '-Werror=strict-flex-arrays',
        '-Werror=undef',
        '-Wfloat-equal',
        # gperf prevents us from enabling this because it does not emit fallthrough
        # attribute with clang.
        #'-Wimplicit-fallthrough',
        '-Wimplicit-fallthrough=5',
        '-Winit-self',
        '-Wlogical-op',
        '-Wmissing-include-dirs',
        '-Wmissing-noreturn',
        '-Wnested-externs',
        '-Wold-style-definition',
        '-Wpointer-arith',
        '-Wredundant-decls',
        '-Wshadow',
        '-Wstrict-aliasing=2',
        '-Wstrict-prototypes',
        '-Wsuggest-attribute=noreturn',
        '-Wunterminated-string-initialization',
        '-Wunused-function',
        '-Wwrite-strings',
        '-Wzero-length-bounds',
        '-Wno-gnu-variable-sized-type-not-at-end',

        # negative arguments are correctly detected starting with meson 0.46.
        '-Wno-error=#warnings',  # clang
        '-Wno-string-plus-int',  # clang

        '-fdiagnostics-show-option',
        '-fno-common',
        '-fstack-protector',
        '-fstack-protector-strong',
        '-fstrict-flex-arrays=3',
        '--param=ssp-buffer-size=4',
]

possible_common_link_flags = [
        '-fstack-protector',
]

c_args = get_option('c_args')

# Disable -Wmaybe-uninitialized when compiling with -Os/-O1/-O3/etc. There are
# too many false positives with gcc >= 8. Effectively, we only test with -O0
# and -O2; this should be enough to catch most important cases without too much
# busywork. See https://github.com/systemd/systemd/pull/19226.
if cc.get_id() == 'gcc' and (not '02'.contains(get_option('optimization')) or
                             cc.version().version_compare('<10') or
                             '-Os' in c_args or
                             '-O1' in c_args or
                             '-O3' in c_args or
                             '-Og' in c_args)
        possible_common_cc_flags += '-Wno-maybe-uninitialized'
endif

# Disable -Wno-unused-result with gcc, see
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425.
if cc.get_id() == 'gcc'
        possible_common_cc_flags += '-Wno-unused-result'
endif

possible_link_flags = [
        '-Wl,--fatal-warnings',
        '-Wl,-z,now',
        '-Wl,-z,relro',
]

possible_cc_flags = [
        '-fno-strict-aliasing',
        '-fstrict-flex-arrays=1',
        '-fvisibility=hidden',
]

add_project_arguments(
        cc.get_supported_arguments(
                basic_disabled_warnings,
                possible_common_cc_flags
        ),
        language : 'c')

add_project_link_arguments(
        cc.get_supported_link_arguments(possible_common_link_flags),
        language : 'c')

userspace_c_args += cc.get_supported_arguments(possible_cc_flags)
userspace_c_ld_args += cc.get_supported_link_arguments(possible_link_flags)

have = cc.has_argument('-Wzero-length-bounds')
conf.set10('HAVE_ZERO_LENGTH_BOUNDS', have)

if cc.compiles('''
   #include <time.h>
   #include <inttypes.h>
   typedef uint64_t usec_t;
   usec_t now(clockid_t clock);
   int main(void) {
           struct timespec now;
           return 0;
   }
''', args: '-Werror=shadow', name : '-Werror=shadow with local shadowing')
        add_project_arguments('-Werror=shadow', language : 'c')
endif

cpp = ' '.join(cc.cmd_array() + get_option('c_args')) + ' -E'

has_wstringop_truncation = cc.has_argument('-Wstringop-truncation')

conf.set('_GNU_SOURCE', 1)
conf.set10('HAVE_WSTRINGOP_TRUNCATION', has_wstringop_truncation)

conf.set('SIZEOF_PID_T', cc.sizeof('pid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_UID_T', cc.sizeof('uid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_GID_T', cc.sizeof('gid_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_DEV_T', cc.sizeof('dev_t', prefix : '#include <sys/types.h>'))
conf.set('SIZEOF_TIME_T', cc.sizeof('time_t', prefix : '#include <sys/time.h>'))

foreach ident : ['secure_getenv', '__secure_getenv']
        conf.set10('HAVE_' + ident.to_upper(), cc.has_function(ident))
endforeach

foreach ident : [
        ['gettid',            '''#include <sys/types.h>
                                 #include <unistd.h>'''],
        ['explicit_bzero' ,   '''#include <string.h>'''],
        ['reallocarray',      '''#include <stdlib.h>'''],
        ['pidfd_send_signal', '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>
                                 #include <sys/pidfd.h>'''],
        ['pidfd_open',        '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>
                                 #include <sys/pidfd.h>'''],
        ['rt_sigqueueinfo',   '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['rt_tgsigqueueinfo', '''#include <stdlib.h>
                                 #include <unistd.h>
                                 #include <signal.h>
                                 #include <sys/wait.h>'''],
        ['close_range',       '''#include <unistd.h>'''],
        ['epoll_pwait2',      '''#include <sys/epoll.h>'''],
        ['pidfd_spawn',       '''#include <spawn.h>'''],
]

        have = cc.has_function(ident[0], prefix : ident[1], args : '-D_GNU_SOURCE')
        conf.set10('HAVE_' + ident[0].to_upper(), have)
endforeach

if cc.has_function('getrandom', prefix : '''#include <sys/random.h>''', args : '-D_GNU_SOURCE')
        conf.set10('USE_SYS_RANDOM_H', true)
        conf.set10('HAVE_GETRANDOM', true)
else
        have = cc.has_function('getrandom', prefix : '''#include <linux/random.h>''')
        conf.set10('USE_SYS_RANDOM_H', false)
        conf.set10('HAVE_GETRANDOM', have)
endif

foreach header : [
                  'sys/auxv.h',
                 ]

        conf.set10('HAVE_' + header.underscorify().to_upper(),
                   cc.has_header(header))
endforeach

enable_debug_hashmap = false
enable_debug_siphash = false
foreach name : get_option('debug-extra')
        if name == 'hashmap'
                enable_debug_hashmap = true
        elif name == 'siphash'
                enable_debug_siphash = true
        else
                message('unknown debug option "@0@", ignoring'.format(name))
        endif
endforeach
conf.set10('ENABLE_DEBUG_HASHMAP', enable_debug_hashmap)
conf.set10('ENABLE_DEBUG_SIPHASH', enable_debug_siphash)

libcap = dependency('libcap')
threads = dependency('threads')
librt = cc.find_library('rt')
libm = cc.find_library('m')

gperf = find_program('gperf')
awk = find_program('awk')
sh = find_program('sh')
echo = find_program('echo')

gperf_test_format = '''
#include <string.h>
const char * in_word_set(const char *, @0@);
@1@
'''
gperf_snippet = run_command(sh, '-c', 'echo foo,bar | "$1" -L ANSI-C', '_', gperf,
                            check : true)
gperf_test = gperf_test_format.format('size_t', gperf_snippet.stdout())
if cc.compiles(gperf_test)
        gperf_len_type = 'size_t'
else
        gperf_test = gperf_test_format.format('unsigned', gperf_snippet.stdout())
        if cc.compiles(gperf_test)
                gperf_len_type = 'unsigned'
        else
                error('unable to determine gperf len type')
        endif
endif
message('gperf len type is @0@'.format(gperf_len_type))
conf.set('GPERF_LEN_TYPE', gperf_len_type,
         description : 'The type of gperf "len" parameter')

generate_gperfs = find_program('tools/generate-gperfs.py')

tests = []

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

meson_render_jinja2 = find_program('tools/meson-render-jinja2.py')
jinja2_cmdline = [meson_render_jinja2, config_h]

userspace_c_args += ['-include', 'config.h']

userspace = declare_dependency(
        compile_args : userspace_c_args,
        link_args : userspace_c_ld_args,
)

man_page_depends = []

basic_includes = include_directories(
        'src/basic',
        'src/fundamental',
        'src/include',
        '.')

lib_includes = [basic_includes, include_directories(
        'src/lib/sd-bus',
        'src/lib/sd-event',
        'src/lib/sd-id128',
        'src/test')]

includes = [lib_includes]

subdir('man')
subdir('src/fundamental')
subdir('src/basic')
subdir('src/lib')
subdir('src/busctl')
subdir('src/test')

install_headers(
        'src/include/_sd-common.h',
        'src/include/sd-bus.h',
        'src/include/sd-bus-protocol.h',
        'src/include/sd-bus-vtable.h',
        'src/include/sd-event.h',
        'src/include/sd-id128.h',
        subdir: meson.project_name(),
)

lib = shared_library(
        meson.project_name(),
        version : '0',
        include_directories : lib_includes,
        link_args : ['-shared',
                     # Make sure our library is never deleted from memory, so that our open logging fds don't leak on dlopen/dlclose cycles.
                     '-z', 'nodelete',
                     '-Wl,--version-script=' + lib_sym_path],
        link_whole : [lib_static],
        link_depends : lib_sym,
        install : true,
        install_dir : libdir)

foreach sources : tests
        timeout = 30

        name = sources[0].split('/')[-1].split('.')[0]

        exe = executable(
                name,
                sources,
                include_directories : lib_includes,
                link_with : [libtest, lib_static],
                dependencies : [userspace],
                install : false)
        test(name, exe, timeout : timeout)
endforeach
