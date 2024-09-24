sources = files(
        'sd-id128/id128-util.c',
        'sd-id128/sd-id128.c',
        'sd-event/event-util.c',
        'sd-event/sd-event.c',
)

c_args = ['-fvisibility=default']

lib_static = static_library(
        meson.project_name() + '_static',
        sources,
        include_directories : lib_includes,
        c_args : c_args,
        link_with : [libbasic_static],
        dependencies : [threads,
                        librt,
                        userspace],
        build_by_default : false)

lib_dir_path = meson.current_source_dir()

lib_sym = files('symbols.sym')
lib_sym_path = lib_dir_path / 'symbols.sym'

lib_pc = custom_target(
        meson.project_name() + '.pc',
        input : meson.project_name() + '.pc.in',
        output : meson.project_name() + '.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfiglibdir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfiglibdir)
