# SPDX-License-Identifier: LGPL-2.1-or-later

# This is lame, I know, but meson has no other include mechanism
subdir('rules')

want_man = get_option('man')
xsltproc = find_program('xsltproc',
                        required : want_man.enabled())
want_man = want_man.allowed() and xsltproc.found()

xsltproc_flags = [
        '--nonet',
        '--xinclude',
        '--maxdepth', '9000',
        '--stringparam', 'man.output.quietly', '1',
        '--stringparam', 'funcsynopsis.style', 'ansi',
        '--stringparam', 'man.authors.section.enabled', '0',
        '--stringparam', 'man.copyright.section.enabled', '0',
        '--stringparam', 'systemd.version', '@0@'.format(meson.project_version()),
        '--path',
        '@0@:@1@'.format(meson.current_build_dir(),
                         meson.current_source_dir())]

custom_man_xsl = files('custom-man.xsl')
xslt_cmd = [xsltproc, '-o', '@OUTPUT0@'] + xsltproc_flags

man_pages = []
source_xml_files = []
dbus_docs = []
foreach tuple : manpages
        stem = tuple[0]
        section = tuple[1]
        aliases = tuple[2]
        condition = tuple[3]

        xml = stem + '.xml'
        man = stem + '.' + section

        manaliases = []
        foreach alias : aliases
                manaliases += alias + '.' + section
        endforeach

        mandirn = get_option('mandir') / ('man' + section)

        file = files(tuple[0] + '.xml')
        source_xml_files += file
        if tuple[0].startswith('org.freedesktop.')
                dbus_docs += file
        endif

        if xsltproc.found()
                p1 = custom_target(
                        man,
                        input : xml,
                        output : [man] + manaliases,
                        command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
                        depends : man_page_depends,
                        install : want_man,
                        install_dir : mandirn)
                man_pages += p1
        endif
endforeach

man = custom_target(
        'man',
        output : 'man',
        depends : man_pages,
        command : [echo])
