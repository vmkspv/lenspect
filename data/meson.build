application_id = 'io.github.vmkspv.lenspect'

desktop_file = i18n.merge_file(
  input: 'io.github.vmkspv.lenspect.desktop.in',
  output: 'io.github.vmkspv.lenspect.desktop',
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'applications'
)

searchprovider_desktop_file = i18n.merge_file(
  input: 'io.github.vmkspv.lenspect.SearchProvider.desktop.in',
  output: 'io.github.vmkspv.lenspect.SearchProvider.desktop',
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'applications'
)

desktop_utils = find_program('desktop-file-validate', required: false)
if desktop_utils.found()
  test('Validate main desktop file', desktop_utils, args: [desktop_file])
  test('Validate search provider desktop file', desktop_utils, args: [searchprovider_desktop_file])
endif

appstream_file = i18n.merge_file(
  input: 'io.github.vmkspv.lenspect.metainfo.xml.in',
  output: 'io.github.vmkspv.lenspect.metainfo.xml',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'metainfo'
)

appstreamcli = find_program('appstreamcli', required: false, disabler: true)
test('Validate appstream file', appstreamcli,
     args: ['validate', '--no-net', '--explain', appstream_file])

service_conf = configuration_data()
service_conf.set('appid', application_id)
service_conf.set('name', meson.project_name())
service_conf.set('bindir', join_paths(get_option('prefix'), get_option('bindir')))
configure_file(
  input: '@0@.SearchProvider.service.in'.format(application_id),
  output: '@0@.SearchProvider.service'.format(application_id),
  configuration: service_conf,
  install_dir: get_option('datadir') / 'dbus-1' / 'services'
)

search_conf = configuration_data()
search_conf.set('appid', application_id)
search_conf.set('object_path', '/io/github/vmkspv/lenspect/SearchProvider')
configure_file(
  input: '@0@.search-provider.ini'.format(application_id),
  output: '@0@.search-provider.ini'.format(application_id),
  configuration: search_conf,
  install_dir: get_option('datadir') / 'gnome-shell' / 'search-providers'
)

subdir('icons')