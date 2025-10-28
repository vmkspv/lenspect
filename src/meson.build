pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()
moduledir = pkgdatadir / 'lenspect'
gnome = import('gnome')

blueprint = custom_target('blueprint',
  input: 'window.blp',
  output: 'window.ui',
  command: [
    find_program('blueprint-compiler', required: true),
    'compile', '--output', '@OUTPUT@', '@INPUT@'
  ]
)

gnome.compile_resources('lenspect',
  'lenspect.gresource.xml',
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
  dependencies: blueprint
)

python = import('python')

conf = configuration_data()
conf.set('PYTHON', python.find_installation('python3').full_path())
conf.set('VERSION', meson.project_version())
conf.set('localedir', get_option('prefix') / get_option('localedir'))
conf.set('pkgdatadir', pkgdatadir)

configure_file(
  input: 'lenspect.in',
  output: 'lenspect',
  configuration: conf,
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'r-xr-xr-x'
)

configure_file(
  input: 'lenspect_search_provider.in',
  output: 'lenspect_search_provider',
  configuration: conf,
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'r-xr-xr-x'
)

lenspect_sources = [
  '__init__.py',
  'main.py',
  'vt_provider.py',
  'window.py'
]

core_sources = [
  'core/__init__.py',
  'core/config_manager.py',
  'core/report_composer.py',
  'core/toast_manager.py'
]

ui_sources = [
  'ui/__init__.py',
  'ui/dialog_manager.py',
  'ui/file_drop_handler.py',
  'ui/history_dialog.py',
  'ui/results_display.py'
]

install_data(lenspect_sources, install_dir: moduledir)
install_data(core_sources, install_dir: moduledir / 'core')
install_data(ui_sources, install_dir: moduledir / 'ui')