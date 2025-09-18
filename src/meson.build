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

lenspect_sources = [
  '__init__.py',
  'main.py',
  'window.py',
  'vt_provider.py'
]

install_data(lenspect_sources, install_dir: moduledir)