project('lenspect',
  version: '1.0.4',
  meson_version: '>= 1.2.0',
  default_options: ['warning_level=2', 'werror=false']
)

i18n = import('i18n')
gnome = import('gnome')

subdir('data')
subdir('src')
subdir('po')

gnome.post_install(
  gtk_update_icon_cache: true,
  update_desktop_database: true
)