application_id = 'io.github.vmkspv.lenspect'

scalable_apps_dir = 'hicolor' / 'scalable' / 'apps'
install_data(
  scalable_apps_dir / ('@0@.svg').format(application_id),
  install_dir: get_option('datadir') / 'icons' / scalable_apps_dir
)

symbolic_apps_dir = 'hicolor' / 'symbolic' / 'apps'
install_data(
  symbolic_apps_dir / ('@0@-symbolic.svg').format(application_id),
  install_dir: get_option('datadir') / 'icons' / symbolic_apps_dir
)

scalable_actions_dir = 'hicolor' / 'scalable' / 'actions'
install_data(
  files(
    scalable_actions_dir / 'copy-hashes-symbolic.svg',
    scalable_actions_dir / 'external-view-symbolic.svg',
    scalable_actions_dir / 'file-mode-symbolic.svg',
    scalable_actions_dir / 'get-api-key-symbolic.svg',
    scalable_actions_dir / 'quota-usage-symbolic.svg',
    scalable_actions_dir / 'url-mode-symbolic.svg',
    scalable_actions_dir / 'wait-for-scan-symbolic.svg'
  ),
  install_dir: get_option('datadir') / 'icons' / scalable_actions_dir
)