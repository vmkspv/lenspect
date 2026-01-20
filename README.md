<p align="center">
  <img src="data/icons/hicolor/scalable/apps/io.github.vmkspv.lenspect.svg" width="128"/>
  <h1 align="center">Lenspect</h1>
  <p align="center"><i>Lenspect</i> is a lightweight security threat scanner powered by <a href="https://www.virustotal.com">VirusTotal</a>.</p>
</p>

<p align="center">
  <a href="https://github.com/vmkspv/lenspect/actions/workflows/flatpak.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/vmkspv/lenspect/flatpak.yml?logo=flatpak&logoColor=e4e4e4&label=flatpak&labelColor=3a484a&color=288c5a"/>
  </a>
  <a href="https://github.com/vmkspv/lenspect/actions/workflows/appimage.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/vmkspv/lenspect/appimage.yml?logo=appimage&logoColor=e4e4e4&label=appimage&labelColor=3a484a&color=288c5a"/>
  </a>
  <a href="https://github.com/vmkspv/lenspect/releases/latest">
    <img src="https://img.shields.io/github/v/release/vmkspv/lenspect?logo=github&logoColor=e4e4e4&labelColor=3a484a&color=288c5a"/>
  </a>
  <a href="https://flathub.org/apps/details/io.github.vmkspv.lenspect">
    <img src="https://img.shields.io/flathub/downloads/io.github.vmkspv.lenspect?logo=flathub&logoColor=e4e4e4&labelColor=3a484a&color=288c5a"/>
  </a>
</p>

<p align="center">
  <img src="data/screenshots/preview.png" width="756" title="Main window"/>
</p>

## Installation

The recommended installation method is via <a href="https://flatpak.org">Flatpak</a>.

<p>
  <a href="https://flathub.org/apps/details/io.github.vmkspv.lenspect">
    <img src="https://flathub.org/api/badge?svg&locale=en" width="180"/>
  </a>
</p>

## Building from source

### GNOME Builder

The recommended method is to use GNOME Builder:

1. Install [`org.gnome.Builder`](https://gitlab.gnome.org/GNOME/gnome-builder) from Flathub.
2. Open Builder and select `Clone Repository`.
3. Clone `https://github.com/vmkspv/lenspect.git`.
4. Press `Run Project` at the top once project is loaded.

### Flatpak

You can also build the actual code as Flatpak:

1. Install [`org.flatpak.Builder`](https://github.com/flatpak/flatpak-builder) from Flathub.
2. Clone `https://github.com/vmkspv/lenspect.git` and `cd lenspect`.
3. Run `flatpak run org.flatpak.Builder --install --user --force-clean build-dir io.github.vmkspv.lenspect.json`.

## Contributing

Contributions are welcome!

If you have an idea, bug report or something else, don’t hesitate to [open an issue](https://github.com/vmkspv/lenspect/issues).

> This project follows the [GNOME Code of Conduct](https://conduct.gnome.org).

## License

Lenspect is released under the [GPL-3.0 license](COPYING).
