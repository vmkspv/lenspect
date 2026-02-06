# Security policy

> [!IMPORTANT]
> Please test using the CI build of [Flatpak](https://github.com/vmkspv/lenspect/actions/workflows/flatpak.yml) or [AppImage](https://github.com/vmkspv/lenspect/actions/workflows/appimage.yml) before reporting a vulnerability. If the artifact is unavailable, run a manual [build from source](https://github.com/vmkspv/lenspect#building-from-source).

It's quite possible that the fix is already in the repository with changes since the latest release.

## Reporting a vulnerability

> [!WARNING]
> Please don't report security vulnerabilities with full details in public GitHub issues.

If you believe you have found a security issue in Lenspect:

1. Open a draft security advisory via [GitHub Security Advisories](https://github.com/vmkspv/lenspect/security/advisories/new), or
2. Contact me by creating a blank issue and describing that it's a security-sensitive matter.

I'll acknowledge your report and work with you to understand and address it. Fixes are released in normal versioned releases; critical issues may be disclosed after a patch is available.

## What to report

- In scope: the Lenspect codebase (this repository), including how it handles your VirusTotal API key and scan data.
- Out of scope: vulnerabilities in dependencies (see below) or in [VirusTotal](https://www.virustotal.com) itself should be reported to those projects.

## Dependencies & services

Lenspect relies on the following; security issues in them should be reported to the respective upstream projects:

| Dependency / service | Upstream |
|----------------------|----------|
| [GNOME Platform](https://gitlab.gnome.org/GNOME/gnome-build-meta) | [GNOME GitLab](https://gitlab.gnome.org/GNOME/gnome-build-meta/-/issues) |
| [GTK](https://gitlab.gnome.org/GNOME/gtk) | [GNOME GitLab](https://gitlab.gnome.org/GNOME/gtk/-/issues) |
| [Libadwaita](https://gitlab.gnome.org/GNOME/libadwaita) | [GNOME GitLab](https://gitlab.gnome.org/GNOME/libadwaita/-/issues) |
| [libsoup](https://gitlab.gnome.org/GNOME/libsoup) | [GNOME GitLab](https://gitlab.gnome.org/GNOME/libsoup/-/issues) |
| [libsecret](https://gitlab.gnome.org/GNOME/libsecret) | [GNOME GitLab](https://gitlab.gnome.org/GNOME/libsecret/-/issues) |
| [VirusTotal](https://www.virustotal.com) | [Support](https://www.virustotal.com/gui/contact-us/support) / [API docs](https://docs.virustotal.com) |

Use of VirusTotal is subject to their [Terms of Service](https://cloud.google.com/terms) and [Privacy Notice](https://cloud.google.com/terms/secops/privacy-notice).
