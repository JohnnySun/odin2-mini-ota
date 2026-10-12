# Handheld OS Releases

The public release hub for [droiddeck](https://github.com/droiddeck)'s open-source
handheld OS distributions. Each release identifies its OS, device, version and
supported installation path.

## Downloads

Download packages, checksums and corresponding source from
[Releases](https://github.com/droiddeck/releases/releases). The first verified
[Android 16 preview](https://github.com/droiddeck/releases/releases/tag/23.2-20261011-preview1-756923b14d2e) is available now.

| System | Device | Availability |
| --- | --- | --- |
| LineageOS-based Android 16 / 23.2 | AYN Odin2 Mini | Development preview |

This is an unofficial third-party distribution. It is not an official
LineageOS release or a hardened production build. An OS brand name has not
been chosen.

## Odin2 Mini installation

The first preview is a full source-only OTA for an **already adapted Odin2
Mini baseline** with same-slot vendor, working Virtual A/B and this
distribution's OTA signing certificate. Factory Android 13 and older cross-slot
development layouts cannot install this package directly. Other Odin models
are not supported by this package.

The package updates system, system_ext, product and vbmeta_system. It does not
include boot/vendor firmware, Google apps or original AYN applications. Those
private components must be obtained separately from an authorized owner.

Use the built-in Updater to check for updates, download and install. Keep power
connected through installation, reboot and snapshot merge. No factory reset
is part of the supported update path. Follow the notes for the exact release
before installing.

## Source

Each release includes a source correspondence archive with the public project
revisions, adaptation patches and build profile used for its package. Original
upstream licenses and notices continue to apply. Device-specific private
inputs and signing keys are not included.

## Update metadata

The Odin2 Mini Android client's public v2 update feed is:

https://raw.githubusercontent.com/droiddeck/releases/main/odin2_mini.json

Additional devices and OS families will use separate feeds. A package enters
the feed after its signatures, contents and supported update/recovery path
have been verified.

## Publication

The main publication workflow checks a reviewed package inbox hourly. Its
container receives only approved assets through a read-only mount and uses
this repository's short-lived GitHub token. Private source, owner components
and signing keys are excluded. The feed advances only after independent
anonymous downloads match the approved hashes.
