# Handheld OS Releases

The public release hub for [droiddeck](https://github.com/droiddeck)'s open-source
handheld OS distributions. Packages are organized by operating system, target
device and version, so this repository can serve multiple handhelds and OS families.

## Downloads

Verified installation packages will be listed under
[Releases](https://github.com/droiddeck/releases/releases), with device-specific
release notes, checksums and installation guidance.

**No installable OS package has been published yet.**

## Current development target

| System | Device | Availability |
| --- | --- | --- |
| LineageOS-based Android 16 / 23.2 | AYN Odin2 Mini | Development; no approved release |

This is a third-party distribution, not an official LineageOS release. An OS
brand name has not been chosen. Only install a package explicitly marked for
your device and supported installation path.

## Update metadata

The Odin2 Mini Android client's public v2 update feed is:

https://raw.githubusercontent.com/droiddeck/releases/main/odin2_mini.json

The feed is currently an empty array, which means no update is available.
Additional devices and OS families will receive their own release metadata.

## Publication

The main-only publication workflow checks an approved package inbox hourly.
Its runner is isolated in a container with a read-only inbox: no private source,
SSH keys, signing keys or Docker control socket are mounted. Fork and pull-request
events do not run publication jobs. Each job uses this repository's short-lived
GitHub token; no account-wide publication token is retained.

Packages must pass payload/hash, pinned whole-file signature, redistribution and
device migration/recovery checks before staging. No approved package is available
yet, so publication runs currently leave the empty feed unchanged.
