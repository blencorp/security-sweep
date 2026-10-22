# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-22

### Added

- `scan`: critical issues (severity critical, CISA KEV, or user-named CVE) in npm, pnpm, Yarn and Composer lockfiles, and PHP/Node.js runtimes declared in Dockerfiles, version files and `config.platform.php`. Distro packages are judged by the distro's tracker via OSV. Manifests without lockfiles and unpinned runtimes make the result INCOMPLETE.
- `plan`: smallest same-major fix per issue, with safety checks (cooldown, malicious package, new install script or Composer plugin, new critical advisory). The footprint is computed in a scratch copy with lockfile-only commands, and each fix gets a prompt.
- `check`: footprint-only scope check against a plan-time snapshot, rescan, test result recording; refuses stale plans and unapproved fixes.
- `revert` and `report`.
- Scoped overrides as the last resort for npm and pnpm transitive fixes.
- Private package patterns (`--private`, `SECURITY_SWEEP_PRIVATE`, `.security-sweep.json`): never sent to public services.
- osv-scanner v2.7.0 pinned by SHA-256 per platform.
- Offline replay test suite with 13 sample projects, including a trap where `npm audit fix --force` breaks the app.

[Unreleased]: https://github.com/blencorp/security-sweep/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/blencorp/security-sweep/releases/tag/v1.0.0
