# PHP and Node.js runtimes

## Where the version is declared, and whose data applies

| Declaration | Origin | Data used |
| --- | --- | --- |
| `FROM php:<tag>` / `FROM node:<tag>` (official images) | official-image | php.net ChangeLog / Node.js security-wg + nodejs.org releases. Official images build from upstream source. |
| `.php-version`, `.nvmrc`, `.node-version` | version-file | Upstream, as above |
| `composer.json` `config.platform.php` | platform-config | Upstream, as above. This only tells Composer which PHP to resolve for, so upgrade the real runtime too. |
| `apt-get install php8.2-cli=<ver>` / `nodejs=<ver>` on `debian`/`ubuntu`; `apk add php82=<ver>` on `alpine` | distro | The distro's own security tracker, via OSV (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`) |

Distros backport fixes without changing the upstream version number, and they mark some upstream CVEs as not affecting their build. Upstream data would give wrong answers for a distro package. Example: upstream PHP 8.2.18 is affected by CVE-2024-4577 (on CISA KEV), but the bug only applies to PHP-CGI on Windows, and Debian marks `php8.2` in bookworm as not affected. The scan does not report it for `8.2.18-1~deb12u1`. The fix version for a distro package is the distro's fixed package version (for example `8.2.26-1~deb12u1`), never an upstream number.

## Pinned versus unpinned

Only an exact patch release can be checked: `php:8.2.27-fpm`, `.nvmrc` `22.12.0`, `php8.2-cli=8.2.26-1~deb12u1`. Floating declarations (`php:8.2-fpm`, `node:20-alpine`, `lts/*`, apt packages without `=version`) get whatever was newest when the image was built, so the version in production is unknown. The scan marks them INCOMPLETE and prints the minimum release in that line with no known critical issue. Ask the user what production actually runs, or suggest pinning.

A `FROM` reference that uses a build argument with no default (`FROM php:${PHP_VERSION}`) cannot be resolved and is also INCOMPLETE.

## Choosing the fix

- The target is the smallest release **in the same line** (PHP `8.2.x`, Node `22.x`) that fixes every critical advisory, released at least 7 days ago. A KEV issue may use a younger release with `--approve cooldown`.
- For official images, the new tag keeps the variant suffix (`8.2.27-fpm-bookworm` → `8.2.28-fpm-bookworm`), and the plan confirms that tag exists on Docker Hub.
- The footprint is that one line of that one file. Rebuild and redeploy the image afterwards. `check` verifies the file edit and re-evaluates the new version; it cannot see what is deployed.

## End-of-life lines

PHP lines missing from php.net's list of supported branches, and Node lines past their end date in the Node.js release schedule, no longer get security fixes, and new CVEs are not tracked for them. An end-of-life runtime is listed in the report, and any fix needs approval for a line change ("needs a newer release line"). Moving to a new PHP or Node line is an upgrade with its own compatibility work. This tool does not plan it.

## Sources

| Question | Source |
| --- | --- |
| Which CVEs a PHP release fixes | `https://www.php.net/ChangeLog-<major>.php`: the trailing `(CVE-…)` on each entry. A CVE mentioned inside a description, like "Bypass of CVE-2024-4577", is a reference, not a fix. |
| Supported PHP branches | `https://www.php.net/releases/active.php` |
| Node.js core vulnerabilities, severity, patched ranges | `https://github.com/nodejs/security-wg` `vuln/core/index.json` |
| Node.js releases and dates | `https://nodejs.org/dist/index.json` |
| Node.js end of life | `https://github.com/nodejs/Release` `schedule.json` |
| Distro package status | OSV `DEBIAN-CVE-*`, `UBUNTU-CVE-*`, `ALPINE-CVE-*` records |
| CVE severity for runtimes | OSV's CVE record (CVSS v3 base score) |
| Exploited in the wild | CISA KEV catalog |
| Image tag exists | Docker Hub `library/<image>/tags/<tag>` |
