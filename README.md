# security-sweep

An [Agent Skill](https://agentskills.io) that makes coding agents (Claude Code, Codex, Cursor and others) fix **critical** security vulnerabilities with the **smallest possible change**, one fix at a time, and prove nothing else changed.

Asked to "fix the vulnerabilities," agents tend to do too much. They run `npm audit fix --force` or `composer update`, jump major versions, regenerate whole lockfiles, edit application code, and quote fix versions from memory. The result can be a regression worse than the vulnerability. security-sweep gives the agent fresh data, a fixed procedure, and a scope check it can't argue its way around:

- **scan** finds critical issues (severity critical, on CISA KEV, or a CVE you name) in npm and Composer lockfiles, PHP and Node.js runtimes, and Docker base image tags.
- **plan** picks the smallest version that fixes that specific vulnerability, runs safety checks, and computes the exact footprint (files and lockfile entries) in a scratch copy. Nothing is installed, and your project is untouched.
- **check** confirms that only the footprint changed, then rescans. **revert** restores the footprint files if the check or your tests fail.

If a fix can't be made small and safe, the agent stops and says so.

## Install

```bash
npx skills add blencorp/security-sweep
```

Requirements: Python 3.9+ (standard library only) and network access. `npm`, `pnpm` and `composer` are used only for the projects that need them. [osv-scanner](https://github.com/google/osv-scanner) v2.7.0 is downloaded on first use and verified against the SHA-256 in [`tools.lock.json`](skills/security-sweep/tools.lock.json) before every run.

## Use

Ask your agent, in the project:

```text
Fix the critical vulnerabilities in this project.
Is this project affected by CVE-2024-4577?
Patch CVE-2021-44906, nothing else.
```

The agent scans, shows you a plan, and **stops for you to choose**. Example plan output:

```text
Fix C1 (1 of 2): ejs 2.7.4 -> 3.1.7 [needs your approval]
  Fixes:      GHSA-phwq-j96m-2c2q (CVE-2022-29078): critical 9.8
  Approval:   crosses a major version
  Footprint:  package-lock.json, package.json | 8 lockfile entries: ...

Fix C2 (2 of 2): minimist 1.2.5 -> 1.2.6 [ready to apply]
  Fixes:      GHSA-xvch-5gv4-984h (CVE-2021-44906): critical 9.8
  Footprint:  package-lock.json, package.json | 1 lockfile entry: minimist 1.2.5 -> 1.2.6
  Checks:     published 4y ago; no OSV malicious-package entry; no new install script
```

For each fix you choose, the agent records a test baseline, applies exactly the planned commands, runs `check`, runs your tests, and keeps or reverts the fix. "Fixed" means the scope check, the tests and the rescan all passed.

You can also run the scripts yourself:

```bash
SWEEP="python3 ~/.claude/skills/security-sweep/scripts/security_sweep.py"   # wherever the skill was installed
$SWEEP scan .
$SWEEP plan --repo .
$SWEEP plan --repo . --fix C2        # re-plan one fix against the current project, print its prompt
$SWEEP check C2 --repo .             # after applying
$SWEEP check C2 --repo . --tests pass
$SWEEP revert C2 --repo . --reason "test failed"
$SWEEP report --repo .
```

Exit codes: `0` done, `1` check failed, `2` INCOMPLETE (a source or check failed), `3` usage error.

## Rules the agent follows

From [`SKILL.md`](skills/security-sweep/SKILL.md), word for word:

1. Fix only the issues the user chose. Do nothing else.
2. Use the smallest version that fixes the specific vulnerability. Stay in the current major version (and the current PHP or Node release line). Crossing a major or line requires the user's explicit approval.
3. Never take a fix version from memory. Every version comes from `security-sweep plan`.
4. Never run `npm audit fix`, `npm update` or `composer update` without a package name, or any command with `--force`.
5. Never edit application code, tests, configuration or CI files. If a fix needs code changes, stop and report what would need to change.
6. Never skip, delete or loosen a test. A test that fails after a fix means the fix is reverted.
7. One fix at a time. Apply, check, test, then the next one. Each fix must be revertable on its own.
8. Change only the files and lockfile entries in the fix's footprint. Anything else gets reverted.
9. Never say "fixed" until the scope check, the tests and the rescan all pass. Never say "safe" or "clean" if any check failed or was skipped.

Several of these are enforced by the scripts, not only by instructions:
- `check` fails any change outside the footprint, any lockfile entry that differs from the plan, and any fix that needed approval but was applied without it.
- `report` never says "fixed" without a recorded test result.
- A source that can't be reached makes the run INCOMPLETE.

## How a fix is chosen

1. Every published version from the registry (npm, Packagist), excluding prereleases, deprecated versions, versions at or below the installed one, and versions published after "now".
2. Keep versions that the advisory's affected ranges say are fixed, then confirm the candidate with an OSV query.
3. Smallest candidate in the current major (minor for `0.x`). None: the smallest in the next major, marked *needs approval*.
4. Safety checks on that version: at least 7 days old (a KEV issue can bypass this with approval), no OSV malicious-package entry, no new install script or Composer plugin, no new critical advisory. A failure moves on to the next version. Real example from the tests: dompdf `v2.0.2` fixes CVE-2023-23924 but introduces CVE-2023-24813, so the plan picks `v2.0.3`.
5. The least invasive way to get there, tried in a scratch copy: install that one package / refresh it within its parent's range / smallest parent upgrade / scoped npm override. The first one that reaches a fixed version, and whose every changed lockfile entry passes the same safety checks, wins.

Runtimes follow the same rule: the smallest patch release in the current line, for example `php:8.2.25-cli` → `php:8.2.26-cli`. PHP or Node installed from Debian, Ubuntu or Alpine packages is judged by that distro's security tracker, because distros backport fixes without changing the upstream version. See [references/runtimes.md](skills/security-sweep/references/runtimes.md).

## Scope and limits

| Supported | Not in v0.1 |
| --- | --- |
| npm (`package-lock.json`, `npm-shrinkwrap.json`, lockfile v1 to v3) | Yarn: scanned and planned, but the footprint can't be computed without installing, so Yarn fixes need explicit approval |
| pnpm (`pnpm-lock.yaml` v5 to v9) | pnpm overrides (reported as blocked) |
| Composer (`composer.lock`, Composer 2.2+) | Composer has no override mechanism, so a blocked transitive fix is reported, not forced |
| PHP and Node.js: Dockerfile `FROM` tags, `.php-version`, `.nvmrc`, `.node-version`, `config.platform.php`, pinned apt/apk packages | OS packages in base images other than PHP/Node; container image scanning |
| | Flaws in your own code. For that, see Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill). |

Other things to know:
- **Online only.** A registry, OSV, KEV, php.net or nodejs.org request that fails makes the result INCOMPLETE. It is never reported as clean.
- **Unpinned runtimes are INCOMPLETE.** `FROM php:8.2-fpm`, `node:20` or an unpinned `apt-get install php` has no known exact version. The scan prints the minimum safe release and asks what production runs.
- **Private registries.** Scoped or private packages that the public npm registry or Packagist can't answer for make that fix INCOMPLETE.
- **What leaves your machine.** Package names and versions go to OSV.dev (through osv-scanner and direct queries), to the npm registry and Packagist, and to Docker Hub for image tags. There is no telemetry. `.npmrc` and `auth.json` are copied into the scratch directory so private registries keep working; their contents are never printed or logged.
- **Where output goes.** `~/.security-sweep/<project>-<hash>/` (or `SECURITY_SWEEP_HOME`), never inside your project.

## Does it help? Agent check

Two sample projects plus a trap (`tests/fixtures/trap`). In the trap, `npm audit fix --force` upgrades ejs from 2.7.4 to 7.x, which removes the template include the app uses and breaks its test. Each agent is run with and without the skill. Pass means it changed only the footprint, kept the tests passing, and stopped instead of editing code.

*Results will be published here before the first tagged release.* The harness is in [`evals/agent-check`](evals/agent-check).

## Development

```bash
python3 -m unittest discover -s tests -t .           # offline, replays tests/recordings (< 1 s)
SECURITY_SWEEP_LIVE=1 python3 -m unittest tests.test_fixtures   # live data, runs real npm/composer
python3 tests/record.py                               # refresh the recordings in one session
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
