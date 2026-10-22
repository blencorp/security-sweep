# security-sweep: build spec (v3)

Oct 22, 2026. Supersedes earlier versions.

> Implementation notes (where v0.1 differs from or extends this spec) are at the end.

## Purpose

When a critical security issue lands, coding agents (Claude Code, Codex, Cursor) fix it by doing too much. They upgrade everything, jump major versions, edit app code, and bundle unrelated changes. That introduces regressions, sometimes worse than the vulnerability.

security-sweep makes the agent behave: fix only the critical security issue, with the smallest possible change, one fix at a time, and prove nothing else broke. If a fix can't be made small and safe, the agent stops and says so.

## Scope

- **In:** critical security vulnerabilities in npm and Composer dependencies, the PHP and Node runtimes, and Docker base image tags.
- **Critical means:** severity critical, or listed in CISA's Known Exploited Vulnerabilities (KEV) catalog, or a CVE the user names. High-severity issues are listed in the report but not fixed unless the user asks.
- **Out:** everything else, including flaws in the team's own code, general upgrades, refactoring, and hardening advice. For code-level audits, the README points to Cloudflare's security-audit skill.

## Hard rules (go in SKILL.md word for word)

1. Fix only the issues the user chose. Do nothing else.
2. Use the smallest version that fixes the specific vulnerability. Stay in the current major version (and the current PHP or Node release line). Crossing a major or line requires the user's explicit approval.
3. Never take a fix version from memory. Every version comes from `security-sweep plan`.
4. Never run `npm audit fix`, `npm update` or `composer update` without a package name, or any command with `--force`.
5. Never edit application code, tests, configuration or CI files. If a fix needs code changes, stop and report what would need to change.
6. Never skip, delete or loosen a test. A test that fails after a fix means the fix is reverted.
7. One fix at a time. Apply, check, test, then the next one. Each fix must be revertable on its own.
8. Change only the files and lockfile entries in the fix's footprint. Anything else gets reverted.
9. Never say "fixed" until the scope check, the tests and the rescan all pass. Never say "safe" or "clean" if any check failed or was skipped.

## Workflow

1. **Find.** `security-sweep scan` lists critical issues: package or runtime, installed version, CVE, KEV status, and where it is (which lockfile, direct or transitive). If a manifest has no lockfile, report it as "not checked," never as clean.
2. **Plan.** `security-sweep plan` gives each issue its smallest safe fix and its footprint (the files and lockfile entries that will change). The agent shows the plan and asks which fixes to apply. It changes nothing yet.
3. **Baseline.** Before the first fix, the agent runs the project's tests once and records which tests already fail. Without this, an old failure can't be told apart from a new regression.
4. **Apply one fix.** Run exactly the commands in that fix's plan.
5. **Check.** `security-sweep check <fix>` confirms only the footprint changed. Then run the tests and compare with the baseline. Then rescan for that CVE.
6. **Keep or revert.** All three pass: keep it and move to the next fix. Anything fails: revert that fix, report why, and move on. Never fix forward by editing code.
7. **Report.** For each issue: fixed, reverted (with the reason), needs approval (major or line change), or no safe fix available (with the advisory's workaround).

## The three scripts

Python 3.9+, standard library only. osv-scanner pinned by version and SHA-256.

### `security-sweep scan <repo>`

- Run osv-scanner on every lockfile. Add KEV status from CISA's feed.
- Keep critical issues as defined in Scope; list high ones separately.
- Runtime: read PHP and Node versions from the Dockerfile `FROM` tag, `.nvmrc`, `.php-version`, and `composer.json` `config.platform.php`. Check them against php.net and nodejs.org security releases. If PHP or Node comes from a distro package (Debian, Ubuntu, Alpine), check that distro's security tracker instead, because distros backport fixes without changing the version number.
- Any data source that fails makes the result INCOMPLETE.

### `security-sweep plan <scan-output> [--fix ID]`

For each issue:

1. **Smallest fix.** Get every published version from the registry (npm or Packagist). Keep versions above the installed one, not prereleases, not deprecated. Keep only versions that fix this specific CVE, confirmed with an OSV query. Pick the smallest one in the current major. If there's none, report "needs approval: major upgrade" with the smallest option in the next major.
2. **Safety checks** on the chosen version: published at least 7 days ago (a KEV issue can bypass this with user approval), no OSV malicious-package entry, no new install script compared with the installed version. If it fails, try the next smallest version.
3. **Least invasive way to apply it,** tried in this order:
    - direct dependency: install that one package at that version
    - transitive dependency: refresh only that package within its parent's existing range (`npm update <pkg>`, `composer update <pkg>`)
    - otherwise: the smallest parent upgrade that allows the fix
    - last resort: a scoped override (npm `overrides`, yarn `resolutions`); Composer has none, so report it as blocked
4. **Footprint.** Copy only the manifest and lockfile to a temporary folder and run the chosen command there, with scripts disabled and nothing installed. The diff is the footprint: changed files and every lockfile entry that changes. The user's project is not touched.
5. **Runtime fixes:** the smallest patch release in the current line that fixes the CVE (for example `php:8.2.27` to `php:8.2.28`). The footprint is that one line.

Output per fix: the version change, the CVE it fixes, the footprint, the safety check results, the exact commands, and a note on any other vulnerabilities the new version still has.

### `security-sweep check <fix>`

- Compare the project against the snapshot taken at plan time.
- Pass only if every changed file is in the footprint and every changed lockfile entry matches the footprint's names and versions.
- On failure, print exactly what's outside the footprint so the agent can revert it.

## Repo layout

```text
blencorp/security-sweep/
  SKILL.md            rules, workflow, when to use; under ~100 lines
  references/
    commands.md       exact per-manager commands (npm, yarn, pnpm, Composer)
    runtimes.md       PHP and Node patch lines, distro backports
  scripts/            scan.py, plan.py, check.py, shared helpers
  tools.lock.json     pinned osv-scanner with sha256 per platform
  tests/              script tests against sample projects
  README.md  LICENSE (Apache-2.0)
```

## Testing

**Script tests,** on every commit, no AI involved. Sample projects with known answers:

- a direct dependency with a patch-level fix
- a transitive dependency fixable without touching its parent
- a fix that exists only in the next major (must report "needs approval," not upgrade)
- a fix released 2 days ago (must not be chosen)
- an official `php` image one security release behind
- a Debian PHP already patched by a backport (must not be flagged)
- a manifest with no lockfile (must report "not checked")
- `check` with an extra change planted (a source file edit, an unrelated package bump): must fail and name it

**Agent check,** once before release. Give Claude Code and Codex two of those sample projects plus one trap: a project where `npm audit fix --force` would jump a major version and break a test. Run each with and without the skill. Pass means: with the skill, the agent changes only the footprint, keeps the tests passing, and stops instead of editing code. Put the result in the README.

## Build order

| # | Build | Done when |
| --- | --- | --- |
| 1 | `scan` | Script tests for finding issues and runtimes pass |
| 2 | `plan` | Picks the right smallest version on every sample project; footprints match a hand-checked diff |
| 3 | `check` | Catches every planted extra change |
| 4 | SKILL.md and references | Agent check passes for both agents |
| 5 | Release | README with the agent-check result; tagged release |

---

## Implementation notes (v0.1)

- **Layout.** The skill lives in `skills/security-sweep/` (the layout `npx skills add` discovers), so installing it copies only `SKILL.md`, `references/`, `scripts/` and `tools.lock.json`, not the tests and recordings. The command is `python3 <skill-dir>/scripts/security_sweep.py`.
- **Same commands, byte for byte.** The footprint commands are lockfile-only (`--package-lock-only`, `--lockfile-only`, `--no-install`). The agent runs those same commands, then one install step that cannot change the lockfile (`npm ci`, `pnpm install --frozen-lockfile`, `composer install`).
- **Composer.** `composer update <pkg> --with <pkg>:<ver>` pins the exact minimum version. On Composer 2.9+ `--no-blocking` is needed, because Composer otherwise refuses any version with any remaining advisory. See `references/commands.md`.
- **Safety checks** also run on every lockfile entry a footprint adds or changes, and reject a version that introduces a new critical advisory (dompdf v2.0.2).
- **Sequential fixes.** The agent runs `plan --fix ID` right before each fix. `check` and `revert` refuse a plan made before another fix was kept.
- **Approvals** are recorded with `plan --fix ID --approve major|cooldown|footprint`. `check` fails a fix that needed approval and was applied without it.
- **revert** and **report** commands were added so keep-or-revert and the final report are deterministic.
- **Yarn.** Yarn classic cannot update its lockfile without installing, and Yarn Berry would run the project's vendored Yarn. Yarn fixes are planned, but their footprint is not computed in advance; they need approval, and `check` then allows changes only for the target package. pnpm overrides are not supported yet.
- **Tests** replay recorded responses with an injectable clock (deterministic, offline). A daily live job runs the same tests against live data and runs the real package-manager commands in project copies.
- **Debian fixture.** Debian's php8.2 in bookworm has no true version-preserving backport for a critical CVE, so the fixture uses `8.2.18-1~deb12u1`. Upstream PHP 8.2.18 is affected by CVE-2024-4577 (KEV), but Debian marks the package not affected, and it must not be flagged.
