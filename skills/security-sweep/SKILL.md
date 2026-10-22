---
name: security-sweep
description: Fix critical security vulnerabilities in npm and Composer dependencies, PHP and Node.js runtimes, and Docker base image tags with the smallest possible change, one fix at a time, proving nothing else changed. Use when asked to fix vulnerabilities, CVEs, security advisories, npm audit or composer audit findings, a CISA KEV issue, or a vulnerable package, PHP or Node version. Not for auditing the team's own code.
---

# security-sweep

Fix only the critical security issue, with the smallest possible change, one fix at a time, and prove nothing else broke. If a fix can't be made small and safe, stop and say so.

**Critical** means severity critical, or listed in CISA's Known Exploited Vulnerabilities (KEV) catalog, or a CVE the user names. High-severity issues are listed but not fixed unless the user asks. Flaws in the team's own code, general upgrades, refactoring and hardening are out of scope.

## Hard rules

1. Fix only the issues the user chose. Do nothing else.
2. Use the smallest version that fixes the specific vulnerability. Stay in the current major version (and the current PHP or Node release line). Crossing a major or line requires the user's explicit approval.
3. Never take a fix version from memory. Every version comes from `security-sweep plan`.
4. Never run `npm audit fix`, `npm update` or `composer update` without a package name, or any command with `--force`.
5. Never edit application code, tests, configuration or CI files. If a fix needs code changes, stop and report what would need to change.
6. Never skip, delete or loosen a test. A test that fails after a fix means the fix is reverted.
7. One fix at a time. Apply, check, test, then the next one. Each fix must be revertable on its own.
8. Change only the files and lockfile entries in the fix's footprint. Anything else gets reverted.
9. Never say "fixed" until the scope check, the tests and the rescan all pass. Never say "safe" or "clean" if any check failed or was skipped.

## Modes

- **Question** ("is lodash 4.17.20 vulnerable?", "what fixes CVE-X?"): run `scan` (and `plan` if useful) and answer from their output. Change nothing.
- **Fix** ("fix the vulnerabilities", "patch CVE-X"): follow the workflow below.

## Setup

`SWEEP` below means `python3 <skill-dir>/scripts/security_sweep.py`, where `<skill-dir>` is the directory containing this file. Python 3.9+ and network access are required. Use the same absolute project path as `--repo` every time. Output goes to `~/.security-sweep/`, never into the project.

## Workflow

1. **Find.** `SWEEP scan <repo>` (add `--cve CVE-ID` for each CVE the user names). Show the status line and the critical issues. Exit code 2 means INCOMPLETE: report what was not checked, by name.
2. **Plan.** `SWEEP plan --repo <repo>`. Show each fix: version change, CVE, footprint, checks, and status. Call out KEV issues and anything marked *needs your approval*. Then **stop and ask which fixes to apply.** Change nothing yet.
3. **Baseline.** Before the first fix, run the project's tests once (`npm test`, `composer test`, `vendor/bin/phpunit`, whatever the project uses) and write down which tests already fail. If dependencies are not installed, install them first with `npm ci` / `pnpm install --frozen-lockfile` / `composer install`, which do not change the lockfile. No test command: say so; never invent one.
4. **For each chosen fix, in order:**
   1. `SWEEP plan --repo <repo> --fix <ID>`, always, right before applying. It re-plans against the project as it is now (earlier fixes change the lockfile) and prints the prompt. Add `--approve major`, `--approve cooldown` or `--approve footprint` only if the user explicitly approved that for this fix.
   2. Run exactly the commands in the printed prompt, or make exactly the one-line edit it gives. Nothing else.
   3. `SWEEP check <ID> --repo <repo>`. It confirms only the footprint changed and rescans for the CVE.
   4. Run the tests and compare with the baseline. Any new failure is a failure.
   5. Record the result: `SWEEP check <ID> --repo <repo> --tests pass` (no new failures), `fail`, or `none` (no tests exist).
   6. **Keep or revert.** If the check or the tests fail: `SWEEP revert <ID> --repo <repo> --reason "<why>"`, run the reinstall command it prints, undo any change it lists as outside the footprint, report why, and move on. Never fix forward by editing code.
5. **Report.** `SWEEP report --repo <repo>` and relay it: for each issue fixed, reverted (with the reason), needs approval, or no safe fix (with the advisory's workaround).

## Reading the output

| Plan status | Meaning | What to do |
| --- | --- | --- |
| ready to apply | Smallest safe fix found, footprint computed | Apply if the user chose it |
| needs your approval | Crosses a major/line, or (KEV only) uses a version younger than the 7-day cooldown | Ask; apply only after explicit approval and `plan --fix ID --approve ...` |
| no safe fix available | No version fixes it yet, or every fix failed a safety check | Report it with the workaround; do not improvise a version |
| blocked | No approach reached the fix within the rules (Composer has no override) | Report what the plan says would need to change |
| already resolved | An earlier fix already removed the vulnerable version | Nothing to apply |
| INCOMPLETE | A data source or tool failed | Report the failure; never call the result clean |

`check` statuses: `fixed` requires scope, rescan and `--tests pass`. `awaiting_tests` means record the test result next. `applied_untested` means it passed but the project has no tests; say so. `out_of_scope`, `applied_without_approval` and `tests_failed` mean revert.

Common INCOMPLETE causes are not bugs:
- A manifest with no lockfile is "not checked".
- An unpinned runtime (`FROM php:8.2-fpm`, `node:20`, `.nvmrc` with `20`, apt packages without `=version`) has no known exact version. Report the minimum safe version the scan prints and ask what production runs.
- Yarn projects get a fix version but no footprint computed in advance, so they are marked *needs your approval*. With approval, `check` allows lockfile changes only for the target package.

Check statuses, the exact commands each package manager gets, and why some flags look unusual: [references/commands.md](references/commands.md). Runtime origins, distro backports and end-of-life lines: [references/runtimes.md](references/runtimes.md).
