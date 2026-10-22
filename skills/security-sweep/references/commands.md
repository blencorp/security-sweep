# Commands per package manager

`plan` computes every fix by running these commands in a scratch copy holding only the manifest, the lockfile and the package manager's config (`.npmrc`, `pnpm-workspace.yaml`, `auth.json`). They are lockfile-only: nothing is installed and no package code runs. The prompt tells you to run **the same commands** in the project, followed by one install step that must not change the lockfile. Do not drop or "clean up" any flag. The check expects the exact result the flags produce.

## Approaches, smallest first

| Situation | npm | pnpm | Composer |
| --- | --- | --- | --- |
| Direct dependency | `npm install <pkg>@<ver> <save flags> --package-lock-only --ignore-scripts --no-audit --no-fund` | `pnpm add <pkg>@<ver> [--save-exact] --lockfile-only --ignore-scripts --ignore-pnpmfile` | `composer update <pkg> --with <pkg>:<ver> <flags>`; first `composer require <pkg>:<constraint> --no-update` only if the current constraint does not allow `<ver>` |
| Transitive, parent's range allows the fix | `npm update <pkg> --package-lock-only ...` | `pnpm update <pkg> --depth Infinity --lockfile-only ...` | `composer update <pkg> --with <pkg>:<ver> <flags>` |
| Transitive, parent's range blocks it | Smallest same-major parent version whose range allows the fix (direct parents only) | same | `composer update <parent> <pkg> --with <parent>:<pver> --with <pkg>:<ver> <flags>` |
| Last resort | Scoped override: `npm pkg set 'overrides[<parent>][<pkg>]=<ver>'`, then `npm install --package-lock-only ...` | Scoped override `'<parent>><pkg>': '<ver>'` written into `pnpm-workspace.yaml` (pnpm 10+) or `package.json` `pnpm.overrides` (older), then `pnpm install --lockfile-only ...` | Composer has no override: reported as blocked |
| Install step afterwards | `npm ci` | `pnpm install --frozen-lockfile` | `composer install` |

npm save flags keep the project's style: an exact pin stays exact (`--save-exact`), `~` stays `~` (`--save-prefix=~`), anything else gets `^` (`--save-prefix=^`). `--save-dev` / `--save-optional` keep the dependency in its section. pnpm decides the saved range itself. pnpm 10 keeps an existing `~` or `^`, and pnpm 12 saves the exact version. Neither widens the range, and the footprint shows the exact `package.json` change before you apply it.

`npm update <pkg>` (and `pnpm update <pkg>`) resolves to the newest version inside the existing ranges, which may be above the minimum fix. The plan reports the version that actually lands, and runs the safety checks on it and on every other entry the change adds or moves.

## Composer flags that look like loosening, and why they are there

`<flags>` is `--no-install --no-scripts --no-plugins --no-interaction --no-audit --ignore-platform-req=ext-*`, plus `--no-blocking` on Composer 2.9 and newer.

- `--with <pkg>:<ver>` pins the exact minimum version. Without it, `composer update <pkg>` jumps to the newest allowed version.
- `--no-blocking` (Composer 2.9+). Composer refuses to resolve to any version that still has *any* advisory, even a low one. The minimum fix for a critical issue often still has lesser advisories; the plan lists them under "Also left". The flag applies only to the packages named in that one command (there is no `-W`), and the plan has already run its own checks (OSV, age, malicious-package, new-plugin) on the exact version.
- `--ignore-platform-req=ext-*`. The machine computing the lockfile is not production and may lack a PHP extension production has. PHP version requirements are still enforced (set `config.platform.php` in `composer.json` to pin them), and `composer install` enforces extensions when it actually installs.
- `--no-scripts --no-plugins` keep package code from running while the lockfile is resolved.

Composer 2.2 or newer is required (`--with`).

## File edits in a prompt

Some fixes (pnpm overrides) include a step like *Replace the whole content of pnpm-workspace.yaml with exactly the lines between the markers*. Write exactly those lines, with no added indentation and a final newline. `check` compares the file byte for byte, because pnpm has no command that writes a `parent>pkg` override key.

## Yarn

Yarn classic (v1) cannot update `yarn.lock` without installing, and Yarn Berry would run the project's own vendored Yarn release. Neither is run in advance. Yarn fixes get a version from `plan`, are marked *needs your approval: footprint cannot be computed in advance*, and come with steps:

- Yarn 1, direct dependency: `yarn add <pkg>@<ver>` with `--exact` / `--tilde` / `--dev` to keep the style and section.
- Yarn 1, transitive dependency: `yarn upgrade <pkg>` does nothing for a transitive package. The prompt instead gives `yarn.lock` with the vulnerable entry removed, then `yarn install --ignore-scripts`, which re-resolves it inside the parent's range.
- Yarn Berry: `yarn up <pkg>@npm:<ver> --mode=update-lockfile` (direct) or `yarn up -R <pkg> --mode=update-lockfile` (transitive).

 With the user's approval (`plan --fix ID --approve footprint`), `check` allows lockfile and `package.json` changes only for the target package.

## What `check` compares

- Files: every changed project file must be in the footprint. Installed dependency directories (`node_modules`, `vendor`) and git-ignored files are not compared.
- Manifests (`package.json`, `composer.json`): must equal the computed result as JSON.
- Lockfiles: the added and removed `(name, version)` pairs must equal the planned ones exactly. An extra pair is out of scope; a missing one means the fix was not fully applied. Any unchanged package whose integrity or source changed is flagged.
- Other files (Dockerfile, `.nvmrc`, `.php-version`): byte-for-byte equal to the planned edit.
- Rescan: osv-scanner rescans the lockfile (or the runtime is re-evaluated) and the targeted advisories must be gone.

If an earlier fix was kept after this fix was planned, `check` and `revert` refuse to run and ask you to re-plan. That is why the workflow always runs `plan --fix <ID>` right before applying.

## Safety checks on a candidate version

| Check | Fails when |
| --- | --- |
| age | Published less than 7 days ago (`--cooldown`). A KEV issue may use it with `--approve cooldown`. |
| malicious | OSV has a `MAL-` entry for that exact version |
| install_scripts (npm) | The version adds a `preinstall`/`install`/`postinstall` script (or `binding.gyp`) the installed version did not have; for an added package, any install script |
| plugin (Composer) | The package becomes `type: composer-plugin` |
| fixes_issue | OSV still lists the targeted advisory for that version |
| new_critical | The version has a critical advisory the installed version did not |

A failed check moves the search to the next smallest version, and the skipped version is listed with the reason.
