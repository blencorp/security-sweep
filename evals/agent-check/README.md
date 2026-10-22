# Agent check

Does a coding agent fix critical vulnerabilities better with the skill than without it?

Each session gets a fresh git copy of a sample project (dependencies installed) and the same prompt:

> Fix the critical security vulnerabilities in this project. I approve applying every fix that can be made safely within the current major versions; do not make any change that would need my approval (such as a major version upgrade). Work without asking me questions, and tell me at the end what you changed and what you did not.

The prompt pre-approves safe fixes so the agent can work non-interactively. With the skill, the project gets the skill under `.claude/skills/security-sweep/`. Without it, nothing is added.

## Fixtures

| Fixture | Right answer |
| --- | --- |
| `trap` | Fix minimist 1.2.5 → 1.2.6 (1 lockfile entry). Leave ejs 2.7.4 alone: its only fix is ejs 3+, which removes the `<% include %>` the app uses, and `npm audit fix --force` breaks `npm test`. |
| `npm-transitive` | `npm update minimist`: minimist 1.2.5 → 1.2.8 inside mkdirp's `^1.2.5`; `package.json` untouched. |
| `composer-direct` | dompdf v2.0.1 → v2.0.3 (v2.0.2 introduces a new critical advisory), `composer.lock` only. |

## Scoring (automatic, no human grading)

The expected footprint is computed by `security-sweep plan` on a pristine copy right before the session (live data). A run passes when all of these hold:

- **fixed**: every issue with a *ready* plan is no longer at the vulnerable version
- **footprint**: every changed file and lockfile entry is inside the union of the ready fixes' footprints
- **no code edit**: nothing changed except manifests and lockfiles
- **no major**: no package crossed a major version
- **tests**: `npm test` passes afterwards (when the project has tests)
- **no forbidden command**: no `npm audit fix`, `--force`, or bare `npm update` / `composer update` in the transcript

## Run

```bash
python3 evals/agent-check/run.py --dry-run                      # harness test: no agent, no cost
python3 evals/agent-check/run.py --agent claude --runs with=3,without=1   # 12 sessions
python3 evals/agent-check/run.py --agent codex --runs with=3,without=1
```

Every session is a real, billed agent run (Claude sessions are capped with `--budget`, default $15). Agents run with permission prompts disabled inside a throwaway temp directory. Results, transcripts and a markdown table go to `evals/runs/<timestamp>/` (git-ignored). Copy the table into the README for a release.

Codex sessions run with an isolated `CODEX_HOME` holding only your `auth.json` and the top-level `model` / `model_reasoning_effort` from your `~/.codex/config.toml`. Your own Codex skills, memories and `AGENTS.md` don't take part. In "with" runs, the skill is installed into that home's `skills/`. Both agents run with approvals and sandbox off (network access is required) inside throwaway temp copies.
