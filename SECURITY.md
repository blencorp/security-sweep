# Security policy

security-sweep runs package managers and a downloaded scanner on behalf of coding agents, so bugs in it can matter. Thank you for reporting them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this repository. Please do not open a public issue.

Include what you ran, what happened, and what you expected. We aim to acknowledge reports within 3 business days and to ship a fix or mitigation for confirmed issues within 30 days.

## In scope

- A way to make `plan` prescribe, or `check` accept, a change outside the computed footprint
- Package or project code running during `plan` (it must only resolve lockfiles, with scripts and plugins disabled)
- osv-scanner checksum verification being bypassed
- Secrets from `.npmrc` or `auth.json` being printed, logged or written to the run directory
- Run output being written inside the scanned project

## Out of scope

- Vulnerabilities in the projects you scan. That is what the tool reports.
- Vulnerable packages under `tests/fixtures/`. They are vulnerable on purpose, as test inputs.
- Wrong or missing data in OSV, CISA KEV, php.net, nodejs.org or the registries. Please report those upstream. A case where security-sweep reports such a failure as clean instead of INCOMPLETE *is* in scope.

## Supported versions

Only the latest release receives fixes.
