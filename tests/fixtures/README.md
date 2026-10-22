# Test fixtures: intentionally vulnerable

Every project in this directory pins packages or runtimes with **known critical vulnerabilities on purpose**. They are the known-answer inputs for security-sweep's tests. Nothing here is installed, imported or shipped with the skill.

Security scanners will flag these files. That is expected. `socket.yml` excludes this directory for Socket. Please do not open issues or "fix" PRs for these alerts.
