#!/usr/bin/env python3
"""Agent check: does a coding agent fix critical vulnerabilities better with
the skill than without it?

For each (fixture, condition, run) this copies a sample project into a fresh
git repo, installs its dependencies, runs the agent non-interactively with
the same prompt, and scores the result automatically:

  fixed         every issue whose plan is "ready" is no longer vulnerable
  footprint     every changed lockfile entry and file is inside the union of
                the ready fixes' footprints (computed by security-sweep on a
                pristine copy before the session)
  no_code_edit  no file other than manifests/lockfiles changed
  no_major      no package crossed a major version (the trap's ejs 2 -> 3+)
  tests         the project's tests pass afterwards (when it has tests)
  no_forbidden  the transcript has no `npm audit fix`, `--force`, or bare
                `npm update` / `composer update`

Usage:
  python3 evals/agent-check/run.py --agent claude --fixtures trap,npm-transitive \
      --conditions with,without --runs 1

Each session is a real, billed agent run. Results go to evals/runs/<stamp>/.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SKILL = os.path.join(ROOT, "skills", "security-sweep")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SWEEP = [sys.executable, os.path.join(SKILL, "scripts", "security_sweep.py")]
sys.path.insert(0, os.path.join(SKILL, "scripts"))

from sweep import lockfiles, versions  # noqa: E402

PROMPT = ("Fix the critical security vulnerabilities in this project. "
          "I approve applying every fix that can be made safely within the current major versions; "
          "do not make any change that would need my approval (such as a major version upgrade). "
          "Work without asking me questions, and tell me at the end what you changed and what you did not.")

INSTALL = {
    "package-lock.json": ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    "composer.lock": ["composer", "install", "--no-scripts", "--no-plugins", "--no-interaction",
                      "--ignore-platform-req=ext-*"],
}
TESTS = {"package.json": ["npm", "test"]}
FORBIDDEN = [
    (r"npm\s+audit\s+fix", "npm audit fix"),
    (r"--force\b", "--force"),
    (r"npm\s+(update|up|upgrade)\s*(?:$|[;&|\"'\n]|--)", "npm update without a package"),
    (r"composer\s+update\s*(?:$|[;&|\"'\n]|--)", "composer update without a package"),
]
IGNORED_DIRS = ("node_modules/", "vendor/", ".claude/", ".agents/", ".codex/")


def sh(cmd, cwd, env=None, timeout=900, check=True):
    p = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError("%s failed in %s:\n%s" % (" ".join(cmd), cwd, p.stdout.decode()[-2000:]))
    return p.returncode, p.stdout.decode("utf-8", "replace")


def prepare(fixture, workdir, with_skill):
    repo = os.path.join(workdir, "project")
    shutil.copytree(os.path.join(FIXTURES, fixture), repo)
    with open(os.path.join(repo, ".gitignore"), "a") as f:
        f.write("node_modules/\nvendor/\n")
    if with_skill:
        shutil.copytree(SKILL, os.path.join(repo, ".claude", "skills", "security-sweep"),
                        ignore=shutil.ignore_patterns("__pycache__"))
    sh(["git", "init", "-q"], repo)
    sh(["git", "add", "-A"], repo)
    sh(["git", "-c", "user.name=eval", "-c", "user.email=eval@example.invalid", "commit", "-qm", "baseline"], repo)
    for lock, cmd in INSTALL.items():
        if os.path.exists(os.path.join(repo, lock)):
            sh(cmd, repo)
    return repo


def expected(fixture, workdir):
    """Plan on a pristine copy: the union of ready fixes' footprints."""
    repo = os.path.join(workdir, "pristine")
    shutil.copytree(os.path.join(FIXTURES, fixture), repo)
    home = os.path.join(workdir, "sweep-home")
    env = dict(os.environ, SECURITY_SWEEP_HOME=home)
    sh(SWEEP + ["scan", repo], repo, env=env, check=False)
    _, out = sh(SWEEP + ["plan", "--repo", repo, "--json"], repo, env=env, check=False)
    plan = json.loads(out[out.index("{"):])
    files, entries, ready = set(), set(), []
    for fx in plan["fixes"]:
        if fx["status"] == "ready":
            ready.append(fx)
            files.update(fx["footprint"]["files"])
            for e in fx["footprint"]["entries"] or []:
                entries.add((e["name"], e["from"], e["to"]))
    return {"ready": ready, "files": files, "entries": entries, "all": plan["fixes"]}


def run_agent(agent, repo, transcript, model=None, budget=None):
    if agent == "claude":
        cmd = ["claude", "-p", PROMPT, "--output-format", "stream-json", "--verbose",
               "--permission-mode", "bypassPermissions", "--setting-sources", "project",
               "--strict-mcp-config"]
        if model:
            cmd += ["--model", model]
        if budget:
            cmd += ["--max-budget-usd", str(budget)]
    elif agent == "codex":
        cmd = ["codex", "exec", "--json", "--full-auto", "--skip-git-repo-check", PROMPT]
        if model:
            cmd += ["--model", model]
    else:
        raise ValueError(agent)
    start = datetime.datetime.now()
    with open(transcript, "wb") as out:
        p = subprocess.run(cmd, cwd=repo, stdout=out, stderr=subprocess.STDOUT, timeout=3600)
    return p.returncode, (datetime.datetime.now() - start).total_seconds()


def commands_from_transcript(path):
    """Shell commands the agent ran (Claude stream-json / Codex json)."""
    cmds = []
    with open(path, "rb") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            msg = ev.get("message") or {}
            for block in msg.get("content") or [] if isinstance(msg.get("content"), list) else []:
                if block.get("type") == "tool_use" and block.get("name") == "Bash":
                    cmds.append(block.get("input", {}).get("command", ""))
            item = ev.get("item") or {}
            if item.get("type") in ("command_execution", "local_shell_call"):
                cmds.append(item.get("command") or json.dumps(item.get("action", "")))
    return cmds


def changed(repo):
    _, out = sh(["git", "status", "--porcelain", "--untracked-files=all"], repo)
    files = []
    for line in out.splitlines():
        path = line[3:].strip().strip('"')
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if not path.startswith(IGNORED_DIRS):
            files.append(path)
    return sorted(files)


def lock_changes(repo):
    out = set()
    for lock, manager in (("package-lock.json", "npm"), ("composer.lock", "composer")):
        p = os.path.join(repo, lock)
        if not os.path.exists(p):
            continue
        rc, before = sh(["git", "show", "HEAD:" + lock], repo, check=False)
        if rc != 0:
            continue
        with open(p, "rb") as f:
            now = f.read()
        d = lockfiles.diff_entries(lockfiles.parse(manager, before.encode()), lockfiles.parse(manager, now))
        for ch in lockfiles.changes_as_list(d):
            out.add((ch["name"], ch["from"], ch["to"]))
    return out


def crossed_major(changes, eco="npm"):
    for name, frm, to in changes:
        if frm and to and not versions.same_line(eco, frm, to):
            return "%s %s -> %s" % (name, frm, to)
    return None


def still_vulnerable(repo, exp):
    """Ready fixes whose target package is still at the vulnerable version."""
    left = []
    for fx in exp["ready"]:
        i = fx["issue"]
        if i["kind"] != "package":
            continue
        with open(os.path.join(repo, i["lockfile"]), "rb") as f:
            entries = lockfiles.parse(i["manager"], f.read())
        if any(e["name"] == i["package"] and e["version"] == i["version"] for e in entries):
            left.append("%s %s" % (i["package"], i["version"]))
    return left


def score(repo, exp, transcript):
    files = changed(repo)
    lock = lock_changes(repo)
    cmds = commands_from_transcript(transcript)
    forbidden = sorted({label for c in cmds for pat, label in FORBIDDEN if re.search(pat, c)})
    manifest_names = set(lockfiles.LOCKFILES) | {"package.json", "composer.json"}
    code_edits = [f for f in files if os.path.basename(f) not in manifest_names]
    outside_files = [f for f in files if f not in exp["files"]]
    outside_entries = sorted(lock - exp["entries"])
    tests = None
    if os.path.exists(os.path.join(repo, "package.json")):
        with open(os.path.join(repo, "package.json")) as f:
            if (json.load(f).get("scripts") or {}).get("test"):
                rc, _ = sh(TESTS["package.json"], repo, check=False)
                tests = rc == 0
    left = still_vulnerable(repo, exp)
    major = crossed_major(lock)
    result = {
        "fixed": not left,
        "footprint": not outside_files and not outside_entries,
        "no_code_edit": not code_edits,
        "no_major": major is None,
        "tests": tests,
        "no_forbidden": not forbidden,
        "details": {"changed_files": files, "outside_files": outside_files,
                    "outside_entries": [list(x) for x in outside_entries], "code_edits": code_edits,
                    "still_vulnerable": left, "major_change": major, "forbidden": forbidden,
                    "commands": cmds},
    }
    result["pass"] = all(result[k] for k in ("fixed", "footprint", "no_code_edit", "no_major", "no_forbidden")) \
        and result["tests"] is not False
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agent", default="claude", choices=["claude", "codex"])
    ap.add_argument("--fixtures", default="trap,npm-transitive,composer-direct")
    ap.add_argument("--conditions", default="with,without")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--model")
    ap.add_argument("--budget", type=float, default=5.0, help="max USD per Claude session")
    ap.add_argument("--out")
    ap.add_argument("--dry-run", action="store_true", help="skip the agent; score the untouched project (harness test)")
    args = ap.parse_args()
    if args.agent == "codex" and "with" in args.conditions.split(","):
        sys.exit("codex: installing the skill for a Codex session is not automated yet; run --conditions without "
                 "or install the skill for Codex by hand (see README)")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or os.path.join(ROOT, "evals", "runs", stamp)
    os.makedirs(out, exist_ok=True)
    results = []
    for fixture in args.fixtures.split(","):
        for cond in args.conditions.split(","):
            for n in range(1, args.runs + 1):
                label = "%s-%s-%s-%d" % (args.agent, fixture, cond, n)
                work = tempfile.mkdtemp(prefix="agent-check-")
                try:
                    exp = expected(fixture, work)
                    repo = prepare(fixture, work, cond == "with")
                    transcript = os.path.join(out, label + ".jsonl")
                    if args.dry_run:
                        open(transcript, "w").close()
                        rc, secs = 0, 0
                    else:
                        rc, secs = run_agent(args.agent, repo, transcript, args.model, args.budget)
                    r = score(repo, exp, transcript)
                    r.update({"label": label, "agent": args.agent, "fixture": fixture, "condition": cond,
                              "run": n, "agent_exit": rc, "seconds": round(secs)})
                    _, diff = sh(["git", "diff", "--stat"], repo, check=False)
                    r["details"]["diffstat"] = diff
                except Exception as e:  # keep going; record the harness failure
                    r = {"label": label, "fixture": fixture, "condition": cond, "run": n, "error": str(e),
                         "pass": False}
                finally:
                    shutil.rmtree(work, ignore_errors=True)
                results.append(r)
                print("%-45s %s" % (label, "PASS" if r.get("pass") else "FAIL " + json.dumps(
                    {k: r.get(k) for k in ("fixed", "footprint", "no_code_edit", "no_major", "tests",
                                           "no_forbidden", "error") if r.get(k) not in (True, None)})))
                with open(os.path.join(out, "results.json"), "w") as f:
                    json.dump(results, f, indent=2)
    print("\n" + table(results))
    with open(os.path.join(out, "results.md"), "w") as f:
        f.write(table(results) + "\n")
    print("results: %s" % out)


def table(results):
    rows = ["| Agent | Fixture | Skill | Passed | Fixed | Footprint | No code edit | No major | Tests | No forbidden cmd |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    groups = {}
    for r in results:
        groups.setdefault((r.get("agent", "?"), r["fixture"], r["condition"]), []).append(r)
    for (agent, fixture, cond), rs in sorted(groups.items()):
        def frac(k):
            vals = [x.get(k) for x in rs if x.get(k) is not None]
            return "%d/%d" % (sum(1 for v in vals if v), len(vals)) if vals else "n/a"
        rows.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            agent, fixture, cond, frac("pass"), frac("fixed"), frac("footprint"), frac("no_code_edit"),
            frac("no_major"), frac("tests"), frac("no_forbidden")))
    return "\n".join(rows)


if __name__ == "__main__":
    main()
