"""Command implementations behind security_sweep.py."""

import json
import os
import sys

from . import check, net, plan, report, scan, state, tools

SKILL_DIR = tools.SKILL_DIR


def _print(text):
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def dispatch(args):
    try:
        return globals()["cmd_" + args.command](args)
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        return 3


def cmd_scan(args):
    repo = os.path.realpath(args.repo)
    if not os.path.isdir(repo):
        raise ValueError("not a directory: %s" % args.repo)
    out = state.run_dir(repo, args.out)
    state.check_outside(repo, out)
    result = scan.run(repo, args.cve, args.private)
    state.write_json(os.path.join(out, "scan.json"), result)
    md = report.scan_markdown(result)
    state.write_text(os.path.join(out, "scan.md"), md)
    if args.json:
        _print(json.dumps(result, indent=2))
    else:
        _print(md)
        _print("Run directory: %s" % out)
    return 2 if result["status"] == "INCOMPLETE" else 0


def cmd_tools(args):
    try:
        path = tools.ensure_osv_scanner(download=(args.action == "install"))
    except net.SourceError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    _print("osv-scanner %s verified: %s" % (tools.load_lock()["osv-scanner"]["version"], path))
    return 0


def _load_scan(args):
    repo = os.path.realpath(args.repo)
    if args.run:
        p = args.run
        path = p if p.endswith(".json") else os.path.join(p, "scan.json")
        out = os.path.dirname(os.path.abspath(path))
    else:
        out = state.run_dir(repo)
        path = os.path.join(out, "scan.json")
    if not os.path.exists(path):
        raise ValueError("no scan found at %s; run scan first" % path)
    result = state.read_json(path)
    if os.path.realpath(result["repo"]) != repo:
        raise ValueError("scan at %s is for %s, not %s (use --repo)" % (path, result["repo"], repo))
    return repo, out, result


def cmd_plan(args):
    if args.approve and not args.fix:
        raise ValueError("--approve applies to one fix the user approved; use it with --fix ID")
    repo, out, result = _load_scan(args)
    p = plan.run(repo, result, out, fix_id=args.fix, include_high=args.include_high,
                 approvals=args.approve, cooldown=args.cooldown)
    for fx in p["fixes"]:
        if fx.get("steps") or fx.get("edit"):
            state.write_text(os.path.join(out, "fixes", fx["id"], "prompt.txt"),
                             report.prompt_text(fx, SKILL_DIR, repo))
    plan_path = os.path.join(out, "plan.json")
    if args.fix and os.path.exists(plan_path):
        # Re-planning one fix: replace its entry, keep the others.
        full = state.read_json(plan_path)
        full["fixes"] = [f for f in full["fixes"] if f["id"] != args.fix] + p["fixes"]
        full["fixes"].sort(key=lambda f: (f["id"][0], int(f["id"][1:])))
    else:
        full = p
    state.write_json(plan_path, full)
    state.write_text(os.path.join(out, "plan.md"), report.plan_markdown(full, SKILL_DIR))
    if args.json:
        _print(json.dumps(p, indent=2))
    else:
        _print(report.plan_markdown(p, SKILL_DIR))
        for fx in p["fixes"]:
            if args.fix and (fx.get("steps") or fx.get("edit")):
                _print(report.prompt_text(fx, SKILL_DIR, repo))
        _print("Run directory: %s" % out)
    if p["scan_status"] == "INCOMPLETE" or any(fx["status"] == "incomplete" for fx in p["fixes"]):
        return 2
    return 0


def _run_dir(args):
    repo = os.path.realpath(args.repo)
    return repo, state.run_dir(repo, getattr(args, "out", None))


def cmd_check(args):
    repo, out = _run_dir(args)
    fx, res = check.run_check(repo, out, args.fix, args.tests)
    if args.json:
        _print(json.dumps(res, indent=2))
        return _check_code(res)
    sc = res["scope"]
    lines = ["Check %s: %s" % (args.fix, check.FINAL_TEXT.get(res["status"], res["status"]))]
    if res["status"] == "applied_without_approval":
        lines.append("  Approval: FAIL this fix needs approval (%s). Revert it; re-plan with --approve only after "
                     "the user explicitly agrees." % ", ".join(fx.get("approvals_needed") or []))
        lines.append("  Run: %s revert %s --repo %s --reason \"applied without approval\""
                     % (report.sweep_cmd(SKILL_DIR), args.fix, repo))
        _print("\n".join(lines))
        return 1
    if not sc["applied"]:
        lines.append("  Scope:  FAIL nothing in the footprint changed; the fix has not been applied")
    elif sc["ok"]:
        lines.append("  Scope:  PASS only %s changed, exactly as planned" % ", ".join(fx["footprint"]["files"]))
    else:
        lines.append("  Scope:  FAIL changes outside the footprint or not as planned. Revert these:")
        for c in sc["outside"]:
            lines.append("    - %s (%s outside the footprint)" % (c["path"], c["change"]))
        for p in sc["inside"]:
            lines.append("    - %s: %s (%s)" % (p["path"], p["item"], p["problem"]))
        lines.append("  Run: %s revert %s --repo %s --reason \"changes outside the footprint\""
                     % (report.sweep_cmd(SKILL_DIR), args.fix, repo))
    if res["rescan"] is not None:
        r = res["rescan"]
        if r["ok"]:
            lines.append("  Rescan: PASS %s no longer reported" % ", ".join(a["id"] for a in fx["issue"]["advisories"]))
        elif r.get("error"):
            lines.append("  Rescan: INCOMPLETE %s" % r["error"])
        else:
            lines.append("  Rescan: FAIL still reported: %s" % "; ".join(r["remaining"]))
    tests = {"pass": "PASS no new failures compared with the baseline", "fail": "FAIL new failures: revert this fix",
             "none": "NONE the project has no tests (reported, not hidden)", None: "not recorded yet: run the tests, "
             "compare with the baseline, then re-run check with --tests pass|fail|none"}[args.tests]
    lines.append("  Tests:  %s" % tests)
    _print("\n".join(lines))
    return _check_code(res)


def _check_code(res):
    if res["status"] in ("fixed", "applied_untested", "awaiting_tests"):
        return 0
    if res["rescan"] and res["rescan"].get("error"):
        return 2
    return 1


def cmd_revert(args):
    repo, out = _run_dir(args)
    fx, entry, reinstall = check.revert(repo, out, args.fix, args.reason)
    lines = ["Reverted %s: restored %s" % (args.fix, ", ".join(entry["restored"] + entry["deleted"]) or "nothing")]
    if reinstall:
        from .footprint import shell_join
        base = os.path.dirname(fx["issue"]["lockfile"])
        lines.append("Now run, from %s: %s   (puts installed packages back in line with the restored lockfile)"
                     % (os.path.join(repo, base) if base else repo, shell_join(reinstall)))
    if entry["manual"]:
        lines.append("These changes are outside the footprint and were not touched; undo them:")
        for m in entry["manual"]:
            lines.append("  - %s: %s" % (m["path"], m["how"]))
    _print("\n".join(lines))
    return 0


def cmd_report(args):
    repo, out = _run_dir(args)
    plan_, rows = check.final_report(out)
    if args.json:
        _print(json.dumps({"repo": repo, "scan_status": plan_["scan_status"],
                           "incomplete_reasons": plan_["incomplete_reasons"],
                           "fixes": [{k: v for k, v in r.items() if k != "fix"} for r in rows]}, indent=2))
        return 2 if plan_["scan_status"] == "INCOMPLETE" else 0
    lines = []
    if plan_["scan_status"] == "INCOMPLETE":
        lines.append("Status: INCOMPLETE. Some checks failed or were skipped; do not call this project clean or safe:")
        for r in plan_["incomplete_reasons"]:
            lines.append("  - %s" % r)
    else:
        lines.append("Status: scan COMPLETE")
    lines.append("")
    for r in rows:
        fx = r["fix"]
        line = "%s  %s: %s" % (r["id"], report.fix_title(fx), r["text"])
        res = r.get("result") or {}
        if r["status"] == "reverted" and res.get("reason"):
            line += " (%s)" % res["reason"]
        if r["status"] in ("needs_approval",) and fx.get("approvals_needed"):
            line += " (%s)" % "; ".join(report.APPROVAL_TEXT.get(a, a) for a in fx["approvals_needed"])
        if r["status"] in ("no_safe_fix", "blocked") and fx.get("detail"):
            line += " (%s)" % fx["detail"]
        lines.append(line)
        for w in fx.get("workarounds") or []:
            lines.append("      workaround: %s" % w.replace("\n", " ")[:300])
    _print("\n".join(lines))
    return 2 if plan_["scan_status"] == "INCOMPLETE" else 0
