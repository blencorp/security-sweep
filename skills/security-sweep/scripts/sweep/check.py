"""security-sweep check / revert / report.

check: the project may differ from the plan-time snapshot only inside the
fix's footprint, and inside it only in the planned way:
  * manifests (package.json, composer.json) must equal the computed result
  * lockfiles must add and remove exactly the planned (name, version) pairs,
    with no integrity/source change on any unchanged entry
  * any other footprint file must equal the computed result byte for byte
Then osv-scanner rescans the lockfile (or the runtime is re-evaluated) and
every targeted advisory must be gone. A fix is "fixed" only when scope,
rescan and tests all passed.
"""

import json
import os
import shutil

from . import footprint, lockfiles, net, osv, runtime, snapshot, state, tools

MANIFEST_NAMES = ("package.json", "composer.json")


def _fix_dir(run_dir, fix_id):
    d = os.path.join(run_dir, "fixes", fix_id)
    if not os.path.exists(os.path.join(d, "plan.json")):
        raise ValueError("no plan for %s in %s; run plan --fix %s first" % (fix_id, run_dir, fix_id))
    return d


def _read(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def _json_diff(a, b, path=""):
    """List of dotted paths whose values differ between two JSON values."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out.extend(_json_diff(a.get(k), b.get(k), "%s.%s" % (path, k) if path else k))
        return out
    return [] if a == b else [path or "(root)"]


def _lockfile_problems(fx, rel, before_bytes, now_bytes, manifest_now):
    issue = fx["issue"]
    manager = issue["manager"]
    fp = fx["footprint"]
    before = lockfiles.parse(manager, before_bytes, None)
    now = lockfiles.parse(manager, now_bytes, manifest_now)
    d = lockfiles.diff_entries(before, now)
    problems = []
    if fp.get("entries") is None:
        allowed = set(fp.get("names_only") or [])
        for n, v in d["added"] + d["removed"]:
            if n not in allowed:
                problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "lockfile entry changed outside the footprint"})
        return problems, d
    from collections import Counter
    want_add = Counter(tuple(x) for x in fp["added"])
    want_rem = Counter(tuple(x) for x in fp["removed"])
    got_add, got_rem = Counter(d["added"]), Counter(d["removed"])
    for n, v in sorted((got_add - want_add).elements()):
        problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "added outside the footprint"})
    for n, v in sorted((got_rem - want_rem).elements()):
        problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "removed outside the footprint"})
    for n, v in sorted((want_add - got_add).elements()):
        problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "planned but missing (fix not fully applied)",
                         "missing": True})
    for n, v in sorted((want_rem - got_rem).elements()):
        problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "planned removal did not happen",
                         "missing": True})
    for n, v in d["refingerprinted"]:
        problems.append({"path": rel, "item": "%s %s" % (n, v), "problem": "same version, different integrity/source"})
    return problems, d


def scope(repo, fix_dir, fx):
    snap = state.read_json(os.path.join(fix_dir, "snapshot.json"))["files"]
    current = snapshot.take(repo)
    changes = snapshot.compare(snap, current)
    fp_files = set((fx.get("footprint") or {}).get("files") or [])
    outside = [c for c in changes if c["path"] not in fp_files]
    inside = []
    for rel in sorted(fp_files):
        now_bytes = _read(os.path.join(repo, rel))
        before_bytes = _read(os.path.join(fix_dir, "before", rel))
        expected = _read(os.path.join(fix_dir, "expected", rel))
        base = os.path.basename(rel)
        if now_bytes is None:
            inside.append({"path": rel, "item": rel, "problem": "file was deleted"})
            continue
        if base in lockfiles.LOCKFILES:
            man_rel = os.path.join(os.path.dirname(rel), "composer.json" if base == "composer.lock" else "package.json")
            man_bytes = _read(os.path.join(repo, man_rel))
            try:
                manifest_now = json.loads(man_bytes.decode("utf-8")) if man_bytes else None
                probs, _ = _lockfile_problems(fx, rel, before_bytes or b"{}", now_bytes, manifest_now)
            except (ValueError, lockfiles.LockfileError) as e:
                probs = [{"path": rel, "item": rel, "problem": "cannot parse: %s" % e}]
            inside.extend(probs)
        elif base in MANIFEST_NAMES and expected is None and before_bytes is not None:
            # Footprint not computed in advance (Yarn): only keys naming the
            # target package may change.
            names = set((fx.get("footprint") or {}).get("names_only") or [])
            try:
                diffs = _json_diff(json.loads(before_bytes.decode("utf-8")), json.loads(now_bytes.decode("utf-8")))
            except ValueError as e:
                diffs = ["(invalid JSON: %s)" % e]
            for k in diffs:
                if not any(k == n or k.endswith("." + n) or k.endswith("/" + n) for n in names):
                    inside.append({"path": rel, "item": k, "problem": "changed outside the target package"})
        elif base in MANIFEST_NAMES and expected is not None:
            try:
                diffs = _json_diff(json.loads(expected.decode("utf-8")), json.loads(now_bytes.decode("utf-8")))
            except ValueError as e:
                diffs = ["(invalid JSON: %s)" % e]
            for k in diffs:
                inside.append({"path": rel, "item": k, "problem": "differs from the planned change"})
        elif expected is not None and now_bytes != expected:
            inside.append({"path": rel, "item": rel, "problem": "differs from the planned change"})
    applied = any(c["path"] in fp_files for c in changes)
    return {"changes": changes, "outside": outside, "inside": inside, "applied": applied,
            "ok": applied and not outside and not inside}


def rescan(repo, fx):
    """True when no targeted advisory remains. Raises SourceError if the
    rescan itself could not run."""
    issue = fx["issue"]
    wanted = set()
    for a in issue["advisories"]:
        wanted.add(a["id"])
        wanted.update(a.get("cves") or [])
    if fx["kind"] == "package":
        content = _read(os.path.join(repo, issue["lockfile"]))
        result = tools.osv_scan_lockfile(os.path.basename(issue["lockfile"]), content)
        left = []
        for res in result.get("results") or []:
            for pkg in res.get("packages") or []:
                name = (pkg.get("package") or {}).get("name") or ""
                if issue["ecosystem"] == "Packagist":
                    name = name.lower()
                if name != issue["package"]:
                    continue
                for v in pkg.get("vulnerabilities") or []:
                    if osv.ids_of(v) & wanted:
                        left.append("%s %s: %s" % (name, pkg["package"].get("version"), v["id"]))
        return not left, left
    decls = [d for d in runtime.detect(repo, [issue["source"]])
             if d["line"] == issue["line"] and d["runtime"] == issue["runtime"]]
    if not decls:
        return False, ["runtime declaration not found at %s:%s" % (issue["source"], issue["line"])]
    rt = runtime.evaluate(decls[0])
    left = ["%s %s: %s" % (rt["runtime"], rt.get("declared"), a["id"]) for a in rt["advisories"]
            if set([a["id"]] + (a.get("aliases") or [])) & wanted]
    return not left, left


def _results_path(run_dir):
    return os.path.join(run_dir, "results.json")


KEPT = ("fixed", "applied_untested", "awaiting_tests")


def _record(run_dir, fix_id, entry):
    path = _results_path(run_dir)
    data = state.read_json(path) if os.path.exists(path) else {}
    entry["seq"] = state.next_seq(run_dir)
    data[fix_id] = entry
    state.write_json(path, data)


def _stale_because(run_dir, fix_dir, fix_id):
    """Another fix kept after this fix was planned makes this plan's snapshot
    and footprint stale."""
    seq = state.read_json(os.path.join(fix_dir, "snapshot.json")).get("seq", 0)
    path = _results_path(run_dir)
    data = state.read_json(path) if os.path.exists(path) else {}
    return sorted(k for k, v in data.items() if k != fix_id and v.get("status") in KEPT and v.get("seq", 0) > seq)


def run_check(repo, run_dir, fix_id, tests=None):
    fix_dir = _fix_dir(run_dir, fix_id)
    fx = state.read_json(os.path.join(fix_dir, "plan.json"))
    if fx["status"] not in ("ready", "needs_approval"):
        raise ValueError("fix %s has status %s; there is nothing to check" % (fix_id, fx["status"]))
    stale = _stale_because(run_dir, fix_dir, fix_id)
    if stale:
        raise ValueError("the plan for %s was made before %s was kept, so its footprint is stale. "
                         "Revert %s's changes by hand (git), then run plan --fix %s and apply the new prompt."
                         % (fix_id, ", ".join(stale), fix_id, fix_id))
    sc = scope(repo, fix_dir, fx)
    out = {"fix": fix_id, "checked_at": net.now().strftime("%Y-%m-%dT%H:%M:%SZ"), "scope": sc,
           "rescan": None, "tests": tests, "status": None}
    if not sc["applied"]:
        out["status"] = "not_applied"
    elif fx["status"] == "needs_approval":
        # Rule 2: crossing a major/line (or the cooldown) needs explicit
        # approval, recorded by re-planning with --approve.
        out["status"] = "applied_without_approval"
    elif not sc["ok"]:
        out["status"] = "out_of_scope"
    else:
        try:
            ok, left = rescan(repo, fx)
            out["rescan"] = {"ok": ok, "remaining": left}
        except net.SourceError as e:
            out["rescan"] = {"ok": False, "error": str(e), "remaining": []}
        if not out["rescan"]["ok"]:
            out["status"] = "applied_unverified"
        elif tests == "pass":
            out["status"] = "fixed"
        elif tests == "fail":
            out["status"] = "tests_failed"
        elif tests == "none":
            out["status"] = "applied_untested"
        else:
            out["status"] = "awaiting_tests"
    state.write_json(os.path.join(fix_dir, "check.json"), out)
    _record(run_dir, fix_id, {"status": out["status"], "at": out["checked_at"], "tests": tests,
                              "outside": [c["path"] for c in sc["outside"]],
                              "inside": [p["item"] for p in sc["inside"]]})
    return fx, out


def revert(repo, run_dir, fix_id, reason=""):
    """Restore the footprint files to their plan-time content. Changes outside
    the footprint are listed (with how to undo them) but not touched."""
    fix_dir = _fix_dir(run_dir, fix_id)
    fx = state.read_json(os.path.join(fix_dir, "plan.json"))
    stale = _stale_because(run_dir, fix_dir, fix_id)
    if stale:
        raise ValueError("the plan for %s predates kept fix(es) %s; restoring its saved files would undo them. "
                         "Undo %s's changes by hand (for example with git) instead." % (fix_id, ", ".join(stale), fix_id))
    restored, removed = [], []
    for rel in (fx.get("footprint") or {}).get("files") or []:
        src = os.path.join(fix_dir, "before", rel)
        dst = os.path.join(repo, rel)
        if os.path.exists(src):
            shutil.copyfile(src, dst)
            restored.append(rel)
        elif rel in (fx.get("created_files") or []) and os.path.exists(dst):
            os.unlink(dst)
            removed.append(rel)
    sc = scope(repo, fix_dir, fx)
    manual = []
    for c in sc["outside"]:
        if c["change"] == "added":
            manual.append({"path": c["path"], "how": "delete it (it did not exist at plan time)"})
        elif snapshot.git_tracked(repo, c["path"]):
            manual.append({"path": c["path"], "how": "git checkout -- %s   (if it had no uncommitted changes before the fix)" % c["path"]})
        else:
            manual.append({"path": c["path"], "how": "restore it by hand; it is not tracked by git"})
    reinstall = None
    if fx["kind"] == "package":
        try:
            reinstall = footprint.MATERIALIZE[footprint.tool_of(fx["issue"]["manager"])]
        except footprint.Unavailable:
            reinstall = None
    entry = {"status": "reverted", "reason": reason, "at": net.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
             "restored": restored, "deleted": removed, "manual": manual}
    _record(run_dir, fix_id, entry)
    return fx, entry, reinstall


# ------------------------------------------------------------------ report

FINAL_TEXT = {
    "fixed": "fixed (scope, tests and rescan passed)",
    "reverted": "reverted",
    "needs_approval": "needs approval",
    "no_safe_fix": "no safe fix available",
    "blocked": "no safe fix available (blocked)",
    "already_resolved": "already resolved",
    "not_applied": "not applied",
    "out_of_scope": "applied with changes outside the footprint: must be reverted",
    "applied_unverified": "applied, NOT verified (rescan failed)",
    "applied_untested": "applied and verified, but the project has no tests",
    "awaiting_tests": "applied and verified; test result not recorded yet",
    "tests_failed": "tests failed: must be reverted",
    "applied_without_approval": "applied without the required approval: must be reverted",
    "incomplete": "INCOMPLETE (a data source failed)",
    "ready": "not applied (ready)",
}


def final_report(run_dir):
    plan_path = os.path.join(run_dir, "plan.json")
    if not os.path.exists(plan_path):
        raise ValueError("no plan in %s; run plan first" % run_dir)
    plan = state.read_json(plan_path)
    results = state.read_json(_results_path(run_dir)) if os.path.exists(_results_path(run_dir)) else {}
    rows = []
    for fx0 in plan["fixes"]:
        fid = fx0["id"]
        p = os.path.join(run_dir, "fixes", fid, "plan.json")
        fx = state.read_json(p) if os.path.exists(p) else fx0
        r = results.get(fid)
        status = r["status"] if r else fx["status"]
        row = {"id": fid, "status": status, "text": FINAL_TEXT.get(status, status), "fix": fx}
        if r:
            row["result"] = r
        rows.append(row)
    return plan, rows
