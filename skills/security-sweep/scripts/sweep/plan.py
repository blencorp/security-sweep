"""security-sweep plan: the smallest safe fix for each critical issue.

For a package issue:
  1. Smallest version above the installed one that OSV says is not affected
     by this issue's critical advisories, in the current major (minor for
     0.x). None in the current major: report the smallest in the next major
     as "needs approval: major".
  2. Safety checks on it (age >= cooldown, no OSV malicious-package entry,
     no new install script, no new critical advisory). Fails: try the next.
  3. Least invasive way to apply it, tried in order in a scratch copy:
     direct install / refresh within existing ranges / smallest parent
     upgrade / scoped override. The first that reaches a fixed version and
     whose every changed lockfile entry passes the safety checks wins.

For a runtime issue: the smallest release in the same line that fixes every
critical advisory; the footprint is one line of one file.
"""

import datetime
import os
import re

from . import footprint, lockfiles, net, osv, registry, runtime, snapshot, state, versions

STATUS_READY = "ready"
STATUS_APPROVAL = "needs_approval"
STATUS_NO_FIX = "no_safe_fix"
STATUS_BLOCKED = "blocked"
STATUS_RESOLVED = "already_resolved"
STATUS_ERROR = "incomplete"


class Ctx(object):
    def __init__(self, repo, cooldown, approvals):
        self.repo = repo
        self.cooldown = cooldown
        self.approvals = set(approvals)
        self.now = net.now()
        self._cflags = None

    def cflags(self):
        if self._cflags is None:
            self._cflags = footprint.composer_flags()
        return self._cflags


def _days(dt, now):
    return (now - dt).total_seconds() / 86400.0


def _age_text(days):
    if days >= 730:
        return "%dy" % (days // 365)
    if days >= 60:
        return "%dmo" % (days // 30)
    return "%dd" % days


# ------------------------------------------------------------ safety checks

def safety(ctx, eco, name, version, prev_version, wanted_ids, kev_listed):
    """Run the safety checks on one package version.

    Returns {"ok", "young", "checks": [{"name","ok","detail"}], "remaining": [advisory ids]}.
    `young` is True when the only failure is the cooldown."""
    checks = []
    rel = registry.find(eco, name, version)
    young = False
    if rel is None or rel.published is None:
        checks.append({"name": "age", "ok": False, "detail": "publish date unknown"})
    else:
        days = _days(rel.published, ctx.now)
        if days >= ctx.cooldown:
            checks.append({"name": "age", "ok": True, "detail": "published %s ago" % _age_text(days)})
        else:
            young = True
            allowed = kev_listed and "cooldown" in ctx.approvals
            checks.append({"name": "age", "ok": allowed,
                           "detail": "published %.1f days ago, cooldown is %d days%s"
                                     % (days, ctx.cooldown, " (approved: KEV)" if allowed else "")})
    vulns = osv.query(eco, name, version)
    mal = [v["id"] for v in vulns if osv.is_malicious(v)]
    checks.append({"name": "malicious", "ok": not mal,
                   "detail": "OSV lists %s" % ", ".join(mal) if mal else "no OSV malicious-package entry"})
    prev = registry.find(eco, name, prev_version) if prev_version else None
    if eco == "npm":
        before = set(prev.install_scripts) if prev else set()
        new = sorted(set(rel.install_scripts if rel else ()) - before)
        checks.append({"name": "install_scripts", "ok": not new,
                       "detail": "adds %s script" % "/".join(new) if new else "no new install script"})
    else:
        was = prev.kind if prev else None
        now_kind = rel.kind if rel else None
        bad = now_kind == "composer-plugin" and was != "composer-plugin"
        checks.append({"name": "plugin", "ok": not bad,
                       "detail": "becomes a Composer plugin (runs code during Composer commands)" if bad
                       else "not a new Composer plugin"})
    still = [v["id"] for v in vulns if osv.matches(v, wanted_ids)]
    if still:
        checks.append({"name": "fixes_issue", "ok": False, "detail": "OSV still lists %s" % ", ".join(still)})
    new_crit = []
    prev_ids = set()
    if prev_version:
        prev_ids = {i for v in osv.query(eco, name, prev_version) for i in osv.ids_of(v)}
    for v in vulns:
        if osv.ids_of(v) & prev_ids or osv.is_malicious(v):
            continue
        lab, _ = osv.severity(v)
        if lab == "critical":
            new_crit.append(v["id"])
    if new_crit:
        checks.append({"name": "new_critical", "ok": False,
                       "detail": "introduces critical advisory %s" % ", ".join(new_crit)})
    if rel is not None and rel.deprecated:
        checks.append({"name": "deprecated", "ok": True, "detail": "warning: deprecated (%s)" % str(rel.deprecated)[:120]})
    ok = all(c["ok"] for c in checks)
    only_age = young and all(c["ok"] for c in checks if c["name"] != "age")
    remaining = sorted(v["id"] for v in vulns if not osv.matches(v, wanted_ids) and not osv.is_malicious(v))
    return {"ok": ok, "young": only_age and not ok, "checks": checks, "remaining": remaining}


# ------------------------------------------------------- package fix search

def _wanted(issue):
    ids = set()
    for a in issue["advisories"]:
        ids.add(a["id"])
        ids.update(a.get("aliases") or [])
    return ids


def _kev(issue):
    return any(a.get("kev") for a in issue["advisories"])


def candidate_versions(ctx, issue, advisories):
    """Published, non-prerelease, non-deprecated versions above the installed
    one that none of the critical advisories affect, ascending."""
    eco, name, installed = issue["ecosystem"], issue["package"], issue["version"]
    parse = versions.parse_semver if eco == "npm" else versions.parse_composer
    inst = parse(installed)
    out = []
    for v, rel in registry.releases(eco, name).items():
        pv = parse(v)
        if pv is None or pv.is_prerelease or rel.deprecated or inst is None or pv <= inst:
            continue
        if any(osv.affects(a, eco, name, v) for a in advisories):
            continue
        out.append((pv, v))
    out.sort()
    return [v for _, v in out]


def choose_version(ctx, issue, advisories):
    """Returns (version or None, status, approvals_needed, skipped, safety)."""
    eco, installed = issue["ecosystem"], issue["version"]
    wanted = _wanted(issue)
    kev_listed = _kev(issue)
    cands = candidate_versions(ctx, issue, advisories)
    same = [v for v in cands if versions.same_line(eco, installed, v)]
    other = [v for v in cands if not versions.same_line(eco, installed, v)]
    skipped = []
    for pool, crossing in ((same, False), (other, True)):
        first_young = None
        for v in pool:
            s = safety(ctx, eco, issue["package"], v, installed, wanted, kev_listed)
            if s["ok"]:
                need = ["major"] if crossing and "major" not in ctx.approvals else []
                return v, (STATUS_APPROVAL if need else STATUS_READY), need, skipped, s
            if s["young"] and first_young is None:
                first_young = (v, s)
            skipped.append({"version": v, "reason": "; ".join(c["detail"] for c in s["checks"] if not c["ok"])})
        if first_young:
            # A fix exists in this line but is younger than the cooldown. Do
            # not jump to another major to dodge the wait.
            v, s = first_young
            if kev_listed:
                need = ["cooldown"] + (["major"] if crossing and "major" not in ctx.approvals else [])
                return v, STATUS_APPROVAL, need, skipped, s
            return None, STATUS_NO_FIX, [], skipped, s
    return None, STATUS_NO_FIX, [], skipped, None


def _current_entries(ctx, issue):
    path = os.path.join(ctx.repo, issue["lockfile"])
    with open(path, "rb") as f:
        content = f.read()
    manifest = None
    if issue.get("manifest") and os.path.exists(os.path.join(ctx.repo, issue["manifest"])):
        manifest = lockfiles.read_json(os.path.join(ctx.repo, issue["manifest"]))
    return lockfiles.parse(issue["manager"], content, manifest), manifest


def _affected_entries(entries, issue, advisories):
    return [e for e in entries if e["name"] == issue["package"]
            and any(osv.affects(a, issue["ecosystem"], e["name"], e["version"]) for a in advisories)]


def _parents(entries, vulnerable_keys):
    return [e for e in entries if any(k in vulnerable_keys for k in e["deps"].values())]


def _reaches_fix(diff_after, issue, advisories):
    left = _affected_entries(diff_after, issue, advisories)
    return not left


def _footprint_safety(ctx, issue, fp, advisories):
    """Safety checks on every lockfile entry the footprint adds or changes."""
    eco = issue["ecosystem"]
    removed = {}
    for n, v in fp["diff"]["removed"]:
        removed.setdefault(n, []).append(v)
    results = []
    wanted = _wanted(issue)
    for n, v in fp["diff"]["added"]:
        prev = removed.get(n, [None])[0]
        s = safety(ctx, eco, n, v, prev, wanted if n == issue["package"] else set(), _kev(issue))
        results.append({"name": n, "from": prev, "to": v, "ok": s["ok"], "young": s["young"],
                        "checks": s["checks"], "remaining": s["remaining"]})
    for n, v in fp["diff"]["refingerprinted"]:
        results.append({"name": n, "from": v, "to": v, "ok": False, "young": False,
                        "checks": [{"name": "integrity", "ok": False,
                                    "detail": "same version, different integrity/source"}], "remaining": []})
    return results


def plan_package(ctx, issue):
    p = {"id": issue["id"], "kind": "package", "issue": _issue_summary(issue)}
    advisories = [osv.get_vuln(a["id"]) for a in issue["advisories"]]
    entries, manifest = _current_entries(ctx, issue)
    vulnerable = _affected_entries(entries, issue, advisories)
    if not vulnerable:
        p.update(status=STATUS_RESOLVED, detail="no installed %s version in %s is affected any more"
                 % (issue["package"], issue["lockfile"]))
        return p
    installed = issue["version"]
    target, status, need, skipped, chosen_safety = choose_version(ctx, issue, advisories)
    p["skipped_versions"] = skipped
    if target is None:
        p.update(status=STATUS_NO_FIX, approvals_needed=[],
                 detail=_no_fix_text(issue, skipped),
                 workarounds=[a.get("workaround") for a in issue["advisories"] if a.get("workaround")])
        return p
    p["target"] = {"package": issue["package"], "from": installed, "to": target,
                   "crosses_major": not versions.same_line(issue["ecosystem"], installed, target)}
    p["status"], p["approvals_needed"] = status, need
    p["safety"] = chosen_safety["checks"] if chosen_safety else []
    p["still_affected_by"] = chosen_safety["remaining"] if chosen_safety else []

    try:
        footprint.tool_of(issue["manager"])
    except footprint.Unavailable as e:
        files = [issue["lockfile"]] + ([issue["manifest"]] if issue.get("manifest") else [])
        need = sorted(set(need) | ({"footprint"} - ctx.approvals))
        p.update(status=STATUS_APPROVAL if need else STATUS_READY, approvals_needed=need,
                 detail=str(e), approach="manual",
                 footprint={"files": sorted(files), "entries": None, "names_only": [issue["package"]]},
                 steps=_manual_steps(issue, target))
        p["_before"] = {}
        for rel in files:
            with open(os.path.join(ctx.repo, rel), "rb") as f:
                p["_before"][rel] = f.read()
        return p

    vulnerable_keys = {e["key"] for e in vulnerable}
    is_direct = any(e["direct"] for e in vulnerable)
    approaches = []
    cflags = ctx.cflags() if issue["manager"] == "composer" else None
    if is_direct:
        approaches.append(("direct", footprint.direct_steps(issue["manager"], issue["package"], target, manifest, cflags)))
    else:
        approaches.append(("refresh", footprint.refresh_steps(issue["manager"], issue["package"], target, cflags)))
    if not is_direct:
        for parent in _parents(entries, vulnerable_keys):
            pv = _parent_candidate(ctx, issue, parent, target)
            if pv and parent["direct"]:
                approaches.append(("parent-upgrade %s %s -> %s" % (parent["name"], parent["version"], pv),
                                   footprint.parent_steps(issue["manager"], parent["name"], pv, issue["package"],
                                                          target, manifest, cflags)))
        if issue["manager"] == "npm":
            parents = sorted({e["name"] for e in _parents(entries, vulnerable_keys)})
            approaches.append(("override", footprint.override_steps("npm", parents, issue["package"], target)))
    attempts = []
    for label, steps in approaches:
        fp = footprint.compute(ctx.repo, issue, steps)
        if not fp["ok"]:
            attempts.append({"approach": label, "result": fp["error"]})
            continue
        if not _reaches_fix(fp["after"], issue, advisories):
            attempts.append({"approach": label, "result": "did not reach a fixed version"})
            continue
        checks = _footprint_safety(ctx, issue, fp, advisories)
        bad = [c for c in checks if not c["ok"]]
        crossing = _major_changes(issue, fp, label)
        if bad and not all(c["young"] for c in bad):
            attempts.append({"approach": label, "result": "safety check failed: " + "; ".join(
                "%s %s: %s" % (c["name"], c["to"], ", ".join(x["detail"] for x in c["checks"] if not x["ok"]))
                for c in bad)})
            continue
        need = set(p["approvals_needed"])
        if bad:
            if not _kev(issue):
                attempts.append({"approach": label, "result": "a changed package is younger than the cooldown: "
                                 + ", ".join("%s %s" % (c["name"], c["to"]) for c in bad)})
                continue
            if "cooldown" not in ctx.approvals:
                need.add("cooldown")
        if crossing and "major" not in ctx.approvals:
            need.add("major")
        p["approach"] = label.split(" ")[0]
        p["approach_detail"] = label
        p["steps"] = [s for s in steps]
        p["materialize"] = footprint.MATERIALIZE[footprint.tool_of(issue["manager"])]
        p["footprint"] = {
            "files": sorted(fp["files"]),
            "entries": lockfiles.changes_as_list(fp["diff"]),
            "added": [list(x) for x in fp["diff"]["added"]],
            "removed": [list(x) for x in fp["diff"]["removed"]],
        }
        p["_expected"] = {rel: after for rel, (before, after) in fp["files"].items()}
        p["_before"] = {rel: before for rel, (before, after) in fp["files"].items()}
        p["entry_checks"] = checks
        landed = sorted({v for n, v in fp["diff"]["added"] if n == issue["package"]},
                        key=versions.semver_key if issue["ecosystem"] == "npm" else versions.composer_key)
        if landed:
            p["target"]["to"] = landed[-1] if len(landed) == 1 else ", ".join(landed)
        tc = [c for c in checks if c["name"] == issue["package"]]
        if tc:
            p["safety"] = tc[0]["checks"]
            p["still_affected_by"] = tc[0]["remaining"]
        p["approvals_needed"] = sorted(need)
        p["status"] = STATUS_APPROVAL if need else STATUS_READY
        p["attempts"] = attempts
        return p
    p.update(status=STATUS_BLOCKED, attempts=attempts,
             detail="no approach reached a fixed version within the safety rules",
             workarounds=[a.get("workaround") for a in issue["advisories"] if a.get("workaround")])
    if issue["manager"] == "composer":
        p["detail"] += "; Composer has no scoped override"
    return p


def _parent_candidate(ctx, issue, parent, target):
    """Smallest parent version (same major) whose declared range for the
    vulnerable package admits the target."""
    eco = issue["ecosystem"]
    try:
        rels = registry.releases(eco, parent["name"])
    except net.NotFound:
        return None
    parse = versions.parse_semver if eco == "npm" else versions.parse_composer
    cur = parse(parent["version"])
    cands = []
    for v, rel in rels.items():
        pv = parse(v)
        if pv is None or pv.is_prerelease or rel.deprecated or cur is None or pv <= cur:
            continue
        if not versions.same_line(eco, parent["version"], v):
            continue
        rng = rel.requires.get(issue["package"])
        if rng is None:
            continue
        try:
            if versions.satisfies(eco, target, rng):
                cands.append((pv, v))
        except ValueError:
            continue
    cands.sort()
    return cands[0][1] if cands else None


def _major_changes(issue, fp, label):
    """A major/0.x-minor change to the target package or the upgraded parent."""
    watch = {issue["package"]}
    m = re.match(r"parent-upgrade (\S+)", label)
    if m:
        watch.add(m.group(1))
    for ch in lockfiles.changes_as_list(fp["diff"]):
        if ch["name"] in watch and ch["from"] and ch["to"] and \
                not versions.same_line(issue["ecosystem"], ch["from"], ch["to"]):
            return True
    return False


def _manual_steps(issue, target):
    name = issue["package"]
    if issue["manager"] == "yarn-classic":
        if issue["direct"]:
            return [["yarn", "upgrade", "%s@%s" % (name, target), "--exact", "--ignore-scripts"]]
        return [["yarn", "install", "--ignore-scripts"]]
    if issue["manager"] == "yarn-berry":
        if issue["direct"]:
            return [["yarn", "up", "%s@npm:%s" % (name, target), "--mode=update-lockfile"]]
        return [["yarn", "up", "-R", name, "--mode=update-lockfile"]]
    return []


def _no_fix_text(issue, skipped):
    if not skipped:
        return "no published version of %s fixes %s" % (
            issue["package"], ", ".join(a["id"] for a in issue["advisories"]))
    return "every fixed version failed a safety check (see skipped_versions)"


def _issue_summary(issue):
    keep = ("id", "kind", "tier", "ecosystem", "manager", "lockfile", "manifest", "package", "version", "direct",
            "dev", "runtime", "origin", "source", "line", "end_line", "branch", "image", "tag", "distro", "eol")
    out = {k: issue[k] for k in keep if k in issue}
    out["advisories"] = [{"id": a["id"], "cves": a.get("cves", []), "severity": a.get("severity"),
                          "score": a.get("score"), "kev": a.get("kev"), "fixed_in": a.get("fixed_in")}
                         for a in issue["advisories"]]
    return out


# ----------------------------------------------------------------- runtimes

def plan_runtime(ctx, issue):
    p = {"id": issue["id"], "kind": "runtime", "issue": _issue_summary(issue)}
    crit = issue["advisories"]
    unfixed = [a["id"] for a in crit if not a.get("fixed_in")]
    if issue.get("eol") or unfixed:
        what = "%s %s is end of life" % (issue["runtime"], issue.get("branch")) if issue.get("eol") else \
            "no release in %s %s fixes %s" % (issue["runtime"], issue.get("branch") or "", ", ".join(unfixed))
        p.update(status=STATUS_APPROVAL, approvals_needed=["line"],
                 detail=what + "; moving to a newer release line needs your approval and is outside "
                               "what this tool changes")
        return p
    if issue["origin"] == "distro":
        return _plan_distro(ctx, issue, p)
    if not crit:
        p.update(status=STATUS_RESOLVED, detail="no critical advisories")
        return p
    rt = issue["runtime"]
    key = versions.semver_key if rt == "node" else versions.composer_key
    need = max((a["fixed_in"] for a in crit), key=key)
    if rt == "php":
        rel = runtime.php_releases(issue["branch"])
    else:
        rel = [(v, d) for v, d, _ in runtime.node_releases() if v.split(".")[0] == issue["branch"]]
    cands = [(v, d) for v, d in rel if key(v) >= key(need)]
    skipped = []
    kev_listed = any(a.get("kev") for a in crit)
    approvals = []
    chosen = None
    for v, d in cands:
        published = net.parse_time(d + "T00:00:00Z") if d else None
        if published is None:
            skipped.append({"version": v, "reason": "release date unknown"})
            continue
        days = _days(published, ctx.now)
        if days < ctx.cooldown:
            if not kev_listed:
                skipped.append({"version": v, "reason": "released %.1f days ago, cooldown is %d days"
                                % (days, ctx.cooldown)})
                break
            if "cooldown" not in ctx.approvals:
                approvals = ["cooldown"]
        if issue["origin"] == "official-image":
            tag = runtime.retag(issue["tag"], v)
            if not runtime.docker_tag_exists(issue["image"], tag):
                skipped.append({"version": v, "reason": "image tag %s:%s does not exist" % (issue["image"], tag)})
                continue
        chosen = (v, days)
        break
    p["skipped_versions"] = skipped
    if not chosen:
        p.update(status=STATUS_NO_FIX, detail="the release that fixes every critical advisory (%s) is not yet "
                                               "past the %d-day cooldown or is unavailable" % (need, ctx.cooldown))
        return p
    v, days = chosen
    p["target"] = {"runtime": rt, "from": issue["version"], "to": v, "crosses_major": False}
    young = days < ctx.cooldown
    p["safety"] = [{"name": "age", "ok": not approvals,
                    "detail": "released %s ago%s" % (_age_text(days) if days >= 1 else "%.1f days" % days,
                                                     (", cooldown is %d days (CISA KEV%s)" % (
                                                         ctx.cooldown, ": approved" if not approvals else ""))
                                                     if young else "")}]
    if issue["origin"] == "official-image":
        p["safety"].append({"name": "image_tag", "ok": True,
                            "detail": "%s:%s exists" % (issue["image"], runtime.retag(issue["tag"], v))})
    return _line_edit(ctx, issue, p, v, approvals)


def _line_edit(ctx, issue, p, new_version, approvals):
    path = os.path.join(ctx.repo, issue["source"])
    with open(path, "rb") as f:
        before = f.read()
    lines = before.decode("utf-8").splitlines(True)
    idx = issue["line"] - 1
    if issue["origin"] == "distro":
        # A RUN instruction can span several lines; edit the one with the pin.
        for j in range(idx, min(issue.get("end_line", issue["line"]), len(lines))):
            if "=" + issue["version"] in lines[j]:
                idx = j
                break
    old_line = lines[idx]
    if issue["origin"] == "official-image":
        new_line = old_line.replace(":" + issue["tag"], ":" + runtime.retag(issue["tag"], new_version), 1)
    elif issue["origin"] == "distro":
        new_line = old_line.replace("=" + issue["version"], "=" + new_version)
    elif issue["origin"] == "platform-config":
        new_line = old_line.replace('"%s"' % issue["version"], '"%s"' % new_version, 1)
    else:
        new_line = old_line.replace(issue["version"], new_version, 1)
    if new_line == old_line:
        p.update(status=STATUS_ERROR, detail="could not locate the version on %s line %d"
                 % (issue["source"], idx + 1))
        return p
    lines[idx] = new_line
    after = "".join(lines).encode("utf-8")
    p["approach"] = "edit-line"
    p["edit"] = {"file": issue["source"], "line": idx + 1,
                 "from": old_line.rstrip("\r\n"), "to": new_line.rstrip("\r\n")}
    p["footprint"] = {"files": [issue["source"]], "entries": [], "added": [], "removed": []}
    p["_expected"] = {issue["source"]: after}
    p["_before"] = {issue["source"]: before}
    p["approvals_needed"] = approvals
    p["status"] = STATUS_APPROVAL if approvals else STATUS_READY
    if issue["origin"] == "platform-config":
        p["notes"] = ["config.platform.php only tells Composer which PHP to resolve for. Upgrade the PHP that "
                      "actually runs this project to %s as well." % new_version,
                      "composer.lock records a content-hash of composer.json; run `composer update --lock` "
                      "afterwards only if Composer warns that the lock file is out of date."]
    if issue["origin"] == "distro":
        p["notes"] = ["Rebuild the image so the pinned package version is installed."]
    if issue["origin"] == "official-image":
        p["notes"] = ["Rebuild and redeploy the image for the new runtime to take effect."]
    return p


def _plan_distro(ctx, issue, p):
    crit = issue["advisories"]
    if not crit:
        p.update(status=STATUS_RESOLVED, detail="no critical advisories")
        return p
    target = crit[0]["fixed_in"]
    cmp_ = versions.dpkg_compare if issue["distro"]["ecosystem"].split(":")[0] in ("Debian", "Ubuntu") \
        else versions.apk_compare
    for a in crit[1:]:
        if cmp_(a["fixed_in"], target) > 0:
            target = a["fixed_in"]
    p["target"] = {"runtime": issue["runtime"], "from": issue["version"], "to": target, "crosses_major": False}
    p["safety"] = [{"name": "age", "ok": True,
                    "detail": "not checked: the distro tracker does not publish release dates"}]
    return _line_edit(ctx, issue, p, target, [])


# --------------------------------------------------------------- top level

def plan_issue(ctx, issue):
    try:
        if issue["kind"] == "runtime":
            return plan_runtime(ctx, issue)
        return plan_package(ctx, issue)
    except (net.SourceError, lockfiles.LockfileError) as e:
        return {"id": issue["id"], "kind": issue["kind"], "issue": _issue_summary(issue),
                "status": STATUS_ERROR, "detail": str(e)}
    except footprint.Unavailable as e:
        return {"id": issue["id"], "kind": issue["kind"], "issue": _issue_summary(issue),
                "status": STATUS_BLOCKED, "detail": str(e)}


def write_fix(run_dir, repo, fx, snap):
    """Save what `check` and `revert` need: the snapshot, the footprint files
    before the fix, and the exact expected content after it."""
    d = os.path.join(run_dir, "fixes", fx["id"])
    before = fx.pop("_before", {})
    expected = fx.pop("_expected", {})
    for rel, data in before.items():
        if data is not None:
            _write_bytes(os.path.join(d, "before", rel), data)
    for rel, data in expected.items():
        if data is not None:
            _write_bytes(os.path.join(d, "expected", rel), data)
    fx["created_files"] = sorted(rel for rel, data in before.items() if data is None)
    state.write_json(os.path.join(d, "snapshot.json"), {"taken_at": net.now().isoformat(),
                                                         "seq": state.next_seq(run_dir), "files": snap})
    state.write_json(os.path.join(d, "plan.json"), fx)
    return d


def _write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def run(repo, scan_result, run_dir, fix_id=None, include_high=False, approvals=(), cooldown=7):
    ctx = Ctx(repo, cooldown, approvals)
    issues = list(scan_result["critical"])
    if include_high or (fix_id and fix_id.startswith("H")):
        issues += scan_result["high"]
    if fix_id:
        issues = [i for i in issues if i["id"] == fix_id]
        if not issues:
            raise ValueError("no issue %s in the scan (ids: %s)" % (
                fix_id, ", ".join(i["id"] for i in scan_result["critical"] + scan_result["high"]) or "none"))
    snap = snapshot.take(repo)
    fixes = []
    for issue in issues:
        fx = plan_issue(ctx, issue)
        fx["approved"] = sorted(ctx.approvals)
        fx["planned_at"] = ctx.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        fx["cooldown_days"] = cooldown
        write_fix(run_dir, repo, fx, snap)
        fixes.append(fx)
    return {
        "repo": repo,
        "scan_status": scan_result["status"],
        "incomplete_reasons": scan_result["incomplete_reasons"],
        "planned_at": ctx.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fixes": fixes,
    }


def days_until(published, cooldown, now):
    return published + datetime.timedelta(days=cooldown) - now
