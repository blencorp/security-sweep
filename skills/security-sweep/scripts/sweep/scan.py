"""security-sweep scan: list critical issues in lockfiles and runtimes.

Critical = severity critical, or listed in CISA KEV, or a CVE the user named.
High-severity issues are listed separately and are not planned for fixing
unless the user asks. Any data source that fails makes the result INCOMPLETE.
"""

import os

from . import __version__, kev, lockfiles, net, osv, privacy, runtime, tools

ECOSYSTEM = {"npm": "npm", "yarn-classic": "npm", "yarn-berry": "npm", "pnpm": "npm", "composer": "Packagist"}


def _tier(sev, kev_rec, ids, named):
    if kev_rec or sev == "critical" or (set(ids) & named):
        return "critical"
    if sev == "high":
        return "high"
    return None


def _advisory(vuln, score_hint, named, workaround=True):
    ids = osv.ids_of(vuln)
    sev, score = osv.severity(vuln, score_hint)
    k = kev.lookup(ids)
    return {
        "id": vuln["id"],
        "aliases": sorted(i for i in (vuln.get("aliases") or [])),
        "cves": osv.cves_of(vuln),
        "summary": vuln.get("summary") or "",
        "severity": sev,
        "score": score,
        "kev": k,
        "named": bool(ids & named),
        "tier": _tier(sev, k, ids, named),
        "workaround": osv.workaround(vuln) if workaround else None,
    }


def scan_lockfile(repo, lk, named, private=()):
    """Return the issues found in one lockfile."""
    path = os.path.join(repo, lk["path"])
    with open(path, "rb") as f:
        content = f.read()
    manifest = None
    if lk["manifest"]:
        try:
            manifest = lockfiles.read_json(os.path.join(repo, lk["manifest"]))
        except (ValueError, OSError):
            manifest = None
    entries = lockfiles.parse(lk["manager"], content, manifest)
    lk["entries"] = len(entries)
    public, lk["private_excluded"] = privacy.sanitize(lk["manager"], content, private)
    result = tools.osv_scan_lockfile(os.path.basename(lk["path"]), public)
    eco = ECOSYSTEM[lk["manager"]]
    issues = []
    for res in result.get("results") or []:
        for pkg in res.get("packages") or []:
            p = pkg.get("package") or {}
            name, version = p.get("name"), p.get("version")
            if eco == "Packagist":
                name = (name or "").lower()
            hints = {}
            for g in pkg.get("groups") or []:
                for i in (g.get("ids") or []) + (g.get("aliases") or []):
                    hints[i] = g.get("max_severity")
            advs = [_advisory(v, hints.get(v["id"]), named) for v in pkg.get("vulnerabilities") or []]
            locs = [e for e in entries if e["name"] == name and _same(eco, e["version"], version)]
            issues.append({
                "kind": "package",
                "ecosystem": eco,
                "manager": lk["manager"],
                "lockfile": lk["path"],
                "manifest": lk["manifest"],
                "package": name,
                "version": version,
                "direct": any(e["direct"] for e in locs),
                "dev": bool(locs) and all(e["dev"] for e in locs),
                "locations": sorted(e["key"] for e in locs),
                "advisories": advs,
            })
    return issues


def _same(eco, a, b):
    if a == b:
        return True
    if eco == "Packagist":
        from . import versions
        return versions.composer_key(a) == versions.composer_key(b)
    return False


def _split(issue):
    """Keep critical advisories as the issue; carry high ones along for the
    report. Returns (tier, issue) or (None, None) when nothing is high+."""
    crit = [a for a in issue["advisories"] if a["tier"] == "critical"]
    high = [a for a in issue["advisories"] if a["tier"] == "high"]
    other = [a for a in issue["advisories"] if a["tier"] is None]
    issue = dict(issue)
    issue["advisories"] = crit or high
    issue["other_advisories"] = [{"id": a["id"], "cves": a.get("cves", []), "severity": a["severity"]}
                                 for a in ((high if crit else []) + other)]
    if crit:
        return "critical", issue
    if high:
        return "high", issue
    return None, None


def _sort_key(issue):
    advs = issue["advisories"]
    return (
        0 if any(a.get("kev") for a in advs) else 1,
        -max([a.get("score") or 0 for a in advs] or [0]),
        issue.get("package") or issue.get("runtime") or "",
    )


def runtime_issue(rt, named):
    advs = []
    for a in rt["advisories"]:
        ids = set([a["id"]] + a.get("aliases", []))
        a = dict(a)
        a["named"] = bool(ids & named)
        a["tier"] = _tier(a["severity"], a.get("kev"), ids, named)
        a.setdefault("cves", sorted(i for i in ids if i.startswith("CVE-")))
        advs.append(a)
    issue = {
        "kind": "runtime",
        "runtime": rt["runtime"],
        "origin": rt["origin"],
        "source": rt["source"],
        "line": rt["line"],
        "end_line": rt.get("end_line", rt["line"]),
        "text": rt["text"],
        "version": rt["declared"],
        "branch": rt.get("branch"),
        "image": rt.get("image"),
        "tag": rt.get("tag"),
        "distro": rt.get("distro"),
        "eol": rt.get("eol"),
        "eol_date": rt.get("eol_date"),
        "data_source": rt.get("data_source"),
        "advisories": advs,
    }
    return issue


def run(repo, named_cves=(), private=()):
    repo = os.path.realpath(repo)
    named = set(named_cves)
    private = privacy.load_patterns(repo, private)
    reasons = []
    files = list(lockfiles.walk(repo))
    locks, not_checked = lockfiles.discover(repo)
    for nc in not_checked:
        reasons.append("%s: %s" % (nc["path"], nc["reason"]))

    critical, high = [], []
    lock_summaries = []
    for lk in locks:
        summary = {"path": lk["path"], "manager": lk["manager"], "manifest": lk["manifest"], "status": "checked"}
        try:
            for issue in scan_lockfile(repo, lk, named, private):
                tier, kept = _split(issue)
                if tier == "critical":
                    critical.append(kept)
                elif tier == "high":
                    high.append(kept)
            summary["entries"] = lk.get("entries")
            summary["private_excluded"] = lk.get("private_excluded", 0)
        except (net.SourceError, lockfiles.LockfileError, privacy.LeakError) as e:
            summary["status"] = "failed"
            summary["error"] = str(e)
            reasons.append("%s: %s" % (lk["path"], e))
        lock_summaries.append(summary)

    runtimes = []
    for decl in runtime.detect(repo, files):
        try:
            rt = runtime.evaluate(decl)
        except net.SourceError as e:
            rt = dict(decl, advisories=[], problem=str(e), eol=None)
            reasons.append("%s:%s %s runtime: %s" % (decl["source"], decl["line"], decl["runtime"], e))
            runtimes.append(rt)
            continue
        issue = runtime_issue(rt, named)
        if rt.get("problem"):
            reasons.append("%s:%s %s" % (rt["source"], rt["line"], rt["problem"]))
            crit = [a for a in issue["advisories"] if a["tier"] == "critical"]
            fixes = [a["fixed_in"] for a in crit if a.get("fixed_in")]
            rt["minimum_safe"] = _max_version(rt, fixes) if fixes else None
        else:
            tier, kept = _split(issue)
            if rt.get("eol") and tier != "critical":
                # End of life is not itself a critical CVE, but it means fixes
                # stopped. List it prominently; a line change needs approval.
                kept = kept or dict(issue, advisories=[], other_advisories=[])
                high.append(kept)
            elif tier == "critical":
                critical.append(kept)
            elif tier == "high":
                high.append(kept)
        runtimes.append({k: v for k, v in rt.items() if k != "advisories"})

    critical.sort(key=_sort_key)
    high.sort(key=_sort_key)
    for i, iss in enumerate(critical, 1):
        iss["id"] = "C%d" % i
        iss["tier"] = "critical"
    for i, iss in enumerate(high, 1):
        iss["id"] = "H%d" % i
        iss["tier"] = "high"

    return {
        "tool": {"name": "security-sweep", "version": __version__,
                 "osv_scanner": tools.load_lock()["osv-scanner"]["version"]},
        "repo": repo,
        "scanned_at": net.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "INCOMPLETE" if reasons else "COMPLETE",
        "incomplete_reasons": reasons,
        "named_cves": sorted(named),
        "private_patterns": private,
        "lockfiles": lock_summaries,
        "not_checked": not_checked,
        "runtimes": runtimes,
        "critical": critical,
        "high": high,
    }


def _max_version(rt, vs):
    from . import versions
    if rt.get("origin") == "distro":
        debian = rt["distro"]["ecosystem"].split(":")[0] in ("Debian", "Ubuntu")
        cmp_ = versions.dpkg_compare if debian else versions.apk_compare
        best = vs[0]
        for v in vs[1:]:
            if cmp_(v, best) > 0:
                best = v
        return best
    key = versions.semver_key if rt["runtime"] == "node" else versions.composer_key
    return max(vs, key=key)
