"""OSV.dev API: advisory records, per-version queries, range evaluation and
severity."""

import re

from . import cvss, net, versions

API = "https://api.osv.dev/v1"


def get_vuln(vid):
    return net.get_json("%s/vulns/%s" % (API, vid), source="osv.dev")


def query(ecosystem, name, version):
    """All advisories OSV lists for one package version (follows pagination)."""
    out = []
    token = None
    while True:
        body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        if token:
            body["page_token"] = token
        res = net.post_json("%s/query" % API, body, source="osv.dev")
        out.extend(res.get("vulns") or [])
        token = res.get("next_page_token")
        if not token:
            return out


def ids_of(vuln):
    return {vuln.get("id")} | set(vuln.get("aliases") or [])


def cves_of(vuln):
    return sorted(i for i in ids_of(vuln) if i and i.startswith("CVE-"))


def matches(vuln, wanted):
    """True when the advisory is one of `wanted` (ids or aliases)."""
    return bool(ids_of(vuln) & set(wanted))


def is_malicious(vuln):
    return any(i.startswith("MAL-") for i in ids_of(vuln))


def _norm(ecosystem, name):
    return name.lower() if ecosystem == "Packagist" else name


def _cmp_factory(ecosystem):
    if ecosystem == "npm":
        def key(v):
            if v == "0":
                return (-1,)
            p = versions.parse_semver(v)
            return p.key() if p else None
        return key
    if ecosystem == "Packagist":
        def key(v):
            if v == "0":
                return (-1,)
            p = versions.parse_composer(v)
            return p.key() if p else None
        return key
    raise ValueError(ecosystem)


def affects(vuln, ecosystem, name, version):
    """Does this advisory affect name@version? Evaluates `versions` lists and
    SEMVER/ECOSYSTEM ranges per the OSV schema. Unknown range types are
    ignored (GIT ranges cannot be evaluated against a package version)."""
    key = _cmp_factory(ecosystem)
    vk = key(version)
    if vk is None:
        return False
    target = _norm(ecosystem, name)
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or _norm(ecosystem, pkg.get("name", "")) != target:
            continue
        for v in aff.get("versions") or []:
            k = key(v)
            if k is not None and k == vk:
                return True
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            if _in_range(rng.get("events") or [], vk, key):
                return True
    return False


def _in_range(events, vk, key):
    evs = []
    for e in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in e:
                k = key(e[kind])
                if k is not None:
                    evs.append((k, kind))
    evs.sort(key=lambda x: (x[0], 0 if x[1] == "introduced" else 1))
    affected = False
    for k, kind in evs:
        if kind == "introduced" and vk >= k:
            affected = True
        elif kind == "fixed" and vk >= k:
            affected = False
        elif kind == "last_affected" and vk > k:
            affected = False
        elif kind == "limit" and vk >= k:
            affected = False
    return affected


def fixed_versions(vuln, ecosystem, name):
    out = []
    target = _norm(ecosystem, name)
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or _norm(ecosystem, pkg.get("name", "")) != target:
            continue
        for rng in aff.get("ranges") or []:
            for e in rng.get("events") or []:
                if "fixed" in e:
                    out.append(e["fixed"])
    return out


_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def severity(vuln, score_hint=None):
    """Return (label, score). Prefers the advisory's own label (GitHub's
    reviewed severity), then a CVSS v3 vector, then the score osv-scanner
    computed, which covers CVSS v4-only advisories."""
    score = None
    for s in vuln.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            score = cvss.base_score(s.get("score"))
            if score is not None:
                break
    if score is None and score_hint not in (None, ""):
        try:
            score = float(score_hint)
        except ValueError:
            score = None
    ds = vuln.get("database_specific") or {}
    lab = ds.get("severity")
    if isinstance(lab, str) and lab.upper() in _LABELS:
        return _LABELS[lab.upper()], score
    for aff in vuln.get("affected") or []:
        lab = (aff.get("ecosystem_specific") or {}).get("severity") or (aff.get("database_specific") or {}).get("severity")
        if isinstance(lab, str) and lab.upper() in _LABELS:
            return _LABELS[lab.upper()], score
    return cvss.label(score), score


_WORKAROUND = re.compile(r"^#+\s*workarounds?\s*$", re.I | re.M)


def workaround(vuln):
    """The 'Workarounds' section of an advisory's details, if it has one."""
    details = vuln.get("details") or ""
    m = _WORKAROUND.search(details)
    if not m:
        return None
    rest = details[m.end():]
    nxt = re.search(r"^#+\s", rest, re.M)
    text = (rest[:nxt.start()] if nxt else rest).strip()
    return text or None
