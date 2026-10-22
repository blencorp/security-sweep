"""PHP and Node.js runtimes: where the project declares them, where they come
from, and which critical vulnerabilities the declared version has.

Origin decides whose data applies:
  official-image  FROM php:/node: tags. Built from upstream source, so
                  php.net and nodejs.org data apply.
  version-file    .php-version, .nvmrc, .node-version. Upstream data.
  platform-config composer.json config.platform.php. Upstream data.
  distro          apt/apk packages on a Debian, Ubuntu or Alpine base. Distros
                  backport fixes without changing the upstream version, so
                  only the distro's own tracker (via OSV) is used.
"""

import json
import os
import re

from . import kev, net, osv, versions

PHP_CHANGELOG = "https://www.php.net/ChangeLog-%s.php"
PHP_ACTIVE = "https://www.php.net/releases/active.php"
NODE_VULNS = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
NODE_DIST = "https://nodejs.org/dist/index.json"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
DOCKER_TAG = "https://hub.docker.com/v2/repositories/library/%s/tags/%s"

DEBIAN_CODENAMES = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
UBUNTU_CODENAMES = {"focal": "20.04", "jammy": "22.04", "noble": "24.04"}
DEFAULT_PHP = {"Debian:11": "php7.4", "Debian:12": "php8.2", "Debian:13": "php8.4",
               "Ubuntu:20.04:LTS": "php7.4", "Ubuntu:22.04:LTS": "php8.1", "Ubuntu:24.04:LTS": "php8.3"}

_VERSION_FILES = {".php-version": "php", ".nvmrc": "node", ".node-version": "node"}


# ---------------------------------------------------------------- detection

def detect(repo, files):
    """Return runtime declarations found in the project."""
    out = []
    for rel in files:
        base = os.path.basename(rel)
        path = os.path.join(repo, rel)
        if base in _VERSION_FILES:
            out.extend(_version_file(path, rel, _VERSION_FILES[base]))
        elif base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith(".Dockerfile"):
            out.extend(_dockerfile(path, rel))
        elif base == "composer.json":
            out.extend(_platform_config(path, rel))
    return out


def _version_file(path, rel, runtime):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines, 1):
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        ver = t.lstrip("v")
        return [_decl(runtime, rel, i, line, ver, "version-file")]
    return []


def _platform_config(path, rel):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        php = ((data.get("config") or {}).get("platform") or {}).get("php")
    except (ValueError, OSError, AttributeError):
        return []
    if not php:
        return []
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    line_no = next((i for i, l in enumerate(lines, 1) if '"php"' in l and php in l), 0)
    return [_decl("php", rel, line_no, lines[line_no - 1] if line_no else "", str(php), "platform-config")]


def _decl(runtime, rel, line_no, text, ver, origin, **extra):
    full = re.match(r"^(\d+)\.(\d+)\.(\d+)$", ver or "")
    d = {"runtime": runtime, "source": rel, "line": line_no, "text": text,
         "declared": ver, "pinned": bool(full), "origin": origin}
    m = re.match(r"^(\d+)(?:\.(\d+))?", ver or "")
    d["branch"] = None
    if m:
        d["branch"] = m.group(1) + ("." + m.group(2) if runtime == "php" and m.group(2) else "")
    d.update(extra)
    return d


def _logical_lines(path):
    """Dockerfile lines with continuations joined; yields (first line no, text)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read().splitlines()
    buf, start = "", None
    for i, line in enumerate(raw, 1):
        s = line.rstrip()
        if not buf and (not s.strip() or s.strip().startswith("#")):
            continue
        if start is None:
            start = i
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        yield start, i, buf.strip(), raw[start - 1]
        buf, start = "", None
    if buf:
        yield start, len(raw), buf.strip(), raw[start - 1]


def _subst(text, args):
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}?",
                  lambda m: args.get(m.group(1), m.group(2) or m.group(0)), text)


def _dockerfile(path, rel):
    out = []
    args = {}
    stage = None
    for line_no, end_no, text, first_raw in _logical_lines(path):
        inst = text.split(None, 1)
        if not inst:
            continue
        cmd = inst[0].upper()
        rest = inst[1] if len(inst) > 1 else ""
        if cmd == "ARG" and stage is None:
            k, _, v = rest.partition("=")
            args[k.strip()] = v.strip().strip('"')
        elif cmd == "FROM":
            parts = [p for p in rest.split() if not p.startswith("--")]
            if not parts:
                continue
            ref = _subst(parts[0], args)
            stage = _from_ref(ref)
            img, tag = stage["image"], stage["tag"]
            if "$" in ref:
                out.append(dict(_decl("php" if img == "php" else "node", rel, line_no, first_raw, None,
                                      "official-image"), unresolved=ref))
                continue
            if img in ("php", "node"):
                ver = re.match(r"^(\d+(?:\.\d+){0,2})", tag or "")
                out.append(_decl(img, rel, line_no, first_raw, ver.group(1) if ver else None,
                                 "official-image", image=img, tag=tag or "latest"))
        elif cmd == "RUN" and stage and stage.get("distro"):
            for d in _distro_packages(rest, stage["distro"], rel, line_no, first_raw):
                d["end_line"] = end_no
                out.append(d)
    return out


def _from_ref(ref):
    ref = ref.split("@", 1)[0]
    name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
    for prefix in ("docker.io/library/", "docker.io/", "library/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    st = {"image": name, "tag": tag, "distro": None}
    t = tag or "latest"
    if name == "debian":
        m = re.match(r"^(\d+)", t)
        code = m.group(1) if m else DEBIAN_CODENAMES.get(t.split("-")[0])
        if code:
            st["distro"] = {"ecosystem": "Debian:%s" % code, "family": "debian"}
    elif name == "ubuntu":
        m = re.match(r"^(\d+\.\d+)", t)
        code = m.group(1) if m else UBUNTU_CODENAMES.get(t.split("-")[0])
        if code:
            st["distro"] = {"ecosystem": "Ubuntu:%s:LTS" % code, "family": "debian"}
    elif name == "alpine":
        m = re.match(r"^(\d+\.\d+)", t)
        if m:
            st["distro"] = {"ecosystem": "Alpine:v%s" % m.group(1), "family": "alpine"}
    return st


_DEB_PHP = re.compile(r"^(php(\d+\.\d+)?)(-[a-z0-9.+-]+)?(?:=(\S+))?$")
_APK_PHP = re.compile(r"^(php(\d+))(-[a-z0-9_-]+)?(?:[=~]+(\S+))?$")
_NODE = re.compile(r"^(nodejs(?:-current)?)(?:[=~]+(\S+))?$")


def _distro_packages(cmd, distro, rel, line_no, first_raw):
    out = []
    seen = set()
    for seg in re.split(r"&&|;|\|\|", cmd):
        toks = seg.split()
        if not toks:
            continue
        is_apt = any(t in ("apt-get", "apt") for t in toks[:2]) and "install" in toks
        is_apk = toks[0] == "apk" and "add" in toks
        if not (is_apt or is_apk):
            continue
        for t in toks:
            if t.startswith("-"):
                continue
            if distro["family"] == "debian":
                m = _DEB_PHP.match(t)
                if m and m.group(1) != "php-pear":
                    src = m.group(1) if m.group(2) else DEFAULT_PHP.get(distro["ecosystem"], "php")
                    key = ("php", src)
                    if key not in seen:
                        seen.add(key)
                        out.append(_distro_decl("php", src, m.group(4), distro, rel, line_no, first_raw, t))
                    continue
            else:
                m = _APK_PHP.match(t)
                if m:
                    key = ("php", m.group(1))
                    if key not in seen:
                        seen.add(key)
                        out.append(_distro_decl("php", m.group(1), m.group(4), distro, rel, line_no, first_raw, t))
                    continue
            m = _NODE.match(t)
            if m:
                key = ("node", m.group(1))
                if key not in seen:
                    seen.add(key)
                    out.append(_distro_decl("node", "nodejs" if distro["family"] == "debian" else m.group(1),
                                            m.group(2), distro, rel, line_no, first_raw, t))
    return out


def _distro_decl(runtime, package, version, distro, rel, line_no, first_raw, token):
    d = {"runtime": runtime, "source": rel, "line": line_no, "text": first_raw, "declared": version,
         "pinned": bool(version), "origin": "distro", "branch": None,
         "distro": {"ecosystem": distro["ecosystem"], "package": package, "token": token}}
    return d


# ---------------------------------------------------------------- PHP data

_cache = {}


def _php_changelog(major):
    """{version: {"date": ..., "cves": [...]}} parsed from php.net's ChangeLog."""
    ck = ("php-cl", major)
    if ck in _cache:
        return _cache[ck]
    html = net.get_text(PHP_CHANGELOG % major, source="php.net")
    out = {}
    parts = re.split(r'<section class="version" id="([0-9.]+)">', html)
    for i in range(1, len(parts) - 1, 2):
        ver, body = parts[i], parts[i + 1]
        date = re.search(r"datetime='([0-9-]+)'", body)
        out[ver] = {"date": date.group(1) if date else None, "cves": _fixed_cves(body)}
    if not out:
        raise net.SourceError("php.net", "ChangeLog-%s has no version sections" % major)
    _cache[ck] = out
    return out


_ITEM = re.compile(r"<li>(.*?)</li>", re.S)
_TRAILING_CVES = re.compile(r"\(\s*(CVE-\d{4}-\d{4,}(?:\s*,\s*CVE-\d{4}-\d{4,})*)\s*\)\s*\.?\s*$")


def _fixed_cves(body):
    """CVE ids a release fixes. php.net puts them in a trailing '(CVE-...)'
    on each item; a CVE mentioned inside the description ('Bypass of
    CVE-2024-4577') is a reference, not a fix."""
    out = set()
    for item in _ITEM.findall(body):
        text = re.sub(r"<[^>]+>", "", item).strip()
        m = _TRAILING_CVES.search(text)
        if m:
            out.update(re.findall(r"CVE-\d{4}-\d{4,}", m.group(1)))
    return sorted(out)


def php_active_branches():
    if "php-active" not in _cache:
        data = net.get_json(PHP_ACTIVE, source="php.net")
        _cache["php-active"] = sorted({b for m in data.values() for b in m})
    return _cache["php-active"]


def php_releases(branch):
    """[(version, date)] for a branch, ascending."""
    cl = _php_changelog(branch.split(".")[0])
    cutoff = net.now()
    rel = [(v, d["date"]) for v, d in cl.items() if v.startswith(branch + ".")
           and not (d["date"] and net.parse_time(d["date"] + "T00:00:00Z") > cutoff)]
    return sorted(rel, key=lambda x: versions.composer_key(x[0]))


def _php_advisories(installed):
    branch = ".".join(installed.split(".")[:2])
    cl = _php_changelog(installed.split(".")[0])
    inst = versions.composer_key(installed)
    fixed_in = {}
    cutoff = net.now()
    for ver, data in sorted(cl.items(), key=lambda x: versions.composer_key(x[0])):
        if not ver.startswith(branch + ".") or versions.composer_key(ver) <= inst:
            continue
        if data["date"] and net.parse_time(data["date"] + "T00:00:00Z") > cutoff:
            continue
        for cve in data["cves"]:
            fixed_in.setdefault(cve, ver)
    return [{"id": cve, "fixed_in": v} for cve, v in fixed_in.items()]


# --------------------------------------------------------------- Node data

def _node_vulns():
    if "node-vulns" not in _cache:
        _cache["node-vulns"] = net.get_json(NODE_VULNS, source="nodejs security-wg")
    return _cache["node-vulns"]


def node_releases():
    """[(version without v, date, security flag)] ascending."""
    if "node-dist" not in _cache:
        data = net.get_json(NODE_DIST, source="nodejs.org")
        rel = [(d["version"].lstrip("v"), d.get("date"), bool(d.get("security"))) for d in data]
        _cache["node-dist"] = sorted(rel, key=lambda x: versions.semver_key(x[0]))
    cutoff = net.now()
    return [r for r in _cache["node-dist"] if not (r[1] and net.parse_time(r[1] + "T00:00:00Z") > cutoff)]


def node_eol(major):
    if "node-sched" not in _cache:
        _cache["node-sched"] = net.get_json(NODE_SCHEDULE, source="nodejs Release schedule")
    s = _cache["node-sched"].get("v%s" % major)
    if not s or not s.get("end"):
        return None
    return s["end"]


def _node_advisories(installed):
    out = []
    seen = set()
    major = installed.split(".")[0]
    rel = [r[0] for r in node_releases() if r[0].split(".")[0] == major]
    for key, e in _node_vulns().items():
        try:
            vulnerable = versions.npm_satisfies(installed, e.get("vulnerable") or "")
            patched = versions.npm_satisfies(installed, e.get("patched") or "<0.0.0")
        except ValueError:
            continue
        if not vulnerable or patched:
            continue
        fix = None
        for v in rel:
            try:
                if versions.npm_satisfies(v, e.get("patched") or "<0.0.0") and \
                        versions.semver_key(v) > versions.semver_key(installed):
                    fix = v
                    break
            except ValueError:
                break
        cves = e.get("cve") or []
        if cves and cves[0] in seen:
            continue
        seen.update(cves)
        out.append({"id": cves[0] if cves else "NSWG-CORE-%s" % key, "aliases": cves[1:], "fixed_in": fix,
                    "severity": (e.get("severity") or "unknown").lower(),
                    "summary": e.get("description") or ""})
    return out


# --------------------------------------------------------------- evaluation

def _cve_severity(cve):
    try:
        v = osv.get_vuln(cve)
    except net.NotFound:
        return "unknown", None, ""
    lab, score = osv.severity(v)
    return lab, score, v.get("summary") or (v.get("details") or "")[:200]


def evaluate(decl):
    """Attach advisories / EOL / problems to a runtime declaration.

    Adds: "advisories" [{id, aliases, severity, score, kev, fixed_in, summary}],
          "eol" (bool or None), "eol_date", "data_source", "problem" (str or None)."""
    d = dict(decl)
    d["advisories"], d["eol"], d["eol_date"], d["problem"] = [], None, None, None
    if d.get("unresolved"):
        d["problem"] = "image reference uses a build argument without a default (%s)" % d["unresolved"]
        return d
    if d["origin"] == "distro":
        return _evaluate_distro(d)
    ver = d.get("declared")
    if not ver or not re.match(r"^\d+(\.\d+){0,2}$", ver):
        d["problem"] = ("no version in %s (%s): the runtime version depends on when the image was built"
                        % (d["source"], d.get("tag") or ver or "latest"))
        return d
    if d["runtime"] == "php":
        d["data_source"] = "php.net ChangeLog"
        branch = ".".join(ver.split(".")[:2]) if ver.count(".") >= 1 else None
        if branch is None:
            d["problem"] = "PHP %s names only a major version; the minor line is unknown" % ver
            return d
        d["branch"] = branch
        d["eol"] = branch not in php_active_branches()
        effective = ver if d["pinned"] else branch + ".0"
        advs = _php_advisories(effective)
    else:
        d["data_source"] = "nodejs security-wg"
        major = ver.split(".")[0]
        d["branch"] = major
        end = node_eol(major)
        d["eol_date"] = end
        if end:
            d["eol"] = net.parse_time(end + "T00:00:00Z") <= net.now()
        rel = [r[0] for r in node_releases() if r[0].split(".")[0] == major]
        if d["pinned"]:
            effective = ver
        else:
            prefix = ver + "."
            matching = [r for r in rel if r == ver or r.startswith(prefix)]
            effective = matching[0] if matching else major + ".0.0"
        advs = _node_advisories(effective)
    for a in advs:
        if "severity" not in a:
            a["severity"], a["score"], a["summary"] = _cve_severity(a["id"])
        a.setdefault("score", None)
        a.setdefault("aliases", [])
        a["kev"] = kev.lookup([a["id"]] + a["aliases"])
    d["advisories"] = advs
    if not d["pinned"]:
        d["problem"] = ("%s %s is not pinned to a patch release; the version in production is unknown"
                        % (d["runtime"], ver))
    return d


def _evaluate_distro(d):
    dist = d["distro"]
    d["data_source"] = "%s security tracker (via OSV)" % dist["ecosystem"].split(":")[0]
    if not d["declared"]:
        d["problem"] = ("%s is installed from %s packages without a pinned version; the installed "
                        "version depends on when the image was built" % (dist["package"], dist["ecosystem"]))
        return d
    vulns = osv.query(dist["ecosystem"], dist["package"], d["declared"])
    advs = []
    for v in vulns:
        upstream = [u for u in (v.get("upstream") or []) + (v.get("aliases") or []) if u.startswith("CVE-")]
        cve = upstream[0] if upstream else re.sub(r"^[A-Z]+-", "", v["id"])
        fix = None
        for aff in v.get("affected") or []:
            pkg = aff.get("package") or {}
            if pkg.get("ecosystem") == dist["ecosystem"] and pkg.get("name") == dist["package"]:
                for r in aff.get("ranges") or []:
                    for e in r.get("events") or []:
                        if "fixed" in e:
                            fix = e["fixed"]
        sev, score, summary = _cve_severity(cve) if cve.startswith("CVE-") else ("unknown", None, "")
        advs.append({"id": cve, "aliases": [v["id"]], "severity": sev, "score": score, "fixed_in": fix,
                     "summary": summary, "kev": kev.lookup([cve])})
    d["advisories"] = advs
    return d


def docker_tag_exists(image, tag):
    try:
        net.get_json(DOCKER_TAG % (image, tag), source="Docker Hub")
        return True
    except net.NotFound:
        return False


def retag(tag, new_version):
    """'8.2.27-fpm-bookworm' + '8.2.28' -> '8.2.28-fpm-bookworm'."""
    return re.sub(r"^\d+(?:\.\d+){0,2}", new_version, tag, count=1)
