"""Find manifests and lockfiles in a project and read lockfile entries.

Supported: package-lock.json / npm-shrinkwrap.json (v1-v3), yarn.lock
(classic and Berry), pnpm-lock.yaml (v5-v9) and composer.lock.

An entry is one resolved package in a lockfile:
    {"name", "version", "key", "direct", "dev", "deps", "fingerprint"}
`key` is unique inside its lockfile (npm install path, yarn spec, pnpm id).
`fingerprint` is the integrity/reference data, used to catch a package whose
version stayed the same but whose content source changed.
"""

import json
import os
import re

from . import miniyaml

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", "bower_components", ".yarn",
             ".pnpm-store", ".venv", "venv", "__pycache__", ".security-sweep"}

LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "composer.lock": "composer",
}
MANIFESTS = {"package.json": "node", "composer.json": "php"}


class LockfileError(Exception):
    pass


def walk(repo):
    """Yield project-relative file paths, skipping dependency and VCS dirs."""
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            yield os.path.relpath(os.path.join(root, f), repo).replace(os.sep, "/")


def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _has_deps(manifest_path, kind):
    try:
        data = read_json(manifest_path)
    except (ValueError, OSError):
        return True  # unreadable: treat as something we must check
    if kind == "node":
        return any(data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies"))
    req = dict(data.get("require") or {})
    req.update(data.get("require-dev") or {})
    return any("/" in k for k in req)


def _declares_workspaces(dirpath):
    pj = os.path.join(dirpath, "package.json")
    if os.path.exists(os.path.join(dirpath, "pnpm-workspace.yaml")):
        return True
    if os.path.exists(pj):
        try:
            return bool(read_json(pj).get("workspaces"))
        except (ValueError, OSError):
            return False
    return False


def discover(repo):
    """Return (lockfiles, not_checked).

    lockfiles: [{"path", "manager", "manifest"}]
    not_checked: [{"path", "reason"}] for manifests with dependencies and no
    lockfile covering them. These must never be reported as clean."""
    files = list(walk(repo))
    present = set(files)
    locks = []
    for rel in files:
        base = os.path.basename(rel)
        if base in LOCKFILES:
            d = os.path.dirname(rel)
            manifest = (d + "/" if d else "") + ("composer.json" if base == "composer.lock" else "package.json")
            locks.append({"path": rel, "manager": _manager(repo, rel), "manifest": manifest if manifest in present else None})
    lock_dirs = {}
    for lk in locks:
        eco = "php" if lk["manager"] == "composer" else "node"
        lock_dirs.setdefault(eco, set()).add(os.path.dirname(lk["path"]))
    not_checked = []
    for rel in files:
        base = os.path.basename(rel)
        if base not in MANIFESTS:
            continue
        kind = MANIFESTS[base]
        d = os.path.dirname(rel)
        if d in lock_dirs.get(kind, ()):
            continue
        if not _has_deps(os.path.join(repo, rel), kind):
            continue
        covered = False
        if kind == "node":
            parent = d
            while parent:
                parent = os.path.dirname(parent)
                if parent in lock_dirs.get("node", ()) and _declares_workspaces(os.path.join(repo, parent)):
                    covered = True
                    break
        if not covered:
            not_checked.append({"path": rel, "reason": "no lockfile: dependency versions are unknown, so nothing was checked"})
    return locks, not_checked


def _manager(repo, rel):
    base = os.path.basename(rel)
    m = LOCKFILES[base]
    if m == "yarn":
        with open(os.path.join(repo, rel), "rb") as f:
            head = f.read(4096).decode("utf-8", "replace")
        return "yarn-berry" if "__metadata:" in head else "yarn-classic"
    return m


def parse(manager, content, manifest=None):
    """Parse lockfile bytes. `manifest` is the parsed package.json/composer.json
    (or None) and is used to mark direct dependencies."""
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    try:
        if manager == "npm":
            return _parse_npm(json.loads(text), manifest)
        if manager == "composer":
            return _parse_composer(json.loads(text), manifest)
        if manager == "yarn-classic":
            return _parse_yarn_classic(text, manifest)
        if manager == "yarn-berry":
            return _parse_yarn_berry(text, manifest)
        if manager == "pnpm":
            return _parse_pnpm(text, manifest)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise LockfileError("cannot parse %s lockfile: %s" % (manager, e))
    raise LockfileError("unknown manager %s" % manager)


def _root_deps(manifest):
    prod, dev = {}, {}
    if manifest:
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            prod.update(manifest.get(k) or {})
        dev.update(manifest.get("devDependencies") or {})
    return prod, dev


# --------------------------------------------------------------------- npm

def npm_resolve(keys, from_key, name):
    """Node module resolution inside a v2/v3 lockfile `packages` map."""
    base = from_key
    while True:
        cand = (base + "/" if base else "") + "node_modules/" + name
        if cand in keys:
            return cand
        if not base:
            return None
        idx = base.rfind("node_modules/")
        if idx < 0:
            base = ""
        else:
            base = base[:idx].rstrip("/")


def _parse_npm(data, manifest):
    packages = data.get("packages")
    if packages is None:
        packages = _npm_v1_to_packages(data.get("dependencies") or {})
        root = {}
        if manifest:
            root = {k: manifest.get(k) or {} for k in ("dependencies", "devDependencies", "optionalDependencies")}
        packages[""] = root
    root = packages.get("") or {}
    importers = {"": root}
    for key, e in packages.items():
        if key and "node_modules/" not in key and not e.get("link"):
            importers[key] = e  # workspace package
    keys = set(packages)
    entries = []
    for key, e in packages.items():
        if not key or "node_modules/" not in key or e.get("link") or not e.get("version"):
            continue
        tail = key.rsplit("node_modules/", 1)
        name = e.get("name") or tail[1]
        owner = tail[0].rstrip("/")
        imp = importers.get(owner)
        direct = False
        if imp is not None:
            alias = tail[1]
            direct = any(alias in (imp.get(k) or {}) for k in
                         ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"))
        deps = {}
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dn in (e.get(k) or {}):
                r = npm_resolve(keys, key, dn)
                if r:
                    deps[dn] = r
        entries.append({
            "name": name, "version": e["version"], "key": key, "direct": direct,
            "dev": bool(e.get("dev")), "deps": deps,
            "ranges": dict(e.get("dependencies") or {}),
            "fingerprint": "%s|%s" % (e.get("integrity", ""), e.get("resolved", "")),
            "install_script": bool(e.get("hasInstallScript")),
        })
    return entries


def _npm_v1_to_packages(deps, prefix=""):
    out = {}
    for name, e in deps.items():
        key = (prefix + "/" if prefix else "") + "node_modules/" + name
        ver = e.get("version", "")
        if ver.startswith("npm:"):
            alias_name, ver = ver[4:].rsplit("@", 1)
        else:
            alias_name = None
        out[key] = {"version": ver, "dev": e.get("dev", False), "integrity": e.get("integrity", ""),
                    "resolved": e.get("resolved", ""), "dependencies": e.get("requires") or {}}
        if alias_name:
            out[key]["name"] = alias_name
        out.update(_npm_v1_to_packages(e.get("dependencies") or {}, key))
    return out


# ---------------------------------------------------------------- composer

def _parse_composer(data, manifest):
    direct = set()
    if manifest:
        for k in ("require", "require-dev"):
            direct.update(n.lower() for n in (manifest.get(k) or {}))
    entries = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            name = p["name"].lower()
            dist = p.get("dist") or {}
            src = p.get("source") or {}
            entries.append({
                "name": name, "version": p["version"], "key": name, "direct": name in direct,
                "dev": dev, "deps": {d.lower(): d.lower() for d in (p.get("require") or {}) if "/" in d},
                "ranges": {d.lower(): c for d, c in (p.get("require") or {}).items() if "/" in d},
                "fingerprint": "%s|%s|%s" % (dist.get("reference", ""), dist.get("shasum", ""), src.get("reference", "")),
                "type": p.get("type", "library"),
            })
    return entries


# -------------------------------------------------------------------- yarn

def _spec_name(spec):
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    return (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")


def _parse_yarn_classic(text, manifest):
    blocks = []
    cur = None
    sub = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            specs = [s.strip().strip('"') for s in line[:-1].split(",")]
            cur = {"specs": specs, "fields": {}, "deps": {}}
            blocks.append(cur)
            sub = None
        elif cur is not None and indent == 2:
            if line.endswith(":"):
                sub = line[:-1]
                continue
            sub = None
            parts = line.split(" ", 1)
            cur["fields"][parts[0]] = parts[1].strip().strip('"') if len(parts) > 1 else ""
        elif cur is not None and indent >= 4 and sub in ("dependencies", "optionalDependencies"):
            parts = line.split(" ", 1)
            cur["deps"][parts[0].strip('"')] = parts[1].strip().strip('"') if len(parts) > 1 else ""
    spec_map = {}
    for b in blocks:
        for s in b["specs"]:
            spec_map[s] = b
    entries = []
    for b in blocks:
        name = _spec_name(b["specs"][0])[0]
        deps = {}
        for dn, rng in b["deps"].items():
            target = spec_map.get("%s@%s" % (dn, rng))
            if target:
                deps[dn] = target["specs"][0]
        entries.append({
            "name": name, "version": b["fields"].get("version", ""), "key": b["specs"][0],
            "specs": b["specs"], "direct": False, "dev": False, "deps": deps, "ranges": dict(b["deps"]),
            "fingerprint": "%s|%s" % (b["fields"].get("integrity", ""), b["fields"].get("resolved", "")),
        })
    by_spec = {s: e for e in entries for s in e["specs"]}
    prod, dev = _root_deps(manifest)
    _mark_roots(entries, by_spec, prod, dev, lambda n, r: "%s@%s" % (n, r))
    return entries


def _parse_yarn_berry(text, manifest):
    data = miniyaml.loads(text)
    entries = []
    for key, e in data.items():
        if key == "__metadata" or not isinstance(e, dict):
            continue
        res = e.get("resolution") or ""
        if "@workspace:" in res or "@link:" in res or "@portal:" in res:
            continue
        specs = [s.strip() for s in key.split(",")]
        name = _spec_name(res or specs[0])[0]
        deps = {}
        ranges = {}
        for dn, rng in (e.get("dependencies") or {}).items():
            ranges[dn] = rng
            deps[dn] = "%s@%s" % (dn, rng)
        entries.append({
            "name": name, "version": str(e.get("version", "")), "key": specs[0], "specs": specs,
            "direct": False, "dev": False, "deps": deps, "ranges": ranges,
            "fingerprint": "%s|%s" % (e.get("checksum", ""), res),
        })
    by_spec = {}
    for e in entries:
        for s in e["specs"]:
            by_spec[s] = e
            n, r = _spec_name(s)
            if r.startswith("npm:"):
                by_spec["%s@%s" % (n, r[4:])] = e
    for e in entries:
        e["deps"] = {dn: by_spec[s]["key"] for dn, s in e["deps"].items() if s in by_spec}
    prod, dev = _root_deps(manifest)
    _mark_roots(entries, by_spec, prod, dev,
                lambda n, r: "%s@%s" % (n, r if ":" in r else "npm:" + r))
    return entries


def _mark_roots(entries, by_spec, prod, dev, spec_of):
    """Mark direct dependencies, then dev-only = not reachable from prod roots."""
    by_key = {e["key"]: e for e in entries}

    def roots(deps):
        out = []
        for n, r in deps.items():
            e = by_spec.get(spec_of(n, r))
            if e:
                e["direct"] = True
                out.append(e["key"])
        return out

    prod_roots = roots(prod)
    roots(dev)
    seen = set()
    stack = list(prod_roots)
    while stack:
        k = stack.pop()
        if k in seen or k not in by_key:
            continue
        seen.add(k)
        stack.extend(by_key[k]["deps"].values())
    for e in entries:
        e["dev"] = e["key"] not in seen


# -------------------------------------------------------------------- pnpm

# v5: '/name/1.2.3', '/@scope/name/1.2.3', with an optional '_peer@1+other@2'
# suffix that itself contains '@'.
_PNPM_V5_KEY = re.compile(r"^/?((?:@[^/@]+/)?[^/@]+)/(\d[^/_(]*)(?:_.*)?$")


def _pnpm_key(key):
    """'/@scope/name@1.2.3(peer@1)' or 'name@1.2.3' or '/name/1.2.3_peer@1' -> (name, version)."""
    k = re.sub(r"\(.*\)$", "", key)
    m = _PNPM_V5_KEY.match(k)
    if m:
        return m.group(1), m.group(2)
    k = k.lstrip("/")
    at = k.find("@", 1)
    if at > 0:
        name, ver = k[:at], k[at + 1:]
    else:
        name, _, ver = k.rpartition("/")
    ver = ver.split("_", 1)[0]
    return name, ver


def _pnpm_ver(v):
    """Drop the peer suffix: '1.2.3(react@17)' (v6+) or '1.2.3_react@17' (v5)."""
    if v is None:
        return ""
    v = re.sub(r"\(.*\)$", "", str(v))
    return re.sub(r"^(\d[^_]*)_.*$", r"\1", v)


def _parse_pnpm(text, manifest):
    data = miniyaml.loads(text)
    packages = data.get("packages") or {}
    snapshots = data.get("snapshots") or {}
    importers = data.get("importers")
    if importers is None:
        importers = {".": {k: data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")}}
    entries = {}
    for key, e in packages.items():
        name, ver = _pnpm_key(key)
        e = e if isinstance(e, dict) else {}
        entries["%s@%s" % (name, ver)] = {
            "name": name, "version": ver, "key": "%s@%s" % (name, ver), "direct": False,
            "dev": e.get("dev"), "deps": {}, "ranges": {},
            "fingerprint": str(e.get("resolution", "")),
            "install_script": bool(e.get("requiresBuild")),
        }
    graph = snapshots or packages
    for key, e in graph.items():
        name, ver = _pnpm_key(key)
        ent = entries.get("%s@%s" % (name, ver))
        if not ent or not isinstance(e, dict):
            continue
        for sec in ("dependencies", "optionalDependencies"):
            for dn, dv in (e.get(sec) or {}).items():
                dv = _pnpm_ver(dv)
                if dv.startswith("/") or "@" in dv[1:]:
                    tk = "%s@%s" % _pnpm_key(dv)
                else:
                    tk = "%s@%s" % (dn, dv)
                if tk in entries:
                    ent["deps"][dn] = tk

    def importer_targets(sec):
        out = []
        for imp in importers.values():
            for dn, spec in ((imp or {}).get(sec) or {}).items():
                v = spec.get("version") if isinstance(spec, dict) else spec
                v = _pnpm_ver(v)
                tk = "%s@%s" % _pnpm_key(v) if (v.startswith("/") or "@" in v[1:]) else "%s@%s" % (dn, v)
                if tk in entries:
                    entries[tk]["direct"] = True
                    out.append(tk)
        return out

    prod = importer_targets("dependencies") + importer_targets("optionalDependencies")
    importer_targets("devDependencies")
    if any(e["dev"] is None for e in entries.values()):
        seen = set()
        stack = list(prod)
        while stack:
            k = stack.pop()
            if k in seen:
                continue
            seen.add(k)
            stack.extend(entries[k]["deps"].values())
        for k, e in entries.items():
            e["dev"] = k not in seen
    return list(entries.values())


# ----------------------------------------------------------------- helpers

def diff_entries(before, after):
    """Compare two entry lists by (name, version).

    Returns {"added": [(name, version)], "removed": [...], "refingerprinted": [...]}
    where each list is sorted; duplicates are kept (two installs of the same
    version at different paths count twice)."""
    from collections import Counter
    b = Counter((e["name"], e["version"]) for e in before)
    a = Counter((e["name"], e["version"]) for e in after)
    added = sorted((a - b).elements())
    removed = sorted((b - a).elements())
    fb = {}
    for e in before:
        fb.setdefault((e["name"], e["version"]), set()).add(e["fingerprint"])
    refp = set()
    for e in after:
        k = (e["name"], e["version"])
        if k in fb and e["fingerprint"] not in fb[k] and e["fingerprint"].strip("|"):
            refp.add(k)
    return {"added": added, "removed": removed, "refingerprinted": sorted(refp)}


def changes_as_list(d):
    """Render a diff_entries() result as [{"name", "from", "to"}] for people."""
    out = []
    removed = {}
    for n, v in d["removed"]:
        removed.setdefault(n, []).append(v)
    added = {}
    for n, v in d["added"]:
        added.setdefault(n, []).append(v)
    for n in sorted(set(removed) | set(added)):
        r, a = removed.get(n, []), added.get(n, [])
        while r or a:
            out.append({"name": n, "from": r.pop(0) if r else None, "to": a.pop(0) if a else None})
    return out
