"""Private package names never go to public services.

Patterns come from `--private` flags, the SECURITY_SWEEP_PRIVATE environment
variable (comma-separated), and a `.security-sweep.json` file in the project
root: {"private": ["@acme/*", "acme/*"]}. They are shell-style globs matched
against package names (case-insensitive).

Matching packages are removed from the lockfile copy that osv-scanner reads,
and no registry or OSV request is made for them. They are reported as not
checked by public sources.
"""

import fnmatch
import json
import os
import re

CONFIG_FILE = ".security-sweep.json"


def load_patterns(repo, cli=()):
    pats = list(cli or [])
    env = os.environ.get("SECURITY_SWEEP_PRIVATE", "")
    pats += [p.strip() for p in env.split(",") if p.strip()]
    path = os.path.join(repo, CONFIG_FILE)
    if os.path.isfile(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except ValueError as e:
            raise ValueError("%s is not valid JSON: %s" % (CONFIG_FILE, e))
        private = data.get("private") or []
        if not isinstance(private, list) or not all(isinstance(p, str) for p in private):
            raise ValueError('%s: "private" must be a list of strings' % CONFIG_FILE)
        pats += private
    seen = []
    for p in pats:
        if p not in seen:
            seen.append(p)
    return seen


def is_private(name, patterns):
    n = (name or "").lower()
    return any(fnmatch.fnmatchcase(n, p.lower()) for p in patterns)


class LeakError(Exception):
    pass


def sanitize(manager, content, patterns):
    """Return (lockfile bytes without private packages, number removed).

    Fails closed: if a private package is still present after stripping,
    raise LeakError instead of returning content that would be sent out."""
    if not patterns:
        return content, 0
    from . import lockfiles
    out, _ = _sanitize(manager, content, patterns)
    left = sorted({e["name"] for e in lockfiles.parse(manager, out, None) if is_private(e["name"], patterns)})
    if left:
        raise LeakError("could not remove private packages %s from the lockfile copy; not scanning it"
                        % ", ".join(left))
    removed = len({(e["name"], e["version"]) for e in lockfiles.parse(manager, content, None)
                   if is_private(e["name"], patterns)})
    return out, removed


DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
            "peerDependenciesMeta", "requires", "require", "require-dev", "suggest", "provide", "replace", "conflict")


def _sanitize(manager, content, patterns):
    text = content.decode("utf-8")
    if manager == "npm":
        data = json.loads(text)
        removed = 0
        pk = data.get("packages")
        if pk is not None:
            for key in list(pk):
                if key and "node_modules/" in key:
                    name = pk[key].get("name") or key.rsplit("node_modules/", 1)[1]
                    if is_private(name, patterns) or is_private(key.rsplit("node_modules/", 1)[1], patterns):
                        del pk[key]
                        removed += 1
                        continue
                _strip_refs(pk[key], patterns)
        removed += _strip_v1(data.get("dependencies") or {}, patterns)
        return json.dumps(data).encode("utf-8"), removed
    if manager == "composer":
        data = json.loads(text)
        removed = 0
        for sec in ("packages", "packages-dev"):
            keep = [p for p in data.get(sec) or [] if not is_private(p.get("name"), patterns)]
            removed += len(data.get(sec) or []) - len(keep)
            for p in keep:
                _strip_refs(p, patterns)
            data[sec] = keep
        return json.dumps(data).encode("utf-8"), removed
    if manager in ("yarn-classic", "yarn-berry", "pnpm"):
        return _strip_text(text, patterns)
    return content, 0


def _strip_refs(entry, patterns):
    for k in DEP_KEYS:
        deps = entry.get(k)
        if isinstance(deps, dict):
            for n in list(deps):
                if is_private(n, patterns):
                    del deps[n]


def _strip_v1(deps, patterns):
    removed = 0
    for name in list(deps):
        if is_private(name, patterns):
            del deps[name]
            removed += 1
        else:
            _strip_refs(deps[name], patterns)
            removed += _strip_v1(deps[name].get("dependencies") or {}, patterns)
    return removed


_KEY = re.compile(r"""^(\s*)["']?/?((?:@[^/@"'\s]+/)?[^@"'/:\s(]+)""")


def _strip_text(text, patterns):
    """yarn.lock and pnpm-lock.yaml: drop every line whose key names a
    private package (a resolved entry, an importer entry or a dependency
    reference), together with the more-indented lines under it."""
    out, removed, skip_indent = [], 0, None
    for line in text.splitlines(True):
        body = line.rstrip("\r\n")
        indent = len(body) - len(body.lstrip(" "))
        if skip_indent is not None:
            if not body.strip() or indent > skip_indent:
                continue
            skip_indent = None
        m = _KEY.match(body)
        if body.strip() and not body.lstrip().startswith("#") and m and is_private(m.group(2), patterns):
            if indent == 0 or (indent == 2 and body.rstrip().endswith((":", "{}"))):
                removed += 1
            skip_indent = indent
            continue
        out.append(line)
    return "".join(out).encode("utf-8"), removed
