"""Package registries: every published version of a package, with the facts
the safety checks need (publish time, deprecation, install scripts, type).

Versions published after the current clock are dropped, so a recorded
registry response can be replayed "as of" an earlier date."""

import urllib.parse

from . import net, versions

NPM = "https://registry.npmjs.org"
PACKAGIST = "https://repo.packagist.org/p2"

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


class Release(object):
    __slots__ = ("version", "published", "deprecated", "install_scripts", "kind", "requires", "publisher")

    def __init__(self, version, published, deprecated=None, install_scripts=(), kind=None,
                 requires=None, publisher=None):
        self.version = version
        self.published = published
        self.deprecated = deprecated
        self.install_scripts = tuple(sorted(install_scripts))
        self.kind = kind
        self.requires = requires or {}
        self.publisher = publisher


_cache = {}


def releases(ecosystem, name):
    """{version string: Release} for every release published up to now()."""
    ck = (ecosystem, name)
    if ck not in _cache:
        if ecosystem == "npm":
            _cache[ck] = _npm(name)
        elif ecosystem == "Packagist":
            _cache[ck] = _packagist(name)
        else:
            raise ValueError(ecosystem)
    cutoff = net.now()
    return {v: r for v, r in _cache[ck].items() if r.published is None or r.published <= cutoff}


def _npm(name):
    url = "%s/%s" % (NPM, urllib.parse.quote(name, safe="@"))
    data = net.get_json(url, source="npm registry")
    times = data.get("time") or {}
    out = {}
    for v, meta in (data.get("versions") or {}).items():
        scripts = meta.get("scripts") or {}
        hooks = [s for s in INSTALL_SCRIPTS if s in scripts]
        # npm adds an implicit "node-gyp rebuild" install step for binding.gyp.
        if meta.get("gypfile") and "install" not in hooks:
            hooks.append("install")
        req = {}
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            req.update(meta.get(k) or {})
        out[v] = Release(
            v, net.parse_time(times.get(v)), meta.get("deprecated") or None, hooks, None,
            req, (meta.get("_npmUser") or {}).get("name"))
    return out


def _expand_minified(entries):
    """Composer 2 metadata is 'minified': each entry only lists fields that
    changed from the previous one; '__unset' deletes a field."""
    out = []
    prev = {}
    for e in entries:
        cur = dict(prev)
        for k, v in e.items():
            if v == "__unset":
                cur.pop(k, None)
            else:
                cur[k] = v
        out.append(cur)
        prev = cur
    return out


def _packagist(name):
    data = net.get_json("%s/%s.json" % (PACKAGIST, name.lower()), source="Packagist")
    raw = (data.get("packages") or {}).get(name.lower()) or []
    if data.get("minified") == "composer/2.0":
        raw = _expand_minified(raw)
    out = {}
    for meta in raw:
        v = meta.get("version")
        if not v or versions.parse_composer(v) is None:
            continue
        req = {k.lower(): c for k, c in (meta.get("require") or {}).items()}
        out[v] = Release(v, net.parse_time(meta.get("time")), meta.get("abandoned") or None, (),
                         meta.get("type", "library"), req, None)
    return out


def find(ecosystem, name, version):
    """The Release for an installed version. Composer lockfiles may write
    'v1.2.3' where Packagist says '1.2.3' (or the reverse)."""
    rel = releases(ecosystem, name)
    if version in rel:
        return rel[version]
    if ecosystem == "Packagist":
        target = versions.composer_key(version)
        for v, r in rel.items():
            if versions.composer_key(v) == target:
                return r
    # The installed version may have been published after a replayed clock.
    allrel = _cache.get((ecosystem, name)) or {}
    return allrel.get(version)
