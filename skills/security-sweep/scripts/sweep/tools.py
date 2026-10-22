"""Pinned external tools. osv-scanner is downloaded once per version, checked
against the SHA-256 in tools.lock.json before every use, and never run if the
checksum does not match."""

import hashlib
import json
import os
import platform
import stat
import tempfile
import urllib.request

from . import net

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCK_PATH = os.path.join(SKILL_DIR, "tools.lock.json")


def load_lock():
    with open(LOCK_PATH) as f:
        return json.load(f)


def platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    return "%s-%s" % (system, arch)


def cache_dir():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "security-sweep", "tools")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def osv_scanner_spec():
    lock = load_lock()["osv-scanner"]
    key = platform_key()
    plat = lock["platforms"].get(key)
    if not plat:
        raise net.SourceError("osv-scanner", "no pinned build for platform %s" % key)
    return lock["version"], lock["url"].format(file=plat["file"]), plat["sha256"], plat["file"]


def ensure_osv_scanner(download=True):
    """Return the path to a verified osv-scanner binary.

    SECURITY_SWEEP_OSV_SCANNER may point at an existing binary (for example in
    CI); it must still match the pinned checksum."""
    version, url, sha, fname = osv_scanner_spec()
    override = os.environ.get("SECURITY_SWEEP_OSV_SCANNER")
    path = override or os.path.join(cache_dir(), version, fname)
    if os.path.isfile(path):
        actual = sha256_file(path)
        if actual != sha:
            raise net.SourceError("osv-scanner", "checksum mismatch for %s (expected %s, got %s); "
                                  "refusing to run it" % (path, sha, actual))
        return path
    if override:
        raise net.SourceError("osv-scanner", "SECURITY_SWEEP_OSV_SCANNER points at a missing file: %s" % path)
    if not download:
        raise net.SourceError("osv-scanner", "not installed; run: security_sweep.py tools install")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": net.USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp, os.fdopen(fd, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
        except OSError as e:
            raise net.SourceError("osv-scanner", "download failed: %s" % e)
        actual = sha256_file(tmp)
        if actual != sha:
            raise net.SourceError("osv-scanner", "downloaded file checksum mismatch (expected %s, got %s)"
                                  % (sha, actual))
        os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def osv_scan_lockfile(basename, content):
    """Scan one lockfile's content with osv-scanner and return parsed JSON.

    The lockfile is copied into a scratch directory under its own basename so
    the scan never reads anything else from the project."""
    mode = os.environ.get("SECURITY_SWEEP_REPLAY")
    binary = None if mode else ensure_osv_scanner()
    res = net.run_tool(
        "osv-scanner",
        [["scan", "source", "--lockfile", basename, "--format", "json", "--verbosity", "error"]],
        {basename: content}, [], binary=binary)
    # 0 = nothing found, 1 = vulnerabilities found, 128 = no packages found.
    if res.code not in (0, 1, 128):
        raise net.SourceError("osv-scanner", "exit %s: %s" % (res.code, res.stderr.strip()[-500:]))
    if res.code == 128 or not res.stdout.strip():
        return {"results": []}
    try:
        return json.loads(res.stdout)
    except ValueError:
        raise net.SourceError("osv-scanner", "output is not JSON")
