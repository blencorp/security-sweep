"""Project snapshots: a hash of every project file, taken at plan time, so
`check` can list exactly what changed and `revert` can restore the files a
fix was allowed to touch.

Installed dependency directories (node_modules, vendor) and git-ignored
files are excluded: they change on every install or test run and are not
part of the project's source."""

import hashlib
import os
import shutil
import subprocess

from . import lockfiles


def _git_files(repo):
    if not os.path.isdir(os.path.join(repo, ".git")) or not shutil.which("git"):
        return None
    try:
        out = subprocess.run(["git", "-C", repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120, check=True).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    files = []
    for rel in out.decode("utf-8", "replace").split("\0"):
        if not rel:
            continue
        parts = rel.split("/")
        if any(p in lockfiles.SKIP_DIRS for p in parts[:-1]):
            continue
        files.append(rel)
    return files


def project_files(repo):
    files = _git_files(repo)
    if files is None:
        files = list(lockfiles.walk(repo))
    return sorted(files)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def take(repo):
    """{relative path: sha256} for the project as it is now."""
    out = {}
    for rel in project_files(repo):
        p = os.path.join(repo, rel)
        if os.path.isfile(p) and not os.path.islink(p):
            out[rel] = sha256(p)
        elif os.path.islink(p):
            out[rel] = "symlink:" + os.readlink(p)
    return out


def compare(before, after):
    """Return [{"path", "change": modified|added|deleted}] sorted by path."""
    out = []
    for rel in sorted(set(before) | set(after)):
        if rel not in after:
            out.append({"path": rel, "change": "deleted"})
        elif rel not in before:
            out.append({"path": rel, "change": "added"})
        elif before[rel] != after[rel]:
            out.append({"path": rel, "change": "modified"})
    return out


def git_tracked(repo, rel):
    if not os.path.isdir(os.path.join(repo, ".git")) or not shutil.which("git"):
        return False
    r = subprocess.run(["git", "-C", repo, "ls-files", "--error-unmatch", "--", rel],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0
