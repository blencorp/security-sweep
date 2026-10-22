"""Where run output lives. Never inside the user's project: by default
~/.security-sweep/<project>-<hash>/, or SECURITY_SWEEP_HOME, or --out."""

import hashlib
import json
import os
import tempfile


def base_dir():
    return os.environ.get("SECURITY_SWEEP_HOME") or os.path.join(os.path.expanduser("~"), ".security-sweep")


def run_dir(repo, out=None):
    if out:
        return os.path.abspath(out)
    repo = os.path.realpath(repo)
    tag = hashlib.sha256(repo.encode("utf-8")).hexdigest()[:8]
    name = os.path.basename(repo.rstrip(os.sep)) or "root"
    return os.path.join(base_dir(), "%s-%s" % (name, tag))


def check_outside(repo, path):
    """Refuse an output directory inside the project: it would show up as a
    change outside every fix's footprint."""
    r = os.path.realpath(repo) + os.sep
    p = os.path.realpath(path) + os.sep
    if p.startswith(r):
        raise ValueError("output directory %s is inside the project; choose a path outside it" % path)


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def read_json(path):
    with open(path) as f:
        return json.load(f)


def next_seq(run_dir):
    """A counter that orders plans and check results within a run directory
    (wall-clock time is not reliable for this; tests pin the clock)."""
    path = os.path.join(run_dir, "seq")
    n = 0
    if os.path.exists(path):
        with open(path) as f:
            n = int(f.read().strip() or 0)
    n += 1
    write_text(path, str(n))
    return n
