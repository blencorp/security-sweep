"""All network access and external tool runs go through this module.

Three modes, chosen by environment variables:

  live    (default)                   real HTTP and real tool runs
  record  SECURITY_SWEEP_RECORD=<dir> live, and every response is saved to <dir>
  replay  SECURITY_SWEEP_REPLAY=<dir> nothing leaves the machine; responses come
                                      from <dir>; a missing one is a failure

Replay exists for the test suite. The CLI itself is online only: a source that
cannot be reached raises SourceError, and the caller marks the run INCOMPLETE.

The clock is injectable the same way (SECURITY_SWEEP_NOW=2024-05-01T00:00:00Z)
so cooldown and "published after now" rules can be tested against recorded data.
"""

import base64
import datetime
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from . import __version__

USER_AGENT = "security-sweep/%s (+https://github.com/blencorp/security-sweep)" % __version__


class SourceError(Exception):
    """A data source or tool could not give an answer. Makes the run INCOMPLETE."""

    def __init__(self, source, message):
        Exception.__init__(self, "%s: %s" % (source, message))
        self.source = source
        self.message = message


class NotFound(SourceError):
    """The source answered, and the answer is 404."""


def now():
    fixed = os.environ.get("SECURITY_SWEEP_NOW")
    if fixed:
        return parse_time(fixed)
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(text):
    """Parse ISO 8601 timestamps as found in registries and feeds."""
    if text is None:
        return None
    t = str(text).strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    # Python 3.9 fromisoformat does not accept more than 6 fractional digits.
    if "." in t:
        head, rest = t.split(".", 1)
        frac = ""
        tz = ""
        for i, ch in enumerate(rest):
            if not ch.isdigit():
                tz = rest[i:]
                break
            frac += ch
        t = head + "." + (frac[:6] or "0") + tz
    try:
        d = datetime.datetime.fromisoformat(t)
    except ValueError:
        try:
            d = datetime.datetime.strptime(str(text).strip(), "%d %b %Y")
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d


def _mode():
    if os.environ.get("SECURITY_SWEEP_REPLAY"):
        return "replay", os.environ["SECURITY_SWEEP_REPLAY"]
    if os.environ.get("SECURITY_SWEEP_RECORD"):
        return "record", os.environ["SECURITY_SWEEP_RECORD"]
    return "live", None


def _key(*parts):
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            p = p.encode("utf-8")
        h.update(p)
        h.update(b"\0")
    return h.hexdigest()[:32]


def _save(dirname, key, record):
    os.makedirs(dirname, exist_ok=True)
    path = os.path.join(dirname, key + ".json.gz")
    tmp = path + ".tmp"
    with gzip.GzipFile(tmp, "wb", mtime=0) as f:
        f.write(json.dumps(record, sort_keys=True, indent=1).encode("utf-8"))
    os.replace(tmp, path)


def _load(dirname, key, what):
    path = os.path.join(dirname, key + ".json.gz")
    if not os.path.exists(path):
        raise SourceError(what, "no recorded response (replay mode, key %s)" % key)
    with gzip.open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


_memo = {}


def request(url, method="GET", body=None, headers=None, source=None, timeout=60):
    """Return response bytes. 404 raises NotFound; anything else that is not
    a 2xx after retries raises SourceError."""
    source = source or url.split("/")[2]
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body, sort_keys=True).encode("utf-8")
    hdrs = {"User-Agent": USER_AGENT}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    mkey = _key(method, url, data or b"", json.dumps(sorted(hdrs.items())))
    if mkey in _memo:
        status, payload = _memo[mkey]
    else:
        mode, d = _mode()
        rkey = _key(method, url, data or b"")
        if mode == "replay":
            rec = _load(d, rkey, source)
            status, payload = rec["status"], base64.b64decode(rec["body"])
        else:
            status, payload = _http(url, method, data, hdrs, source, timeout)
            if mode == "record":
                _save(d, rkey, {"url": url, "method": method, "status": status,
                                "body": base64.b64encode(payload).decode("ascii")})
        _memo[mkey] = (status, payload)
    if status == 404:
        raise NotFound(source, "404 for %s" % url)
    if not 200 <= status < 300:
        raise SourceError(source, "HTTP %s for %s" % (status, url))
    return payload


def _http(url, method, data, hdrs, source, timeout):
    last = None
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return resp.status, raw
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, b""
            last = "HTTP %s" % e.code
            if e.code not in (408, 425, 429, 500, 502, 503, 504):
                return e.code, b""
        except (urllib.error.URLError, OSError) as e:
            last = str(getattr(e, "reason", e))
        time.sleep(min(2 ** attempt, 8))
    raise SourceError(source, "unreachable (%s)" % last)


def get_json(url, source=None, headers=None):
    raw = request(url, headers=headers, source=source)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise SourceError(source or url, "response is not JSON")


def post_json(url, body, source=None):
    raw = request(url, method="POST", body=body, source=source)
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise SourceError(source or url, "response is not JSON")


def get_text(url, source=None):
    return request(url, source=source).decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# External tool runs (osv-scanner, npm, composer, pnpm) in a scratch directory
# ---------------------------------------------------------------------------

class ToolResult(object):
    def __init__(self, code, stdout, stderr, files):
        self.code, self.stdout, self.stderr, self.files = code, stdout, stderr, files


def run_tool(name, steps, inputs, outputs, env=None, binary=None, timeout=600):
    """Run a tool in a fresh scratch directory and return its result.

    steps    list of argument lists (after the program name), run in order in
             the same scratch dir; stops at the first non-zero exit
    inputs   {relative path: bytes} written into the scratch dir first
    outputs  relative paths whose content after the run is returned
    binary   path to the executable (defaults to looking up `name` on PATH)

    The project directory is never the working directory, so a tool cannot
    touch the user's files. In record/replay mode the result is keyed by the
    command and the exact input bytes.
    """
    mode, d = _mode()
    parts = [name]
    for argv in steps:
        parts.extend(list(argv) + ["\x1e"])
    for rel in sorted(inputs):
        parts.extend([rel, inputs[rel]])
    rkey = _key(*parts)
    if mode == "replay":
        rec = _load(d, rkey, name)
        files = {k: (base64.b64decode(v) if v is not None else None) for k, v in rec["files"].items()}
        return ToolResult(rec["code"], rec["stdout"], rec["stderr"], files)

    exe = binary or shutil.which(name)
    if not exe:
        raise SourceError(name, "%s is not installed or not on PATH" % name)
    scratch = tempfile.mkdtemp(prefix="security-sweep-")
    try:
        for rel, content in inputs.items():
            p = os.path.join(scratch, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(content)
        full_env = dict(os.environ)
        full_env.update(env or {})
        code, out, err = 0, b"", b""
        for argv in steps:
            try:
                proc = subprocess.run([exe] + list(argv), cwd=scratch, env=full_env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=timeout)
            except subprocess.TimeoutExpired:
                raise SourceError(name, "timed out after %ss" % timeout)
            code, out, err = proc.returncode, out + proc.stdout, err + proc.stderr
            if code != 0:
                break
        files = {}
        for rel in outputs:
            p = os.path.join(scratch, rel)
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    files[rel] = f.read()
            else:
                files[rel] = None
        res = ToolResult(code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), files)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if mode == "record":
        _save(d, rkey, {"argv": [name] + [list(a) for a in steps], "code": res.code, "stdout": res.stdout,
                        "stderr": res.stderr[-20000:],
                        "files": {k: (base64.b64encode(v).decode("ascii") if v is not None else None)
                                  for k, v in res.files.items()}})
    return res
