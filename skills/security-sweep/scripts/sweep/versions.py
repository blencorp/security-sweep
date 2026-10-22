"""Version parsing, ordering and range matching.

Three schemes are needed:
  * npm semver (npm packages, Node.js releases)
  * Composer versions and constraints (Packagist packages, PHP releases)
  * dpkg and apk versions (distro packages, ordering only)

Everything here is pure and deterministic so it can be unit tested in depth.
"""

import re

# ---------------------------------------------------------------------------
# npm semver
# ---------------------------------------------------------------------------

_SEMVER = re.compile(
    r"^\s*[v=]?\s*(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


class SemVer(object):
    __slots__ = ("major", "minor", "patch", "pre", "raw")

    def __init__(self, major, minor, patch, pre=(), raw=None):
        self.major, self.minor, self.patch = major, minor, patch
        self.pre = tuple(pre)
        self.raw = raw or "%d.%d.%d%s" % (
            major, minor, patch, ("-" + ".".join(str(p) for p in pre)) if pre else "")

    def key(self):
        # A release sorts after any prerelease of the same version.
        pre = tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in self.pre)
        return (self.major, self.minor, self.patch, 0 if self.pre else 1, pre)

    def __lt__(self, other):
        return self.key() < other.key()

    def __le__(self, other):
        return self.key() <= other.key()

    def __gt__(self, other):
        return self.key() > other.key()

    def __ge__(self, other):
        return self.key() >= other.key()

    def __eq__(self, other):
        return isinstance(other, SemVer) and self.key() == other.key()

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return "SemVer(%s)" % self.raw

    def __str__(self):
        return self.raw

    @property
    def is_prerelease(self):
        return bool(self.pre)


def parse_semver(text):
    """Parse a full semver string. Returns None when it is not one."""
    if text is None:
        return None
    m = _SEMVER.match(str(text))
    if not m:
        return None
    pre = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)), pre, str(text).strip().lstrip("v="))


def semver_key(text):
    v = parse_semver(text)
    return v.key() if v else (-1,)


_XR = r"(?:[xX*]|\d+)"
_PARTIAL = re.compile(
    r"^[v=]?(" + _XR + r")(?:\.(" + _XR + r")(?:\.(" + _XR + r")"
    r"(?:-([0-9A-Za-z.-]+))?)?)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _partial(text):
    m = _PARTIAL.match(text.strip())
    if not m:
        raise ValueError("bad version in range: %r" % text)
    parts = []
    for g in m.group(1, 2, 3):
        if g is None or g in ("x", "X", "*"):
            parts.append(None)
        else:
            parts.append(int(g))
    # Anything after a wildcard is a wildcard too.
    for i in range(3):
        if parts[i] is None:
            parts[i + 1:] = [None] * (2 - i)
            break
    pre = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    return parts[0], parts[1], parts[2], pre


def _v(maj, mi, pa, pre=()):
    return SemVer(maj or 0, mi or 0, pa or 0, pre)


class _Cmp(object):
    __slots__ = ("op", "ver")

    def __init__(self, op, ver):
        self.op, self.ver = op, ver

    def test(self, v):
        k, o = v.key(), self.ver.key()
        return {
            ">": k > o, ">=": k >= o, "<": k < o, "<=": k <= o, "=": k == o,
        }[self.op]


def _expand_simple(op, text):
    """Turn one npm comparator (with ^, ~, x-ranges) into primitive comparators."""
    maj, mi, pa, pre = _partial(text)
    if op in ("", "="):
        if maj is None:
            return []  # '*' matches anything
        if mi is None:
            return [_Cmp(">=", _v(maj, 0, 0)), _Cmp("<", _v(maj + 1, 0, 0, (0,)))]
        if pa is None:
            return [_Cmp(">=", _v(maj, mi, 0)), _Cmp("<", _v(maj, mi + 1, 0, (0,)))]
        return [_Cmp("=", _v(maj, mi, pa, pre))]
    if op == "^":
        if maj is None:
            return []
        lo = _v(maj, mi, pa, pre)
        if maj > 0 or mi is None:
            hi = _v(maj + 1, 0, 0, (0,))
        elif mi > 0 or pa is None:
            hi = _v(0, mi + 1, 0, (0,))
        else:
            hi = _v(0, 0, pa + 1, (0,))
        return [_Cmp(">=", lo), _Cmp("<", hi)]
    if op == "~":
        if maj is None:
            return []
        lo = _v(maj, mi, pa, pre)
        hi = _v(maj + 1, 0, 0, (0,)) if mi is None else _v(maj, mi + 1, 0, (0,))
        return [_Cmp(">=", lo), _Cmp("<", hi)]
    if op in (">", "<=") and maj is not None and (mi is None or pa is None):
        # >1.2 means >=1.3.0 ; <=1.2 means <1.3.0
        nxt = _v(maj + 1, 0, 0) if mi is None else _v(maj, mi + 1, 0)
        return [_Cmp(">=" if op == ">" else "<", nxt)]
    if maj is None:
        return [] if op in (">=", "<=") else [_Cmp("<", _v(0, 0, 0, (0,)))]
    return [_Cmp(op, _v(maj, mi, pa, pre))]


_TOKEN = re.compile(r"(\^|~>?|>=|<=|>|<|=)?\s*([^\s]+)")


def _parse_set(text):
    text = text.strip()
    hy = re.match(r"^(\S+)\s+-\s+(\S+)$", text)
    if hy:
        a = _partial(hy.group(1))
        b = _partial(hy.group(2))
        cmps = [] if a[0] is None else [_Cmp(">=", _v(*a))]
        if b[0] is not None:
            if b[1] is None:
                cmps.append(_Cmp("<", _v(b[0] + 1, 0, 0, (0,))))
            elif b[2] is None:
                cmps.append(_Cmp("<", _v(b[0], b[1] + 1, 0, (0,))))
            else:
                cmps.append(_Cmp("<=", _v(*b)))
        return cmps
    cmps = []
    for m in _TOKEN.finditer(text):
        op = (m.group(1) or "").replace("~>", "~")
        cmps.extend(_expand_simple(op, m.group(2)))
    return cmps


def parse_npm_range(text):
    """Parse an npm range into a list of comparator sets (OR of ANDs).

    Raises ValueError for things that are not ranges (tags, URLs, git specs)."""
    text = (text or "").strip()
    if text in ("", "*", "latest", "x", "X"):
        return [[]]
    if re.search(r"[:/#]", text) and not text.startswith("npm:"):
        raise ValueError("not a semver range: %r" % text)
    if text.startswith("npm:"):
        text = text.rsplit("@", 1)[-1] if "@" in text[4:] else "*"
    # npm allows a space between operator and version (">= 1.2.3").
    text = re.sub(r"(\^|~>?|>=|<=|>|<|=)\s+", r"\1", text)
    return [_parse_set(part) for part in text.split("||")]


def npm_satisfies(version, rng):
    """True when the version is inside the range, with npm's prerelease rule:
    a prerelease only matches a comparator set that names the same
    major.minor.patch with a prerelease."""
    v = version if isinstance(version, SemVer) else parse_semver(version)
    if v is None:
        return False
    sets = rng if isinstance(rng, list) else parse_npm_range(rng)
    for cmps in sets:
        if all(c.test(v) for c in cmps):
            if v.pre:
                ok = any(c.ver.pre and (c.ver.major, c.ver.minor, c.ver.patch) ==
                         (v.major, v.minor, v.patch) for c in cmps)
                if not ok:
                    continue
            return True
    return False


# ---------------------------------------------------------------------------
# Composer
# ---------------------------------------------------------------------------

_STABILITY = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "": 4, "stable": 4,
              "patch": 5, "pl": 5, "p": 5}

_COMPOSER = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)(?:[.-]?(\d+))?)?"
    r"(?:[.-]?dev)?$",
    re.I,
)


class ComposerVersion(object):
    __slots__ = ("nums", "stab", "stab_n", "raw")

    def __init__(self, nums, stab, stab_n, raw):
        self.nums, self.stab, self.stab_n, self.raw = nums, stab, stab_n, raw

    def key(self):
        return self.nums + (self.stab, self.stab_n)

    def __lt__(self, o):
        return self.key() < o.key()

    def __le__(self, o):
        return self.key() <= o.key()

    def __gt__(self, o):
        return self.key() > o.key()

    def __ge__(self, o):
        return self.key() >= o.key()

    def __eq__(self, o):
        return isinstance(o, ComposerVersion) and self.key() == o.key()

    def __ne__(self, o):
        return not self == o

    def __hash__(self):
        return hash(self.key())

    def __repr__(self):
        return "ComposerVersion(%s)" % self.raw

    def __str__(self):
        return self.raw

    @property
    def major(self):
        return self.nums[0]

    @property
    def minor(self):
        return self.nums[1]

    @property
    def is_prerelease(self):
        return self.stab < 4


def parse_composer(text):
    """Parse a Composer version ('v1.2.3', '1.2.3.0', '2.0.0-RC1').

    Branch versions ('dev-main', '1.x-dev') return None: they have no order."""
    if text is None:
        return None
    t = str(text).strip()
    if t.lower().startswith("dev-") or t.lower().endswith(".x-dev") or "x-dev" in t.lower():
        return None
    m = _COMPOSER.match(t)
    if not m:
        return None
    nums = tuple(int(g) if g is not None else 0 for g in m.group(1, 2, 3, 4))
    stab_word = (m.group(5) or "").lower()
    stab = _STABILITY[stab_word]
    if t.lower().endswith("dev") and not stab_word:
        stab = 0
    stab_n = int(m.group(6)) if m.group(6) else 0
    return ComposerVersion(nums, stab, stab_n, t)


def composer_key(text):
    v = parse_composer(text)
    return v.key() if v else (-1,)


def _cv(nums, stab=4, n=0):
    nums = tuple(nums) + (0,) * (4 - len(nums))
    return ComposerVersion(nums, stab, n, ".".join(str(x) for x in nums))


def _composer_simple(op, text):
    text = text.strip()
    text = re.sub(r"@(dev|alpha|beta|rc|stable)$", "", text, flags=re.I)
    if text in ("*", ""):
        return []
    wild = re.match(r"^v?(\d+(?:\.\d+)*)\.[x*]$", text, re.I)
    if wild:
        parts = [int(x) for x in wild.group(1).split(".")]
        hi = parts[:-1] + [parts[-1] + 1]
        return [_Cmp(">=", _cv(parts, 0)), _Cmp("<", _cv(hi, 0))]
    v = parse_composer(text)
    if v is None:
        raise ValueError("bad composer version: %r" % text)
    given = len([p for p in re.split(r"[.]", re.sub(r"[-_].*$", "", text.lstrip("vV"))) if p != ""])
    nums = list(v.nums)
    if op == "^":
        lo = v
        # ^1.2.3 -> <2.0.0 ; ^0.3 -> <0.4 ; ^0.0.3 -> <0.0.4
        idx = 0
        while idx < min(given, 3) - 1 and nums[idx] == 0:
            idx += 1
        hi = nums[:idx] + [nums[idx] + 1]
        return [_Cmp(">=", ComposerVersion(lo.nums, lo.stab if lo.stab != 4 else 0, lo.stab_n, lo.raw)),
                _Cmp("<", _cv(hi, 0))]
    if op == "~":
        lo = v
        cut = max(given - 1, 1)
        hi = nums[:cut - 1] + [nums[cut - 1] + 1]
        return [_Cmp(">=", ComposerVersion(lo.nums, lo.stab if lo.stab != 4 else 0, lo.stab_n, lo.raw)),
                _Cmp("<", _cv(hi, 0))]
    if op == "!=":
        return [_NotEq(v)]
    if op in ("", "=", "=="):
        return [_Cmp("=", v)]
    return [_Cmp(op, v)]


class _NotEq(object):
    def __init__(self, ver):
        self.ver = ver

    def test(self, v):
        return v.key() != self.ver.key()


def parse_composer_constraint(text):
    """Parse a Composer constraint into OR-of-AND comparator lists."""
    text = (text or "").strip()
    out = []
    for alt in re.split(r"\s*\|\|?\s*", text):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            out.append([_Cmp(">=", parse_composer(hy.group(1))), _Cmp("<=", parse_composer(hy.group(2)))])
            continue
        alt = re.sub(r"(\^|~|>=|<=|!=|==|>|<|=)\s+", r"\1", alt)
        cmps = []
        for tok in re.split(r"\s*,\s*|\s+", alt):
            if not tok:
                continue
            m = re.match(r"^(\^|~|>=|<=|!=|==|>|<|=)?(.*)$", tok)
            cmps.extend(_composer_simple(m.group(1) or "", m.group(2)))
        out.append(cmps)
    return out


def composer_satisfies(version, constraint):
    v = version if isinstance(version, ComposerVersion) else parse_composer(version)
    if v is None:
        return False
    sets = constraint if isinstance(constraint, list) else parse_composer_constraint(constraint)
    return any(all(c.test(v) for c in cmps) for cmps in sets)


# ---------------------------------------------------------------------------
# Scheme dispatch used by the rest of the code
# ---------------------------------------------------------------------------

def parse(ecosystem, text):
    if ecosystem in ("npm", "node"):
        return parse_semver(text)
    if ecosystem in ("Packagist", "php"):
        return parse_composer(text)
    raise ValueError("unknown ecosystem %r" % ecosystem)


def same_line(ecosystem, a, b):
    """Same major (or same minor while the major is 0): no breaking change
    is expected between a and b under semver."""
    va, vb = parse(ecosystem, a), parse(ecosystem, b)
    if va is None or vb is None:
        return False
    if va.major != vb.major:
        return False
    if va.major == 0:
        return va.minor == vb.minor
    return True


def satisfies(ecosystem, version, rng):
    if ecosystem == "npm":
        return npm_satisfies(version, rng)
    return composer_satisfies(version, rng)


# ---------------------------------------------------------------------------
# dpkg (Debian, Ubuntu) and apk (Alpine) ordering
# ---------------------------------------------------------------------------

def _dpkg_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _dpkg_cmp_part(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _dpkg_split(v):
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, "0"
    return epoch, up, rev


def dpkg_compare(a, b):
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _dpkg_cmp_part(ua, ub)
    if c:
        return c
    return _dpkg_cmp_part(ra, rb)


def apk_compare(a, b):
    def split(v):
        rel = 0
        m = re.match(r"^(.*?)-r(\d+)$", v)
        if m:
            v, rel = m.group(1), int(m.group(2))
        parts = re.findall(r"\d+|[a-z]+|_[a-z]+\d*", v)
        key = []
        for p in parts:
            if p.isdigit():
                key.append((1, int(p), ""))
            elif p.startswith("_"):
                # _alpha/_beta/_pre/_rc sort before the release, _p after.
                key.append((0 if p[1:2] != "p" or p.startswith("_pre") else 2, 0, p))
            else:
                key.append((1, 0, p))
        return key, rel

    ka, ra = split(a)
    kb, rb = split(b)
    if ka != kb:
        return -1 if ka < kb else 1
    if ra != rb:
        return -1 if ra < rb else 1
    return 0
