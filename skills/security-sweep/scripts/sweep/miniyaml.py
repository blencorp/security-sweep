"""A small block-YAML reader for pnpm-lock.yaml and Yarn Berry's yarn.lock.

It handles what those files use: nested block mappings, block sequences,
single- and double-quoted scalars, and inline flow collections (returned as
their raw text, which is enough here). It is not a general YAML parser.
"""


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        inner = s[1:-1]
        if s[0] == "'":
            return inner.replace("''", "'")
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return s


def _split_key(line):
    """Split 'key: value' respecting quotes. Returns (key, rest) or (None, line)."""
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
            continue
        if ch in "'\"":
            q = ch
        elif ch == ":" and (i + 1 == len(line) or line[i + 1] == " "):
            return _unquote(line[:i]), line[i + 1:].strip()
    return None, line


def _strip_comment(line):
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
            continue
        if ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] == " "):
            return line[:i].rstrip()
    return line.rstrip()


def loads(text):
    lines = []
    for raw in text.splitlines():
        if raw.lstrip().startswith("#") or not raw.strip() or raw.strip() == "---":
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        lines.append((len(line) - len(line.lstrip(" ")), line.strip()))
    value, _ = _parse(lines, 0, 0)
    return value if value is not None else {}


def _scalar(s):
    if s in ("", "~", "null"):
        return None
    if s.startswith(("'", '"')):
        return _unquote(s)
    if s in ("true", "false"):
        return s == "true"
    return s


def _parse(lines, i, indent):
    if i >= len(lines):
        return None, i
    ind, content = lines[i]
    if content.startswith("- ") or content == "-":
        out = []
        while i < len(lines) and lines[i][0] == ind and (lines[i][1].startswith("- ") or lines[i][1] == "-"):
            item = lines[i][1][2:].strip()
            k, rest = _split_key(item) if item else (None, "")
            if k is not None:
                # "- key: value" starts a mapping inside the list item
                sub = [(ind + 2, item)]
                j = i + 1
                while j < len(lines) and lines[j][0] > ind:
                    sub.append(lines[j])
                    j += 1
                val, _ = _parse(sub, 0, ind + 2)
                out.append(val)
                i = j
            else:
                i += 1
                if item:
                    out.append(_scalar(item))
                else:
                    val, i = _parse(lines, i, ind + 1)
                    out.append(val)
        return out, i
    out = {}
    while i < len(lines) and lines[i][0] == ind:
        k, rest = _split_key(lines[i][1])
        if k is None:
            i += 1
            continue
        i += 1
        if rest == "" or rest in ("|", ">", "|-", ">-"):
            if i < len(lines) and lines[i][0] > ind:
                val, i = _parse(lines, i, lines[i][0])
            elif i < len(lines) and lines[i][0] == ind and lines[i][1].startswith("- "):
                val, i = _parse(lines, i, ind)
            else:
                val = None
            out[k] = val
        else:
            out[k] = _scalar(rest)
    return out, i
