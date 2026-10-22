"""Compute a fix's footprint without touching the project.

Only the manifest, the lockfile and the package manager's config files are
copied to a scratch directory. The fix commands run there in lockfile-only
mode with scripts and plugins disabled, so no package is installed and no
package code runs. The difference between before and after is the footprint.

The agent later runs the very same commands in the project (they are already
lockfile-only), followed by one install step that must not change the
lockfile. That keeps the real change byte-for-byte equal to the computed one.
"""

import json
import os
import re

from . import lockfiles, net

CONFIG_FILES = {
    "npm": [".npmrc"],
    "pnpm": [".npmrc", "pnpm-workspace.yaml"],
    "composer": ["auth.json"],
}

NPM_FLAGS = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
PNPM_FLAGS = ["--lockfile-only", "--ignore-scripts", "--ignore-pnpmfile"]
# ext-* requirements are ignored only while resolving: the machine computing
# the footprint is not production. `composer install` still enforces them.
COMPOSER_FLAGS = ["--no-install", "--no-scripts", "--no-plugins", "--no-interaction", "--no-audit",
                  "--ignore-platform-req=ext-*"]

MATERIALIZE = {
    "npm": ["npm", "ci"],
    "pnpm": ["pnpm", "install", "--frozen-lockfile"],
    "composer": ["composer", "install"],
}

TOOL_ENV = {
    "npm": {"npm_config_update_notifier": "false", "npm_config_loglevel": "error"},
    "pnpm": {"npm_config_update_notifier": "false"},
    "composer": {"COMPOSER_NO_INTERACTION": "1", "COMPOSER_NO_AUDIT": "1"},
}


class Unavailable(Exception):
    pass


def tool_of(manager):
    if manager in ("npm", "pnpm", "composer"):
        return manager
    raise Unavailable("%s cannot update its lockfile without installing packages, so the footprint "
                      "cannot be computed in advance" % manager)


def gather_inputs(repo, lockfile, manifest, manager):
    """{path relative to the lockfile's directory: bytes}."""
    base = os.path.dirname(lockfile)
    rels = [os.path.basename(lockfile)]
    if manifest:
        rels.append(os.path.basename(manifest))
    rels += CONFIG_FILES.get(manager, [])
    if manager == "npm":
        # Workspace members are needed for npm to resolve the root lockfile.
        try:
            data = lockfiles.read_json(os.path.join(repo, lockfile))
            for key in (data.get("packages") or {}):
                if key and "node_modules/" not in key:
                    rels.append(key + "/package.json")
        except (ValueError, OSError):
            pass
    out = {}
    for rel in rels:
        p = os.path.join(repo, base, rel)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                out[rel] = f.read()
    return out


def composer_version():
    res = net.run_tool("composer", [["--version", "--no-ansi"]], {}, [], env=TOOL_ENV["composer"])
    m = re.search(r"Composer (?:version )?(\d+)\.(\d+)\.(\d+)", res.stdout + res.stderr)
    if not m:
        raise net.SourceError("composer", "cannot read composer --version")
    return tuple(int(x) for x in m.groups())


def composer_flags():
    flags = list(COMPOSER_FLAGS)
    v = composer_version()
    if v < (2, 2, 0):
        raise net.SourceError("composer", "Composer %d.%d.%d is too old; --with needs 2.2 or newer" % v)
    if v >= (2, 9, 0):
        # Composer 2.9+ refuses any version that still has *any* advisory.
        # The chosen version fixes the critical issue; lesser advisories it
        # still has are listed in the plan. Limited to the packages named in
        # this update (no -W), so nothing else is affected.
        flags.append("--no-blocking")
    return flags


def compute(repo, issue, steps, edit=None):
    """Run `steps` (argv lists, including the program name) in a scratch copy.

    `edit(inputs) -> {rel: bytes}` optionally rewrites config files (paths
    relative to the lockfile's directory) before the steps run; the agent
    makes the same edit by writing the exact content the plan shows.

    Returns {"ok", "error", "files": {rel: (before, after)}, "before", "after",
    "edits": {project-relative path: bytes}}."""
    manager = issue["manager"]
    tool = tool_of(manager)
    lockfile, manifest = issue["lockfile"], issue.get("manifest")
    original = gather_inputs(repo, lockfile, manifest, manager)
    inputs = dict(original)
    lock_rel = os.path.basename(lockfile)
    man_rel = os.path.basename(manifest) if manifest else None
    outputs = [lock_rel] + ([man_rel] if man_rel else [])
    edits = edit(dict(original)) if edit else {}
    for rel, content in edits.items():
        inputs[rel] = content
        if rel not in outputs:
            outputs.append(rel)
    for s in steps:
        if s[0] != tool:
            raise ValueError("step %r does not use %s" % (s, tool))
    res = net.run_tool(tool, [s[1:] for s in steps], inputs, outputs, env=TOOL_ENV.get(tool))
    if res.code != 0:
        msg = (res.stderr.strip() or res.stdout.strip())[-1500:]
        return {"ok": False, "error": "%s exited %s: %s" % (" ".join(steps[-1]), res.code, msg)}
    manifest_json = json.loads(res.files[man_rel].decode("utf-8")) if man_rel and res.files.get(man_rel) else None
    old_manifest = json.loads(original[man_rel].decode("utf-8")) if man_rel and man_rel in original else None
    before = lockfiles.parse(manager, inputs[lock_rel], old_manifest)
    if res.files.get(lock_rel) is None:
        return {"ok": False, "error": "the command removed the lockfile"}
    after = lockfiles.parse(manager, res.files[lock_rel], manifest_json)
    base = os.path.dirname(lockfile)
    prefix = base + "/" if base else ""
    files = {}
    for rel in outputs:
        new = res.files.get(rel)
        old = original.get(rel)
        if new != old:
            files[prefix + rel] = (old, new)
    return {"ok": True, "error": None, "files": files, "before": before, "after": after,
            "diff": lockfiles.diff_entries(before, after),
            "edits": {prefix + rel: res.files.get(rel) for rel in edits}}


# ------------------------------------------------------------------ commands

def save_flags(manager, spec, section):
    """Flags that keep the project's existing version style for a direct dep."""
    flags = []
    if manager == "npm":
        if section == "devDependencies":
            flags.append("--save-dev")
        elif section == "optionalDependencies":
            flags.append("--save-optional")
        if spec and re.match(r"^\d", spec):
            flags.append("--save-exact")
        elif spec and spec.startswith("~"):
            flags.append("--save-prefix=~")
        else:
            flags.append("--save-prefix=^")
    elif manager == "pnpm":
        if section == "devDependencies":
            flags.append("--save-dev")
        elif section == "optionalDependencies":
            flags.append("--save-optional")
        if spec and re.match(r"^\d", spec):
            flags.append("--save-exact")
    return flags


def composer_constraint(old, version):
    """Keep the constraint style: exact stays exact, ~ stays ~, else ^."""
    old = (old or "").strip()
    if re.match(r"^v?\d", old) and not any(c in old for c in "*|, "):
        return version
    if old.startswith("~"):
        return "~" + version
    return "^" + version


def manifest_section(manifest, name, manager):
    if not manifest:
        return None, None
    if manager == "composer":
        for sec in ("require", "require-dev"):
            for k, v in (manifest.get(sec) or {}).items():
                if k.lower() == name:
                    return sec, v
        return None, None
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (manifest.get(sec) or {}):
            return sec, manifest[sec][name]
    return None, None


def direct_steps(manager, name, version, manifest, cflags=None):
    sec, spec = manifest_section(manifest, name, manager)
    if manager == "npm":
        return [["npm", "install", "%s@%s" % (name, version)] + save_flags("npm", spec, sec) + NPM_FLAGS]
    if manager == "pnpm":
        return [["pnpm", "add", "%s@%s" % (name, version)] + save_flags("pnpm", spec, sec) + PNPM_FLAGS]
    if manager == "composer":
        from . import versions
        steps = []
        if spec is not None and not versions.composer_satisfies(version, spec):
            steps.append(["composer", "require", "%s:%s" % (name, composer_constraint(spec, version)),
                          "--no-update", "--no-plugins", "--no-scripts", "--no-interaction"]
                         + (["--dev"] if sec == "require-dev" else []))
        steps.append(["composer", "update", name, "--with", "%s:%s" % (name, version)] + list(cflags))
        return steps
    raise Unavailable(manager)


def refresh_steps(manager, name, version=None, cflags=None):
    if manager == "npm":
        return [["npm", "update", name] + NPM_FLAGS]
    if manager == "pnpm":
        return [["pnpm", "update", name, "--depth", "Infinity"] + PNPM_FLAGS]
    if manager == "composer":
        return [["composer", "update", name, "--with", "%s:%s" % (name, version)] + list(cflags)]
    raise Unavailable(manager)


def parent_steps(manager, parent, parent_version, name, version, manifest, cflags=None):
    if manager == "npm":
        return direct_steps("npm", parent, parent_version, manifest)
    if manager == "pnpm":
        return direct_steps("pnpm", parent, parent_version, manifest)
    if manager == "composer":
        from . import versions
        sec, spec = manifest_section(manifest, parent, manager)
        steps = []
        if spec is not None and not versions.composer_satisfies(parent_version, spec):
            steps.append(["composer", "require", "%s:%s" % (parent, composer_constraint(spec, parent_version)),
                          "--no-update", "--no-plugins", "--no-scripts", "--no-interaction"]
                         + (["--dev"] if sec == "require-dev" else []))
        steps.append(["composer", "update", parent, name, "--with", "%s:%s" % (parent, parent_version),
                      "--with", "%s:%s" % (name, version)] + list(cflags))
        return steps
    raise Unavailable(manager)


def override_steps(manager, parents, name, version):
    """Scoped override: pin `name` only under the given parents.

    Returns (steps, edit) where edit is None or a function for compute().
    npm uses `npm pkg set`. pnpm 10+ reads overrides only from
    pnpm-workspace.yaml (older pnpm from package.json "pnpm.overrides"), and
    no pnpm command can write a `parent>pkg` key, so it is a file edit.
    Composer has no override mechanism."""
    if manager == "npm":
        steps = []
        for p in parents:
            steps.append(["npm", "pkg", "set", "overrides[%s][%s]=%s" % (p, name, version)])
        if not parents:
            steps.append(["npm", "pkg", "set", "overrides[%s]=%s" % (name, version)])
        steps.append(["npm", "install"] + NPM_FLAGS)
        return steps, None
    if manager == "pnpm":
        selectors = ["%s>%s" % (p, name) for p in parents] or [name]
        if pnpm_major() >= 10:
            edit = lambda inputs: {"pnpm-workspace.yaml": workspace_overrides(
                inputs.get("pnpm-workspace.yaml"), selectors, version)}
        else:
            edit = lambda inputs: {"package.json": manifest_overrides(inputs.get("package.json"), selectors, version)}
        return [["pnpm", "install"] + PNPM_FLAGS], edit
    raise Unavailable("no scoped override is available for %s" % manager)


def pnpm_major():
    res = net.run_tool("pnpm", [["--version"]], {}, [], env=TOOL_ENV["pnpm"])
    m = re.match(r"\s*(\d+)\.", res.stdout)
    if not m:
        raise net.SourceError("pnpm", "cannot read pnpm --version")
    return int(m.group(1))


def _yaml_quote(s):
    return "'" + s.replace("'", "''") + "'"


def workspace_overrides(existing, selectors, version):
    """Add override lines to pnpm-workspace.yaml, keeping everything else
    byte for byte. Existing entries for the same selector are replaced."""
    text = existing.decode("utf-8") if existing else ""
    lines = text.splitlines()
    new = ["  %s: %s" % (_yaml_quote(sel), _yaml_quote(version)) for sel in selectors]
    keys = {sel for sel in selectors}
    idx = next((i for i, l in enumerate(lines) if re.match(r"^overrides:\s*$", l)), None)
    if idx is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines += ["overrides:"] + new
    else:
        end = idx + 1
        while end < len(lines) and (lines[end].startswith(" ") or not lines[end].strip()):
            end += 1
        block = [l for l in lines[idx + 1:end]
                 if not any(l.strip().startswith((k + ":", _yaml_quote(k) + ":", '"%s":' % k)) for k in keys)]
        while block and not block[-1].strip():
            block.pop()
        lines[idx + 1:end] = block + new
    return ("\n".join(lines) + "\n").encode("utf-8")


def manifest_overrides(existing, selectors, version):
    data = json.loads(existing.decode("utf-8"))
    ov = data.setdefault("pnpm", {}).setdefault("overrides", {})
    for sel in selectors:
        ov[sel] = version
    return (json.dumps(data, indent=2) + "\n").encode("utf-8")


def shell_join(argv):
    out = []
    for a in argv:
        if re.match(r"^[A-Za-z0-9_@%+=:,./^~-]+$", a) and "[" not in a:
            out.append(a)
        else:
            out.append("'" + a.replace("'", "'\"'\"'") + "'")
    return " ".join(out)
