"""Human-readable output. Status always comes first, and the words "clean"
and "safe" are never used for a result that is INCOMPLETE."""

import os


def _adv_line(a):
    ids = a["id"]
    cves = [c for c in a.get("cves") or [] if c != a["id"]]
    if cves:
        ids += " (%s)" % ", ".join(cves)
    bits = [a.get("severity") or "unknown"]
    if a.get("score"):
        bits[0] += " %.1f" % a["score"]
    if a.get("kev"):
        bits.append("CISA KEV, due %s" % a["kev"].get("due_date"))
    if a.get("named"):
        bits.append("named by user")
    if a.get("fixed_in"):
        bits.append("fixed in %s" % a["fixed_in"])
    return "%s: %s" % (ids, ", ".join(bits))


def issue_title(i):
    if i["kind"] == "package":
        where = "direct" if i["direct"] else "transitive"
        if i.get("dev"):
            where += ", dev only"
        return "%s %s in %s (%s)" % (i["package"], i["version"], i["lockfile"], where)
    origin = i["origin"]
    if i.get("distro"):
        origin += " %s %s" % (i["distro"]["ecosystem"], i["distro"]["package"])
    return "%s %s from %s:%s (%s)" % (i["runtime"], i["version"], i["source"], i["line"], origin)


def scan_markdown(s):
    out = []
    crit, high = s["critical"], s["high"]
    if s["status"] == "INCOMPLETE":
        out.append("# Status: INCOMPLETE")
        out.append("")
        out.append("Some checks failed or were skipped, so this is not a complete answer. "
                   "Do not call this project clean or safe.")
        out.append("")
        for r in s["incomplete_reasons"]:
            out.append("- %s" % r)
    else:
        out.append("# Status: COMPLETE")
        out.append("")
        out.append("%d critical issue(s), %d high." % (len(crit), len(high)))
    out.append("")
    out.append("## Critical issues (%d)" % len(crit))
    out.append("")
    if not crit:
        out.append("None found in what was checked.")
    for i in crit:
        out.append("### %s. %s" % (i["id"], issue_title(i)))
        if i.get("eol"):
            out.append("- End of life: this release line no longer gets security fixes%s."
                       % (" (ended %s)" % i["eol_date"] if i.get("eol_date") else ""))
        for a in i["advisories"]:
            out.append("- %s" % _adv_line(a))
        if i.get("other_advisories"):
            out.append("- Also has %d non-critical advisory(ies): %s" % (
                len(i["other_advisories"]), ", ".join(a["id"] for a in i["other_advisories"][:8])))
        out.append("")
    out.append("## High issues (%d), listed only; not fixed unless asked" % len(high))
    out.append("")
    for i in high:
        out.append("- %s. %s: %s" % (i["id"], issue_title(i), "; ".join(_adv_line(a) for a in i["advisories"])))
    if high:
        out.append("")
    out.append("## What was checked")
    out.append("")
    for lk in s["lockfiles"]:
        out.append("- %s (%s): %s%s" % (lk["path"], lk["manager"], lk["status"],
                                         ", %s packages" % lk["entries"] if lk.get("entries") is not None else ""))
    for nc in s["not_checked"]:
        out.append("- %s: NOT CHECKED, %s" % (nc["path"], nc["reason"]))
    for rt in s["runtimes"]:
        line = "- %s %s from %s:%s (%s)" % (rt["runtime"], rt.get("declared") or "?", rt["source"], rt["line"],
                                            rt["origin"])
        if rt.get("problem"):
            line += ": NOT FULLY CHECKED, %s" % rt["problem"]
            if rt.get("minimum_safe"):
                line += "; minimum version without known critical issues: %s" % rt["minimum_safe"]
        elif rt.get("eol"):
            line += ": end of life"
        out.append(line)
    if not s["lockfiles"] and not s["not_checked"] and not s["runtimes"]:
        out.append("- No npm/Composer lockfiles, manifests or PHP/Node runtime declarations were found.")
    out.append("")
    return "\n".join(out)


# ------------------------------------------------------------------- plans

STATUS_TEXT = {
    "ready": "ready to apply",
    "needs_approval": "needs your approval",
    "no_safe_fix": "no safe fix available",
    "blocked": "blocked",
    "already_resolved": "already resolved",
    "incomplete": "INCOMPLETE",
}

APPROVAL_TEXT = {
    "major": "crosses a major version",
    "line": "needs a newer release line",
    "cooldown": "uses a version younger than the cooldown (allowed only because the issue is on CISA KEV)",
    "footprint": "footprint cannot be computed in advance for this package manager (approve with --approve footprint)",
}


def sweep_cmd(skill_dir):
    return "python3 %s/scripts/security_sweep.py" % skill_dir


def fix_title(fx):
    t = fx.get("target")
    if t:
        name = t.get("package") or t.get("runtime")
        return "%s %s -> %s" % (name, t["from"], t["to"])
    i = fx["issue"]
    return "%s %s" % (i.get("package") or i.get("runtime"), i.get("version"))


def _footprint_text(fx):
    fp = fx.get("footprint")
    if not fp:
        return "none"
    parts = [", ".join(fp["files"])]
    if fp.get("entries") is None:
        parts.append("lockfile entries unknown in advance; only %s may change" % ", ".join(fp.get("names_only") or []))
    elif fp["entries"]:
        ents = ["%s %s" % (e["name"], ("%s -> %s" % (e["from"], e["to"])) if e["from"] and e["to"]
                           else ("added %s" % e["to"]) if e["to"] else ("removed %s" % e["from"]))
                for e in fp["entries"]]
        parts.append("%d lockfile entr%s: %s" % (len(ents), "y" if len(ents) == 1 else "ies", "; ".join(ents)))
    return " | ".join(parts)


def fix_block(fx, n, total, skill_dir, repo):
    i = fx["issue"]
    out = ["Fix %s (%d of %d): %s [%s]" % (fx["id"], n, total, fix_title(fx), STATUS_TEXT.get(fx["status"], fx["status"]))]
    out.append("  Fixes:      %s" % "; ".join(_adv_line(a) for a in i["advisories"]) if i["advisories"]
               else "  Issue:      %s" % ("end of life" if i.get("eol") else ""))
    if fx.get("approvals_needed"):
        out.append("  Approval:   %s" % "; ".join(APPROVAL_TEXT.get(a, a) for a in fx["approvals_needed"]))
    if fx.get("detail"):
        out.append("  Detail:     %s" % fx["detail"])
    if fx.get("still_affected_by"):
        out.append("  Also left:  %s (not fixed by this version; not critical)" % ", ".join(fx["still_affected_by"]))
    if fx.get("footprint"):
        out.append("  Footprint:  %s" % _footprint_text(fx))
    if fx.get("safety"):
        out.append("  Checks:     %s" % "; ".join(("" if c["ok"] else "FAIL ") + c["detail"] for c in fx["safety"]))
    bad_entries = [c for c in fx.get("entry_checks") or [] if c["name"] != (fx.get("target") or {}).get("package")]
    if bad_entries:
        out.append("  Other changed packages checked: %s" % ", ".join(
            "%s %s%s" % (c["name"], c["to"], "" if c["ok"] else " (needs approval: younger than cooldown)")
            for c in bad_entries))
    for s in fx.get("skipped_versions") or []:
        out.append("  Skipped:    %s (%s)" % (s["version"], s["reason"]))
    for a in fx.get("attempts") or []:
        out.append("  Tried:      %s: %s" % (a["approach"], a["result"][:300]))
    for w in fx.get("workarounds") or []:
        out.append("  Workaround: %s" % w.replace("\n", " ")[:400])
    for note in fx.get("notes") or []:
        out.append("  Note:       %s" % note)
    if fx.get("steps") or fx.get("edit"):
        out.append("  Prompt:     see %s" % "fixes/%s/prompt.txt" % fx["id"])
    return "\n".join(out)


def prompt_text(fx, skill_dir, repo):
    """The fenced-in instruction for applying exactly one fix."""
    from .footprint import shell_join
    i = fx["issue"]
    cmd = sweep_cmd(skill_dir)
    lines = ["Apply fix %s only: %s." % (fx["id"], fix_title(fx))]
    if i["advisories"]:
        lines.append("It fixes: %s." % "; ".join(_adv_line(a) for a in i["advisories"]))
    lines.append("Allowed changes (footprint): %s." % _footprint_text(fx))
    lines.append("")
    if fx.get("edit"):
        e = fx["edit"]
        lines.append("Edit %s line %d. Replace exactly:" % (e["file"], e["line"]))
        lines.append("  %s" % e["from"])
        lines.append("with:")
        lines.append("  %s" % e["to"])
        lines.append("Change nothing else in that file or any other file.")
    else:
        base = os.path.dirname(i["lockfile"]) if i.get("lockfile") else ""
        lines.append("Run exactly these commands, in order, from %s:" % os.path.join(repo, base) if base
                     else "Run exactly these commands, in order, from %s:" % repo)
        n = 0
        for s in fx.get("steps") or []:
            n += 1
            lines.append("  %d. %s" % (n, shell_join(s)))
        if fx.get("materialize"):
            n += 1
            lines.append("  %d. %s   (installs what the lockfile now says; must not change the lockfile)"
                         % (n, shell_join(fx["materialize"])))
    lines.append("")
    lines.append("Then run: %s check %s --repo %s" % (cmd, fx["id"], repo))
    lines.append("If the check fails or reports changes outside the footprint, run:")
    lines.append("  %s revert %s --repo %s --reason \"<why>\"" % (cmd, fx["id"], repo))
    lines.append("and stop. Do not try to fix forward.")
    lines.append("")
    lines.append("Do not run npm audit fix, npm update or composer update without a package name, or any "
                 "command with --force. Do not edit application code, tests, configuration or CI files. "
                 "Do not change any other dependency.")
    lines.append("After the check passes, run the project's tests and compare with the baseline; then record "
                 "the result: %s check %s --repo %s --tests pass|fail|none" % (cmd, fx["id"], repo))
    return "\n".join(lines) + "\n"


def plan_markdown(plan, skill_dir):
    out = []
    fixes = plan["fixes"]
    if plan["scan_status"] == "INCOMPLETE":
        out.append("# Status: INCOMPLETE (the scan had failures; this plan covers only what was checked)")
        for r in plan["incomplete_reasons"]:
            out.append("- %s" % r)
    else:
        out.append("# Plan: %d fix(es)" % len(fixes))
    out.append("")
    counts = {}
    for fx in fixes:
        counts[fx["status"]] = counts.get(fx["status"], 0) + 1
    if counts:
        out.append(", ".join("%d %s" % (v, STATUS_TEXT.get(k, k)) for k, v in sorted(counts.items())))
        out.append("")
    out.append("Nothing has been changed. Choose which fixes to apply; they are applied one at a time.")
    out.append("")
    out.append("```text")
    for n, fx in enumerate(fixes, 1):
        out.append(fix_block(fx, n, len(fixes), skill_dir, plan["repo"]))
        out.append("")
    out.append("```")
    return "\n".join(out) + "\n"
