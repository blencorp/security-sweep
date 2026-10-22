"""Human-readable output. Status always comes first, and the words "clean"
and "safe" are never used for a result that is INCOMPLETE."""


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
