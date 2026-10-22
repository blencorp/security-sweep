#!/usr/bin/env python3
"""security-sweep: fix only critical vulnerabilities, with the smallest change.

  scan   <repo>                 list critical issues (and high ones, separately)
  plan   [<run-dir>] [--fix ID] smallest safe fix and footprint per issue
  check  <fix-id>               confirm only the footprint changed; rescan
  revert <fix-id>               restore the files a fix was allowed to change
  report                        final per-issue status
  tools  install|verify         download / verify the pinned osv-scanner

Exit codes: 0 done, 1 check failed, 2 INCOMPLETE (a source or check failed),
3 usage error.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from sweep import __version__  # noqa: E402
from sweep import cli  # noqa: E402


def main(argv=None):
    p = argparse.ArgumentParser(prog="security-sweep", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="security-sweep %s" % __version__)
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="find critical issues")
    s.add_argument("repo", nargs="?", default=".")
    s.add_argument("--cve", action="append", default=[], metavar="ID",
                   help="treat this CVE/GHSA id as critical (repeatable)")
    s.add_argument("--out", help="run directory (default: ~/.security-sweep/<project>-<hash>)")
    s.add_argument("--json", action="store_true", help="print scan.json to stdout")

    pl = sub.add_parser("plan", help="prescribe the smallest safe fix per issue")
    pl.add_argument("run", nargs="?", help="run directory or scan.json (default: the one for --repo)")
    pl.add_argument("--repo", default=".", help="project directory (default: .)")
    pl.add_argument("--fix", metavar="ID", help="plan (or re-plan) one issue against the current project")
    pl.add_argument("--include-high", action="store_true", help="also plan high-severity issues")
    pl.add_argument("--approve", action="append", default=[], choices=["major", "cooldown"],
                    help="user approved crossing a major/release line, or (KEV only) a version younger than the cooldown")
    pl.add_argument("--cooldown", type=int, default=7, metavar="DAYS")
    pl.add_argument("--json", action="store_true")

    c = sub.add_parser("check", help="verify an applied fix")
    c.add_argument("fix")
    c.add_argument("--repo", default=".")
    c.add_argument("--out")
    c.add_argument("--tests", choices=["pass", "fail", "none"],
                   help="test result compared with the baseline: pass = no new failures")
    c.add_argument("--json", action="store_true")

    r = sub.add_parser("revert", help="restore the files a fix changed")
    r.add_argument("fix")
    r.add_argument("--repo", default=".")
    r.add_argument("--out")
    r.add_argument("--reason", default="", help="why the fix is being reverted (goes in the report)")

    rp = sub.add_parser("report", help="final per-issue status")
    rp.add_argument("--repo", default=".")
    rp.add_argument("--out")
    rp.add_argument("--json", action="store_true")

    t = sub.add_parser("tools", help="manage the pinned osv-scanner")
    t.add_argument("action", choices=["install", "verify"])

    args = p.parse_args(argv)
    if not args.command:
        p.print_help()
        return 3
    return cli.dispatch(args)


if __name__ == "__main__":
    sys.exit(main())
