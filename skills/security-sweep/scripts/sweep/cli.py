"""Command implementations behind security_sweep.py."""

import json
import os
import sys

from . import net, report, scan, state, tools


def _print(text):
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def dispatch(args):
    try:
        return globals()["cmd_" + args.command](args)
    except ValueError as e:
        sys.stderr.write("error: %s\n" % e)
        return 3


def cmd_scan(args):
    repo = os.path.realpath(args.repo)
    if not os.path.isdir(repo):
        raise ValueError("not a directory: %s" % args.repo)
    out = state.run_dir(repo, args.out)
    state.check_outside(repo, out)
    result = scan.run(repo, args.cve)
    state.write_json(os.path.join(out, "scan.json"), result)
    md = report.scan_markdown(result)
    state.write_text(os.path.join(out, "scan.md"), md)
    if args.json:
        _print(json.dumps(result, indent=2))
    else:
        _print(md)
        _print("Run directory: %s" % out)
    return 2 if result["status"] == "INCOMPLETE" else 0


def cmd_tools(args):
    try:
        path = tools.ensure_osv_scanner(download=(args.action == "install"))
    except net.SourceError as e:
        sys.stderr.write("error: %s\n" % e)
        return 2
    _print("osv-scanner %s verified: %s" % (tools.load_lock()["osv-scanner"]["version"], path))
    return 0
