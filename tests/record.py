#!/usr/bin/env python3
"""Refresh tests/recordings in one session.

All fixture tests run live with every HTTP response and tool run saved. The
recordings directory is wiped first so it never mixes data from different
days, and the clock is pinned to the start of the session so cooldown and
"published after now" rules replay exactly.

Usage: python3 tests/record.py
"""

import datetime
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REC = os.path.join(HERE, "recordings")


def main():
    shutil.rmtree(REC, ignore_errors=True)
    os.makedirs(REC)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = dict(os.environ, SECURITY_SWEEP_RECORD=REC, SECURITY_SWEEP_NOW=now)
    env.pop("SECURITY_SWEEP_REPLAY", None)
    env.pop("SECURITY_SWEEP_LIVE", None)
    code = subprocess.call([sys.executable, "-m", "unittest", "-v", "tests.test_fixtures"], cwd=ROOT, env=env)
    if code != 0:
        print("recording run failed; recordings left in place for inspection", file=sys.stderr)
        return code
    with open(os.path.join(REC, "RECORDED_AT"), "w") as f:
        f.write(now + "\n")
    print("recorded at %s into %s" % (now, REC))
    return 0


if __name__ == "__main__":
    sys.exit(main())
