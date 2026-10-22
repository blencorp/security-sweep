"""Shared test setup: import path, replay mode and the recording clock."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "security-sweep", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
RECORDINGS = os.path.join(ROOT, "tests", "recordings")

if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


def recorded_at():
    with open(os.path.join(RECORDINGS, "RECORDED_AT")) as f:
        return f.read().strip()


def live():
    """SECURITY_SWEEP_LIVE=1 runs the fixture tests against live data
    (the scheduled CI job). Exact-answer assertions that drift are skipped."""
    return os.environ.get("SECURITY_SWEEP_LIVE") == "1"
