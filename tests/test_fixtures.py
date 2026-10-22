"""Script tests against sample projects with known right answers.

By default these replay recorded responses (tests/recordings) at the clock
the recording was made, so they are offline and deterministic. To refresh
the recordings run tests/record.py. SECURITY_SWEEP_LIVE=1 runs them against
live data instead; answers that drift over time are skipped then.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import helpers
import security_sweep  # noqa: E402  (path set up by helpers)
from sweep import kev, net, registry, runtime


def _env(now=None):
    env = {}
    if os.environ.get("SECURITY_SWEEP_RECORD"):
        env["SECURITY_SWEEP_NOW"] = now or os.environ["SECURITY_SWEEP_NOW"]
    elif helpers.live():
        if now:
            env["SECURITY_SWEEP_NOW"] = now
    else:
        env["SECURITY_SWEEP_REPLAY"] = helpers.RECORDINGS
        env["SECURITY_SWEEP_NOW"] = now or helpers.recorded_at()
    return env


def _reset_caches():
    net._memo.clear()
    kev._cache.clear()
    registry._cache.clear()
    runtime._cache.clear()


class FixtureTest(unittest.TestCase):
    fixture = None
    now = None

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sweep-test-")
        self.repo = os.path.join(self.tmp, "project")
        shutil.copytree(os.path.join(helpers.FIXTURES, self.fixture), self.repo)
        env = _env(self.now)
        env["SECURITY_SWEEP_HOME"] = os.path.join(self.tmp, "home")
        self.env = mock.patch.dict(os.environ, env)
        self.env.start()
        _reset_caches()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sweep(self, *args):
        """Run the CLI in-process; returns (exit code, parsed JSON or text)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = security_sweep.main(list(args))
        out = buf.getvalue()
        if "--json" in args:
            return code, json.loads(out)
        return code, out

    def scan(self, *extra):
        return self.sweep("scan", self.repo, "--json", *extra)

    def plan(self, *extra):
        return self.sweep("plan", "--repo", self.repo, "--json", *extra)

    def run_dir(self):
        from sweep import state
        return state.run_dir(os.path.realpath(self.repo))

    def apply_expected(self, fix_id):
        """Do what a well-behaved agent does: produce exactly the planned files."""
        d = os.path.join(self.run_dir(), "fixes", fix_id, "expected")
        for root, _, files in os.walk(d):
            for f in files:
                src = os.path.join(root, f)
                rel = os.path.relpath(src, d)
                shutil.copyfile(src, os.path.join(self.repo, rel))

    def only_fix(self, plan, fix_id="C1"):
        fx = [f for f in plan["fixes"] if f["id"] == fix_id]
        self.assertEqual(len(fx), 1, plan["fixes"])
        return fx[0]


class NpmDirectTest(FixtureTest):
    fixture = "npm-direct"

    def test_scan_finds_direct_critical(self):
        code, s = self.scan()
        self.assertEqual(code, 0)
        self.assertEqual(s["status"], "COMPLETE")
        self.assertEqual(len(s["critical"]), 1)
        i = s["critical"][0]
        self.assertEqual((i["package"], i["version"], i["direct"], i["dev"]), ("minimist", "1.2.5", True, False))
        self.assertIn("GHSA-xvch-5gv4-984h", [a["id"] for a in i["advisories"]])
        self.assertIn("CVE-2021-44906", i["advisories"][0]["cves"])

    def test_plan_smallest_patch(self):
        self.scan()
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready")
        self.assertEqual(fx["target"]["to"], "1.2.6")
        self.assertEqual(fx["approach"], "direct")
        self.assertEqual(fx["steps"][0][:3], ["npm", "install", "minimist@1.2.6"])
        self.assertIn("--save-exact", fx["steps"][0])
        self.assertIn("--package-lock-only", fx["steps"][0])
        self.assertEqual(fx["footprint"]["files"], ["package-lock.json", "package.json"])
        self.assertEqual(fx["footprint"]["entries"], [{"name": "minimist", "from": "1.2.5", "to": "1.2.6"}])
        self.assertTrue(all(c["ok"] for c in fx["safety"]))
        with open(os.path.join(self.run_dir(), "fixes", "C1", "prompt.txt")) as f:
            prompt = f.read()
        self.assertIn("npm install minimist@1.2.6 --save-exact", prompt)
        self.assertIn("npm ci", prompt)

    def test_check_passes_for_exact_change(self):
        self.scan()
        self.plan()
        self.apply_expected("C1")
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(code, 0, res)
        self.assertTrue(res["scope"]["ok"])
        self.assertTrue(res["rescan"]["ok"])
        self.assertEqual(res["status"], "awaiting_tests")
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--tests", "pass", "--json")
        self.assertEqual(res["status"], "fixed")

    def test_check_catches_source_edit(self):
        self.scan()
        self.plan()
        self.apply_expected("C1")
        with open(os.path.join(self.repo, "index.js"), "w") as f:
            f.write("module.exports = 1;\n")
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(res["status"], "out_of_scope")
        self.assertEqual(res["scope"]["outside"], [{"path": "index.js", "change": "added"}])

    def test_check_catches_unrelated_bump(self):
        self.scan()
        self.plan()
        self.apply_expected("C1")
        p = os.path.join(self.repo, "package-lock.json")
        with open(p) as f:
            lock = json.load(f)
        lock["packages"]["node_modules/ms"]["version"] = "2.1.3"
        with open(p, "w") as f:
            json.dump(lock, f, indent=2)
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(code, 1)
        items = {(x["item"], x["problem"]) for x in res["scope"]["inside"]}
        self.assertIn(("ms 2.1.3", "added outside the footprint"), items)
        self.assertIn(("ms 2.1.2", "removed outside the footprint"), items)

    def test_check_not_applied_and_revert(self):
        self.scan()
        self.plan()
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(res["status"], "not_applied")
        self.apply_expected("C1")
        with open(os.path.join(self.repo, "package.json")) as f:
            changed = f.read()
        self.assertIn('"minimist": "1.2.6"', changed)
        code, out = self.sweep("revert", "C1", "--repo", self.repo, "--reason", "tests failed")
        self.assertEqual(code, 0)
        self.assertIn("npm ci", out)
        with open(os.path.join(self.repo, "package.json")) as f:
            self.assertIn('"minimist": "1.2.5"', f.read())
        code, out = self.sweep("report", "--repo", self.repo)
        self.assertIn("reverted (tests failed)", out)

    def test_report_never_says_fixed_without_tests(self):
        self.scan()
        self.plan()
        self.apply_expected("C1")
        self.sweep("check", "C1", "--repo", self.repo, "--tests", "none")
        code, rep = self.sweep("report", "--repo", self.repo, "--json")
        self.assertEqual(rep["fixes"][0]["status"], "applied_untested")


class YoungFixTest(FixtureTest):
    """The only fix (minimist 1.2.6, published 2022-03-22) is 2 days old."""
    fixture = "npm-direct"
    now = "2022-03-24T00:00:00Z"

    def test_young_fix_is_not_chosen(self):
        self.scan()
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "no_safe_fix")
        self.assertNotIn("steps", fx)
        self.assertEqual(fx["skipped_versions"][0]["version"], "1.2.6")
        self.assertIn("cooldown is 7 days", fx["skipped_versions"][0]["reason"])


class NpmTransitiveTest(FixtureTest):
    fixture = "npm-transitive"

    def test_refresh_without_touching_parent(self):
        code, s = self.scan()
        i = s["critical"][0]
        self.assertEqual((i["package"], i["version"], i["direct"]), ("minimist", "1.2.5", False))
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready")
        self.assertEqual(fx["approach"], "refresh")
        self.assertEqual(fx["steps"][0][:3], ["npm", "update", "minimist"])
        self.assertEqual(fx["footprint"]["files"], ["package-lock.json"])
        self.assertEqual([e["name"] for e in fx["footprint"]["entries"]], ["minimist"])
        self.assertEqual(fx["footprint"]["entries"][0]["from"], "1.2.5")
        if not helpers.live():
            self.assertEqual(fx["target"]["to"], "1.2.8")


class NpmMajorOnlyTest(FixtureTest):
    fixture = "npm-major-only"

    def test_major_needs_approval(self):
        self.scan()
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "needs_approval")
        self.assertEqual(fx["approvals_needed"], ["major"])
        self.assertEqual(fx["target"]["to"], "3.1.7")
        self.assertTrue(fx["target"]["crosses_major"])
        code, out = self.sweep("plan", "--repo", self.repo)
        self.assertIn("needs your approval", out)
        self.assertIn("crosses a major version", out)

    def test_approved_major_is_ready(self):
        self.scan()
        code, p = self.plan("--fix", "C1", "--approve", "major")
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready")


class ComposerDirectTest(FixtureTest):
    fixture = "composer-direct"

    def test_composer_minimal_fix(self):
        code, s = self.scan()
        i = s["critical"][0]
        self.assertEqual((i["package"], i["version"], i["direct"]), ("dompdf/dompdf", "v2.0.1", True))
        self.assertIn("GHSA-3cw5-7cxw-v5qg", [a["id"] for a in i["advisories"]])
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready", fx)
        # v2.0.2 fixes CVE-2023-23924 but introduces CVE-2023-24813 (critical),
        # so the smallest safe fix is v2.0.3.
        if not helpers.live():
            self.assertEqual(fx["skipped_versions"][0]["version"], "v2.0.2")
            self.assertIn("introduces critical advisory", fx["skipped_versions"][0]["reason"])
        self.assertEqual(fx["target"]["to"], "v2.0.3")
        self.assertEqual(fx["steps"][-1][:5], ["composer", "update", "dompdf/dompdf", "--with", "dompdf/dompdf:v2.0.3"])
        self.assertIn("--no-install", fx["steps"][-1])
        self.assertEqual(fx["footprint"]["files"], ["composer.lock"])
        self.assertEqual(fx["footprint"]["entries"], [{"name": "dompdf/dompdf", "from": "v2.0.1", "to": "v2.0.3"}])


class PhpImageTest(FixtureTest):
    fixture = "php-image"

    def test_image_one_release_behind(self):
        code, s = self.scan()
        self.assertEqual(s["status"], "COMPLETE")
        i = s["critical"][0]
        self.assertEqual((i["kind"], i["runtime"], i["origin"], i["version"]), ("runtime", "php", "official-image", "8.2.25"))
        ids = sorted(a["id"] for a in i["advisories"])
        self.assertTrue({"CVE-2024-11236", "CVE-2024-8932"} <= set(ids), ids)
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready")
        if not helpers.live():
            self.assertEqual(fx["target"]["to"], "8.2.26")
            self.assertEqual(fx["edit"], {"file": "Dockerfile", "line": 1, "from": "FROM php:8.2.25-cli",
                                          "to": "FROM php:8.2.26-cli"})
        self.assertEqual(fx["footprint"]["files"], ["Dockerfile"])

    def test_check_runtime_edit(self):
        self.scan()
        self.plan()
        self.apply_expected("C1")
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(code, 0, res)
        self.assertTrue(res["rescan"]["ok"])


class DebianPhpTest(FixtureTest):
    fixture = "debian-php"

    def test_distro_data_not_upstream(self):
        code, s = self.scan()
        rts = s["runtimes"]
        self.assertEqual(len(rts), 1)
        self.assertEqual(rts[0]["origin"], "distro")
        self.assertEqual(rts[0]["distro"]["ecosystem"], "Debian:12")
        self.assertEqual(rts[0]["distro"]["package"], "php8.2")
        ids = {a["id"] for i in s["critical"] + s["high"] for a in i["advisories"]}
        # Upstream PHP 8.2.18 is affected by CVE-2024-4577 (on CISA KEV), but
        # Debian's tracker says its php8.2 package is not: it must not show.
        self.assertNotIn("CVE-2024-4577", ids)
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["edit"]["line"], 4)
        if not helpers.live():
            self.assertEqual(s["critical"][0]["advisories"][0]["fixed_in"], "8.2.26-1~deb12u1")
            self.assertEqual(fx["target"]["to"], "8.2.26-1~deb12u1")
            self.assertIn("php8.2-cli=8.2.26-1~deb12u1", fx["edit"]["to"])
        self.assertEqual(fx["footprint"]["files"], ["Dockerfile"])

    def test_patched_distro_version_not_flagged(self):
        p = os.path.join(self.repo, "Dockerfile")
        with open(p) as f:
            text = f.read().replace("8.2.18-1~deb12u1", "8.2.26-1~deb12u1")
        with open(p, "w") as f:
            f.write(text)
        code, s = self.scan()
        self.assertEqual(s["critical"], [])
        self.assertEqual(s["status"], "COMPLETE")


class NoLockfileTest(FixtureTest):
    fixture = "no-lockfile"

    def test_reports_not_checked(self):
        code, s = self.scan()
        self.assertEqual(code, 2)
        self.assertEqual(s["status"], "INCOMPLETE")
        self.assertEqual(sorted(n["path"] for n in s["not_checked"]), ["composer.json", "package.json"])
        code, md = self.sweep("scan", self.repo)
        self.assertIn("INCOMPLETE", md)
        self.assertIn("NOT CHECKED", md)
        self.assertNotIn(" clean", md.replace("Do not call this project clean", ""))


class YarnClassicTest(FixtureTest):
    fixture = "yarn-classic"

    def test_version_planned_footprint_needs_approval(self):
        code, s = self.scan()
        self.assertEqual(s["critical"][0]["manager"], "yarn-classic")
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "needs_approval")
        self.assertIn("footprint", fx["approvals_needed"])
        self.assertEqual(fx["target"]["to"], "1.2.6")
        self.assertIsNone(fx["footprint"]["entries"])

    def _edit_lock(self, old, new):
        p = os.path.join(self.repo, "yarn.lock")
        with open(p) as f:
            text = f.read()
        with open(p, "w") as f:
            f.write(text.replace(old, new))

    def test_check_allows_only_the_target_package(self):
        self.scan()
        self.plan()
        self._edit_lock('version "1.2.5"', 'version "1.2.6"')
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(res["status"], "applied_without_approval")
        self._edit_lock('version "1.2.6"', 'version "1.2.5"')
        code, p = self.plan("--fix", "C1", "--approve", "footprint")
        self.assertEqual(self.only_fix(p)["status"], "ready")
        self._edit_lock('minimist@1.2.5:\n  version "1.2.5"', 'minimist@1.2.6:\n  version "1.2.6"')
        self._edit_lock("minimist-1.2.5.tgz", "minimist-1.2.6.tgz")
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertTrue(res["scope"]["ok"], res["scope"])
        self._edit_lock('version "2.1.2"', 'version "2.1.3"')
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(res["status"], "out_of_scope")
        self.assertIn("ms 2.1.3", [x["item"] for x in res["scope"]["inside"]])


class LiveCommandsMixin(object):
    """Run the prescribed commands in the real project and check the result
    matches the footprint computed in the scratch copy."""
    materialize_extra = []

    def test_prescribed_commands_stay_in_footprint(self):
        self.scan()
        code, p = self.plan()
        fx = self.only_fix(p)
        for step in fx["steps"]:
            subprocess.run(step, cwd=self.repo, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(fx["materialize"] + self.materialize_extra, cwd=self.repo, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        code, res = self.sweep("check", "C1", "--repo", self.repo, "--json")
        self.assertEqual(res["status"], "awaiting_tests", res)


@unittest.skipUnless(helpers.live(), "live only: runs real package managers in the project")
class LiveNpmDirect(LiveCommandsMixin, FixtureTest):
    fixture = "npm-direct"
    materialize_extra = ["--ignore-scripts"]


@unittest.skipUnless(helpers.live(), "live only: runs real package managers in the project")
class LiveNpmTransitive(LiveCommandsMixin, FixtureTest):
    fixture = "npm-transitive"
    materialize_extra = ["--ignore-scripts"]


@unittest.skipUnless(helpers.live(), "live only: runs real package managers in the project")
class LiveComposerDirect(LiveCommandsMixin, FixtureTest):
    fixture = "composer-direct"
    materialize_extra = ["--no-scripts", "--no-plugins", "--ignore-platform-req=ext-*"]


class TrapTest(FixtureTest):
    """minimist (patch fix) + ejs (fix only in 3.x, which breaks this app)."""
    fixture = "trap"

    def ids(self):
        code, s = self.scan()
        return {i["package"]: i["id"] for i in s["critical"]}

    def test_plan_separates_safe_and_breaking(self):
        ids = self.ids()
        code, p = self.plan()
        by = {f["issue"]["package"]: f for f in p["fixes"]}
        self.assertEqual(by["minimist"]["status"], "ready")
        self.assertEqual(by["minimist"]["footprint"]["entries"], [{"name": "minimist", "from": "1.2.5", "to": "1.2.6"}])
        self.assertEqual(by["ejs"]["status"], "needs_approval")
        self.assertEqual(by["ejs"]["approvals_needed"], ["major"])
        self.assertEqual(set(ids), {"minimist", "ejs"})

    def test_unapproved_major_fails_check(self):
        ids = self.ids()
        self.plan()
        self.apply_expected(ids["ejs"])
        code, res = self.sweep("check", ids["ejs"], "--repo", self.repo, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(res["status"], "applied_without_approval")

    def test_approve_requires_fix_id(self):
        self.ids()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code, _ = self.sweep("plan", "--repo", self.repo, "--approve", "major")
        self.assertEqual(code, 3)
        self.assertIn("--fix", buf.getvalue())

    def test_sequential_fixes_and_stale_guard(self):
        ids = self.ids()
        ejs, mini = ids["ejs"], ids["minimist"]
        self.plan("--fix", ejs, "--approve", "major")
        self.plan("--fix", mini)
        self.apply_expected(mini)
        code, res = self.sweep("check", mini, "--repo", self.repo, "--tests", "pass", "--json")
        self.assertEqual(res["status"], "fixed")
        # ejs was planned before minimist was kept: its snapshot is stale.
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            code, _ = self.sweep("check", ejs, "--repo", self.repo)
        self.assertEqual(code, 3)
        self.assertIn("stale", buf.getvalue())
        # Re-planning against the current project fixes that.
        code, p = self.plan("--fix", ejs, "--approve", "major")
        fx = self.only_fix(p, ejs)
        self.assertEqual(fx["status"], "ready")
        self.assertNotIn("minimist", [e["name"] for e in fx["footprint"]["entries"]])
        self.apply_expected(ejs)
        code, res = self.sweep("check", ejs, "--repo", self.repo, "--json")
        self.assertEqual(res["status"], "awaiting_tests", res)
        self.sweep("check", ejs, "--repo", self.repo, "--tests", "fail")
        code, out = self.sweep("revert", ejs, "--repo", self.repo, "--reason", "test failed: legacy include removed in ejs 3")
        self.assertEqual(code, 0)
        with open(os.path.join(self.repo, "package.json")) as f:
            pkg = json.load(f)
        self.assertEqual(pkg["dependencies"], {"ejs": "^2.7.4", "minimist": "1.2.6"})
        code, rep = self.sweep("report", "--repo", self.repo, "--json")
        status = {r["id"]: r["status"] for r in rep["fixes"]}
        self.assertEqual(status, {mini: "fixed", ejs: "reverted"})


class KevCooldownTest(FixtureTest):
    """PHP 8.2.19 two days after 8.2.20 shipped the fix for CVE-2024-4577,
    which is on CISA KEV. (The KEV catalog itself is not clock-filtered.)"""
    fixture = "php-image"
    now = "2024-06-08T00:00:00Z"

    def setUp(self):
        FixtureTest.setUp(self)
        with open(os.path.join(self.repo, "Dockerfile"), "w") as f:
            f.write("FROM php:8.2.19-cli\n")

    def test_kev_young_fix_needs_approval_then_ready(self):
        code, s = self.scan()
        i = s["critical"][0]
        self.assertEqual([a["id"] for a in i["advisories"]], ["CVE-2024-4577"])
        self.assertTrue(i["advisories"][0]["kev"])
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "needs_approval")
        self.assertEqual(fx["approvals_needed"], ["cooldown"])
        self.assertEqual(fx["target"]["to"], "8.2.20")
        code, p = self.plan("--fix", "C1", "--approve", "cooldown")
        self.assertEqual(self.only_fix(p)["status"], "ready")


class NodeNamedCveTest(FixtureTest):
    fixture = "node-version"

    def test_named_cve_becomes_critical_and_high_is_listed(self):
        code, s = self.scan()
        rt = s["runtimes"][0]
        self.assertEqual((rt["runtime"], rt["origin"], rt["declared"]), ("node", "version-file", "22.12.0"))
        high = [a for i in s["high"] for a in i["advisories"]]
        self.assertTrue(high, "expected high-severity Node advisories for 22.12.0")
        named = high[0]["id"]
        code, s2 = self.scan("--cve", named)
        crit = [a for i in s2["critical"] for a in i["advisories"]]
        self.assertIn(named, [a["id"] for a in crit])
        self.assertTrue([a for a in crit if a["id"] == named][0]["named"])
        code, p = self.plan()
        fx = self.only_fix(p)
        self.assertEqual(fx["status"], "ready")
        self.assertEqual(fx["edit"]["file"], ".nvmrc")
        self.assertEqual(fx["edit"]["from"], "22.12.0")

    def test_include_high_plans_high_issues(self):
        code, s = self.scan()
        code, p = self.plan()
        self.assertEqual([f["id"] for f in p["fixes"]], [i["id"] for i in s["critical"]])
        code, p = self.plan("--include-high")
        self.assertTrue(any(f["id"].startswith("H") for f in p["fixes"]))


if __name__ == "__main__":
    unittest.main()
