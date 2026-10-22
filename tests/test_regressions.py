"""Regression tests for issues found in the pre-release code review."""

import json
import os
import shutil
import tempfile
import unittest

from tests import helpers  # noqa: F401
from sweep import check, footprint, lockfiles, plan, runtime, scan, state


def vuln(fixed):
    return {"id": "GHSA-x", "aliases": [], "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def entry(name, version):
    return {"name": name, "version": version, "key": "node_modules/" + name + "@" + version}


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def write(self, rel, text):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p


class TwoInstalledVersionsTest(unittest.TestCase):
    def test_other_version_does_not_block_this_fix(self):
        issue = {"package": "minimist", "version": "1.2.0", "ecosystem": "npm"}
        advs = [vuln("1.2.6")]
        before = [entry("minimist", "1.2.0"), entry("minimist", "0.0.8")]
        after = [entry("minimist", "1.2.6"), entry("minimist", "0.0.8")]
        self.assertTrue(plan._reaches_fix(before, after, issue, advs))
        self.assertFalse(plan._reaches_fix(before, before, issue, advs))


class PnpmV5KeysTest(unittest.TestCase):
    def test_peer_suffix(self):
        self.assertEqual(lockfiles._pnpm_key("/styled-components/5.3.0_react-dom@17.0.2"),
                         ("styled-components", "5.3.0"))
        self.assertEqual(lockfiles._pnpm_key("/@babel/core/7.1.0"), ("@babel/core", "7.1.0"))
        self.assertEqual(lockfiles._pnpm_key("/@babel/core@7.1.0(supports-color@5.5.0)"), ("@babel/core", "7.1.0"))
        self.assertEqual(lockfiles._pnpm_key("minimist@1.2.5"), ("minimist", "1.2.5"))
        self.assertEqual(lockfiles._pnpm_ver("5.3.0_react@17.0.2"), "5.3.0")


class PnpmWorkspaceInputsTest(TmpDir):
    def test_members_are_copied(self):
        self.write("package.json", "{}")
        self.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
        self.write("packages/a/package.json", '{"name": "a"}')
        self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a:\n"
                   "    dependencies:\n      ms:\n        specifier: 2.1.2\n        version: 2.1.2\n")
        got = footprint.gather_inputs(self.d, "pnpm-lock.yaml", "package.json", "pnpm")
        self.assertIn("packages/a/package.json", got)
        self.assertIn("pnpm-workspace.yaml", got)


class YarnTransitiveStepsTest(TmpDir):
    def test_lock_entry_removed_then_install(self):
        with open(os.path.join(helpers.FIXTURES, "lockfiles", "yarn-classic.lock")) as f:
            self.write("yarn.lock", f.read())
        issue = {"manager": "yarn-classic", "direct": False, "package": "minimist", "version": "1.2.8",
                 "lockfile": "yarn.lock"}
        ctx = plan.Ctx(self.d, 7, [])
        writes = plan._manual_writes(ctx, issue)
        new = writes["yarn.lock"]
        self.assertNotIn("minimist@^1.2.5:", new)
        self.assertIn("minimist@1.2.5:", new)  # the direct 1.2.5 entry is a different issue
        self.assertIn("mkdirp@0.5.5:", new)
        self.assertNotIn("\n\n\n", new)
        self.assertEqual(plan._manual_steps(issue, "1.2.9"), [["yarn", "install", "--ignore-scripts"]])

    def test_direct_keeps_style(self):
        issue = {"manager": "yarn-classic", "direct": True, "package": "ms"}
        self.assertEqual(plan._manual_steps(issue, "2.1.3", {"devDependencies": {"ms": "~2.1.2"}}),
                         [["yarn", "add", "ms@2.1.3", "--tilde", "--dev", "--ignore-scripts"]])
        self.assertEqual(plan._manual_steps(issue, "2.1.3", {"dependencies": {"ms": "2.1.2"}}),
                         [["yarn", "add", "ms@2.1.3", "--exact", "--ignore-scripts"]])


class PlatformConfigLineTest(TmpDir):
    def test_platform_key_not_require(self):
        self.write("composer.json", json.dumps({"require": {"php": "8.2.10"},
                                                "config": {"platform": {"php": "8.2.10"}}}, indent=4))
        decl = runtime.detect(self.d, ["composer.json"])[0]
        with open(os.path.join(self.d, "composer.json")) as f:
            lines = f.read().splitlines()
        self.assertGreater(decl["line"], next(i for i, l in enumerate(lines, 1) if '"platform"' in l))


class MultiLinePinTest(TmpDir):
    def test_every_pin_moves_together(self):
        self.write("Dockerfile", "FROM debian:12\nRUN apt-get install -y \\\n    php8.2-cli=8.2.18-1~deb12u1 \\\n"
                   "    php8.2-fpm=8.2.18-1~deb12u1\n")
        decl = runtime.detect(self.d, ["Dockerfile"])[0]
        issue = {"source": "Dockerfile", "line": decl["line"], "end_line": decl["end_line"], "origin": "distro",
                 "version": "8.2.18-1~deb12u1"}
        p = plan._line_edit(plan.Ctx(self.d, 7, []), issue, {}, "8.2.26-1~deb12u1", [])
        self.assertEqual([x["line"] for x in p["edit"]["lines"]], [3, 4])
        self.assertNotIn(b"8.2.18", p["_expected"]["Dockerfile"])


class YarnManifestScopeTest(unittest.TestCase):
    def test_exact_package_names_only(self):
        self.assertTrue(check._names_package("dependencies.lodash", "lodash"))
        self.assertTrue(check._names_package("resolutions.**/lodash", "lodash"))
        self.assertFalse(check._names_package("dependencies.@evil/lodash", "lodash"))
        self.assertFalse(check._names_package("dependencies.lodash.merge", "merge"))
        self.assertFalse(check._names_package("scripts.lodash", "minimist"))


class KeptSeqTest(TmpDir):
    def test_rechecking_a_kept_fix_does_not_stale_later_plans(self):
        check._record(self.d, "C1", {"status": "awaiting_tests"})
        fix_dir = os.path.join(self.d, "fixes", "C2")
        state.write_json(os.path.join(fix_dir, "snapshot.json"), {"seq": state.next_seq(self.d), "files": {}})
        check._record(self.d, "C1", {"status": "fixed"})
        self.assertEqual(check._stale_because(self.d, fix_dir, "C2"), [])


class ManifestOverridesFormatTest(unittest.TestCase):
    def test_indent_and_unicode_kept(self):
        src = '{\n    "name": "x",\n    "author": "Jos\u00e9"\n}\n'.encode("utf-8")
        out = footprint.manifest_overrides(src, ["a>b"], "1.0.0").decode("utf-8")
        self.assertIn('\n    "author": "Jos\u00e9"', out)
        self.assertIn('"a>b": "1.0.0"', out)


class AlpineOrderingTest(unittest.TestCase):
    def test_apk_for_alpine(self):
        rt = {"origin": "distro", "runtime": "php", "distro": {"ecosystem": "Alpine:v3.19"}}
        self.assertEqual(scan._max_version(rt, ["8.2.10-r0", "8.2.9-r3"]), "8.2.10-r0")


if __name__ == "__main__":
    unittest.main()
