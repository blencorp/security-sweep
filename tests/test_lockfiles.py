import json
import os
import shutil
import tempfile
import unittest

from tests import helpers
from sweep import lockfiles, miniyaml

LF = os.path.join(helpers.FIXTURES, "lockfiles")


def load(name):
    with open(os.path.join(LF, name), "rb") as f:
        return f.read()


MANIFEST = json.loads(load("package.json"))


def index(entries):
    return {(e["name"], e["version"]): e for e in entries}


class NodeLockfilesTest(unittest.TestCase):
    def check_common(self, entries, transitive_minimist):
        idx = index(entries)
        self.assertTrue(idx[("minimist", "1.2.5")]["direct"])
        self.assertFalse(idx[("minimist", "1.2.5")]["dev"])
        self.assertTrue(idx[("mkdirp", "0.5.5")]["direct"])
        self.assertTrue(idx[("ejs", "2.7.4")]["direct"])
        self.assertTrue(idx[("ejs", "2.7.4")]["dev"])
        t = idx[("minimist", transitive_minimist)]
        self.assertFalse(t["dev"])
        for e in entries:
            self.assertTrue(e["fingerprint"].strip("|"), e)

    def test_npm(self):
        entries = lockfiles.parse("npm", load("package-lock.json"), MANIFEST)
        self.assertEqual(len(entries), 3)
        self.check_common(entries, "1.2.5")
        self.assertEqual(index(entries)[("mkdirp", "0.5.5")]["deps"], {"minimist": "node_modules/minimist"})

    def test_yarn_classic(self):
        entries = lockfiles.parse("yarn-classic", load("yarn-classic.lock"), MANIFEST)
        self.check_common(entries, "1.2.8")
        self.assertFalse(index(entries)[("minimist", "1.2.8")]["direct"])

    def test_yarn_berry(self):
        entries = lockfiles.parse("yarn-berry", load("yarn-berry.lock"), MANIFEST)
        self.assertNotIn("n1", {e["name"] for e in entries})
        self.check_common(entries, "1.2.8")

    def test_pnpm(self):
        entries = lockfiles.parse("pnpm", load("pnpm-lock.yaml"), MANIFEST)
        self.check_common(entries, "1.2.5")
        self.assertEqual(index(entries)[("mkdirp", "0.5.5")]["deps"], {"minimist": "minimist@1.2.5"})

    def test_npm_resolve_walks_up(self):
        keys = {"node_modules/a", "node_modules/a/node_modules/b", "node_modules/b", "node_modules/c"}
        self.assertEqual(lockfiles.npm_resolve(keys, "node_modules/a", "b"), "node_modules/a/node_modules/b")
        self.assertEqual(lockfiles.npm_resolve(keys, "node_modules/c", "b"), "node_modules/b")
        self.assertIsNone(lockfiles.npm_resolve(keys, "node_modules/c", "zzz"))


class ComposerLockTest(unittest.TestCase):
    def test_composer(self):
        manifest = json.loads(load("composer.json"))
        entries = lockfiles.parse("composer", load("composer.lock"), manifest)
        idx = {e["name"]: e for e in entries}
        self.assertTrue(idx["guzzlehttp/guzzle"]["direct"])
        self.assertFalse(idx["guzzlehttp/psr7"]["direct"])
        self.assertEqual(idx["guzzlehttp/psr7"]["version"], "2.1.0")
        self.assertIn("guzzlehttp/psr7", idx["guzzlehttp/guzzle"]["deps"])


class DiffTest(unittest.TestCase):
    def test_diff_entries(self):
        e = lambda n, v, fp="x": {"name": n, "version": v, "fingerprint": fp}
        before = [e("a", "1.0.0"), e("b", "1.0.0"), e("c", "1.0.0")]
        after = [e("a", "1.0.1"), e("b", "1.0.0"), e("c", "1.0.0", "changed"), e("d", "2.0.0")]
        d = lockfiles.diff_entries(before, after)
        self.assertEqual(d["added"], [("a", "1.0.1"), ("d", "2.0.0")])
        self.assertEqual(d["removed"], [("a", "1.0.0")])
        self.assertEqual(d["refingerprinted"], [("c", "1.0.0")])
        self.assertEqual(lockfiles.changes_as_list(d), [
            {"name": "a", "from": "1.0.0", "to": "1.0.1"}, {"name": "d", "from": None, "to": "2.0.0"}])


class DiscoverTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def write(self, rel, text):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def test_manifest_without_lockfile_is_not_checked(self):
        self.write("package.json", '{"dependencies": {"x": "1"}}')
        self.write("api/composer.json", '{"require": {"php": ">=8.1", "a/b": "^1"}}')
        self.write("empty/package.json", '{"name": "nothing"}')
        self.write("node_modules/x/package.json", '{"dependencies": {"y": "1"}}')
        locks, nc = lockfiles.discover(self.d)
        self.assertEqual(locks, [])
        self.assertEqual(sorted(n["path"] for n in nc), ["api/composer.json", "package.json"])

    def test_workspace_member_is_covered(self):
        self.write("package.json", '{"workspaces": ["packages/*"]}')
        self.write("package-lock.json", '{"lockfileVersion": 3, "packages": {}}')
        self.write("packages/a/package.json", '{"dependencies": {"x": "1"}}')
        locks, nc = lockfiles.discover(self.d)
        self.assertEqual([l["path"] for l in locks], ["package-lock.json"])
        self.assertEqual(nc, [])


class MiniYamlTest(unittest.TestCase):
    def test_shapes(self):
        doc = miniyaml.loads(
            "a: 1\n"
            "'quoted key': \"v\"\n"
            "flow: {x: 1}\n"
            "nested:\n"
            "  k:\n"
            "    deep: yes # comment\n"
            "list:\n"
            "  - one\n"
            "  - two\n")
        self.assertEqual(doc["a"], "1")
        self.assertEqual(doc["quoted key"], "v")
        self.assertEqual(doc["flow"], "{x: 1}")
        self.assertEqual(doc["nested"]["k"]["deep"], "yes")
        self.assertEqual(doc["list"], ["one", "two"])


if __name__ == "__main__":
    unittest.main()
