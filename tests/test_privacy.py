import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tests import helpers
from sweep import lockfiles, privacy

LF = os.path.join(helpers.FIXTURES, "lockfiles")


def load(name):
    with open(os.path.join(LF, name), "rb") as f:
        return f.read()


class SanitizeTest(unittest.TestCase):
    """mkdirp stands in for a private package in these lockfiles."""

    def check(self, manager, name):
        content = load(name)
        out, removed = privacy.sanitize(manager, content, ["mkdirp"])
        self.assertGreaterEqual(removed, 1)
        names = {e["name"] for e in lockfiles.parse(manager, out, None)}
        self.assertNotIn("mkdirp", names)
        self.assertIn("minimist", names)
        self.assertIn("ejs", names)

    def test_npm(self):
        self.check("npm", "package-lock.json")

    def test_yarn_classic(self):
        self.check("yarn-classic", "yarn-classic.lock")

    def test_yarn_berry(self):
        self.check("yarn-berry", "yarn-berry.lock")

    def test_pnpm(self):
        self.check("pnpm", "pnpm-lock.yaml")

    def test_composer(self):
        out, removed = privacy.sanitize("composer", load("composer.lock"), ["guzzlehttp/*"])
        names = {e["name"] for e in lockfiles.parse("composer", out, None)}
        self.assertFalse([n for n in names if n.startswith("guzzlehttp/")])
        self.assertIn("psr/http-message", names)
        self.assertEqual(removed, 3)

    def test_no_patterns_is_identity(self):
        content = load("package-lock.json")
        self.assertEqual(privacy.sanitize("npm", content, []), (content, 0))

    def test_glob_case_insensitive(self):
        self.assertTrue(privacy.is_private("@Acme/billing", ["@acme/*"]))
        self.assertFalse(privacy.is_private("@acmex/billing", ["@acme/*"]))

    def test_fails_closed(self):
        with mock.patch.object(privacy, "_sanitize", lambda m, c, p: (c, 0)):
            with self.assertRaises(privacy.LeakError):
                privacy.sanitize("npm", load("package-lock.json"), ["mkdirp"])


class PatternsTest(unittest.TestCase):
    def test_sources_merge(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, ".security-sweep.json"), "w") as f:
                json.dump({"private": ["@acme/*", "acme/*"]}, f)
            with mock.patch.dict(os.environ, {"SECURITY_SWEEP_PRIVATE": "@corp/*, acme/*"}):
                self.assertEqual(privacy.load_patterns(d, ["internal-*"]),
                                 ["internal-*", "@corp/*", "acme/*", "@acme/*"])
        finally:
            shutil.rmtree(d)

    def test_bad_config(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, ".security-sweep.json"), "w") as f:
                f.write('{"private": "@acme/*"}')
            with self.assertRaises(ValueError):
                privacy.load_patterns(d)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
