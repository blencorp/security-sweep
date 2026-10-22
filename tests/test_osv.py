import unittest

from tests import helpers  # noqa: F401
from sweep import osv


def vuln(ranges=None, versions=None, eco="npm", name="pkg", **extra):
    v = {"id": "GHSA-test", "aliases": ["CVE-2099-0001"],
         "affected": [{"package": {"ecosystem": eco, "name": name},
                       "ranges": ranges or [], "versions": versions or []}]}
    v.update(extra)
    return v


class AffectsTest(unittest.TestCase):
    def test_introduced_fixed(self):
        v = vuln([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}])
        self.assertTrue(osv.affects(v, "npm", "pkg", "1.2.5"))
        self.assertFalse(osv.affects(v, "npm", "pkg", "1.2.6"))
        self.assertFalse(osv.affects(v, "npm", "other", "1.2.5"))

    def test_multiple_windows(self):
        v = vuln([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"},
                                                {"introduced": "2.0.0"}, {"fixed": "2.0.3"}]}])
        self.assertTrue(osv.affects(v, "npm", "pkg", "2.0.1"))
        self.assertFalse(osv.affects(v, "npm", "pkg", "1.9.0"))
        self.assertFalse(osv.affects(v, "npm", "pkg", "2.0.3"))

    def test_last_affected(self):
        v = vuln([{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]}])
        self.assertTrue(osv.affects(v, "npm", "pkg", "1.4.0"))
        self.assertFalse(osv.affects(v, "npm", "pkg", "1.4.1"))

    def test_versions_list_and_packagist_case(self):
        v = vuln(versions=["v2.1.0"], eco="Packagist", name="Guzzle/PSR7")
        self.assertTrue(osv.affects(v, "Packagist", "guzzle/psr7", "2.1.0"))
        v = vuln([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.4.5"}]}],
                 eco="Packagist", name="guzzlehttp/psr7")
        self.assertTrue(osv.affects(v, "Packagist", "guzzlehttp/psr7", "v2.1.0"))
        self.assertFalse(osv.affects(v, "Packagist", "guzzlehttp/psr7", "2.4.5"))

    def test_git_ranges_ignored(self):
        v = vuln([{"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}])
        self.assertFalse(osv.affects(v, "npm", "pkg", "1.0.0"))


class SeverityTest(unittest.TestCase):
    def test_label_beats_score(self):
        v = vuln(database_specific={"severity": "CRITICAL"},
                 severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}])
        self.assertEqual(osv.severity(v), ("critical", 4.0))

    def test_vector_then_hint(self):
        v = vuln(severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        self.assertEqual(osv.severity(v), ("critical", 9.8))
        self.assertEqual(osv.severity(vuln(), "7.5"), ("high", 7.5))
        self.assertEqual(osv.severity(vuln()), ("unknown", None))

    def test_malicious(self):
        self.assertTrue(osv.is_malicious({"id": "MAL-2024-1"}))
        self.assertFalse(osv.is_malicious({"id": "GHSA-x", "aliases": []}))

    def test_workaround(self):
        v = {"details": "### Impact\nbad\n\n### Workarounds\nDisable the feature.\n\n### References\nx"}
        self.assertEqual(osv.workaround(v), "Disable the feature.")
        self.assertIsNone(osv.workaround({"details": "### Impact\nbad"}))


if __name__ == "__main__":
    unittest.main()
