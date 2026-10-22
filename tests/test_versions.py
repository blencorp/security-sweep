import unittest

from tests import helpers  # noqa: F401
from sweep import versions as V


class SemverTest(unittest.TestCase):
    def test_order(self):
        seq = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]
        parsed = [V.parse_semver(s) for s in seq]
        self.assertEqual(parsed, sorted(parsed))

    def test_parse_rejects_partial(self):
        self.assertIsNone(V.parse_semver("1.2"))
        self.assertIsNone(V.parse_semver("latest"))

    def test_caret(self):
        self.assertTrue(V.npm_satisfies("1.9.9", "^1.2.3"))
        self.assertFalse(V.npm_satisfies("2.0.0", "^1.2.3"))
        self.assertTrue(V.npm_satisfies("0.2.9", "^0.2.3"))
        self.assertFalse(V.npm_satisfies("0.3.0", "^0.2.3"))
        self.assertFalse(V.npm_satisfies("0.0.4", "^0.0.3"))

    def test_tilde_and_x(self):
        self.assertTrue(V.npm_satisfies("1.2.9", "~1.2.3"))
        self.assertFalse(V.npm_satisfies("1.3.0", "~1.2.3"))
        self.assertTrue(V.npm_satisfies("1.5.0", "1.x"))
        self.assertTrue(V.npm_satisfies("3.0.0", "*"))

    def test_comparators_and_or(self):
        self.assertTrue(V.npm_satisfies("1.5.0", ">=1.2.0 <2.0.0"))
        self.assertFalse(V.npm_satisfies("2.0.0", ">=1.2.0 <2.0.0"))
        self.assertTrue(V.npm_satisfies("22.23.2", "^22.23.2 || ^24.18.1"))
        self.assertFalse(V.npm_satisfies("22.23.1", "^22.23.2 || ^24.18.1"))
        self.assertTrue(V.npm_satisfies("8.0.0", "<= 8.x"))
        self.assertFalse(V.npm_satisfies("9.0.0", "<= 8.x"))

    def test_hyphen(self):
        self.assertTrue(V.npm_satisfies("1.5.0", "1.2.3 - 2.3"))
        self.assertTrue(V.npm_satisfies("2.3.9", "1.2.3 - 2.3"))
        self.assertFalse(V.npm_satisfies("2.4.0", "1.2.3 - 2.3"))

    def test_prerelease_needs_same_tuple(self):
        self.assertFalse(V.npm_satisfies("1.3.0-beta.1", "^1.2.0"))
        self.assertTrue(V.npm_satisfies("1.2.0-beta.2", ">=1.2.0-beta.1 <2.0.0"))

    def test_not_a_range(self):
        with self.assertRaises(ValueError):
            V.parse_npm_range("git+https://github.com/x/y.git")


class ComposerTest(unittest.TestCase):
    def test_order(self):
        seq = ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0", "1.0.0-p1", "1.0.1", "v1.10"]
        parsed = [V.parse_composer(s) for s in seq]
        self.assertEqual(parsed, sorted(parsed))

    def test_branches_have_no_order(self):
        self.assertIsNone(V.parse_composer("dev-main"))
        self.assertIsNone(V.parse_composer("2.x-dev"))

    def test_v_prefix(self):
        self.assertEqual(V.composer_key("v2.5.4"), V.composer_key("2.5.4"))

    def test_caret(self):
        self.assertTrue(V.composer_satisfies("1.9.0", "^1.2.3"))
        self.assertFalse(V.composer_satisfies("2.0.0", "^1.2.3"))
        self.assertTrue(V.composer_satisfies("0.3.9", "^0.3"))
        self.assertFalse(V.composer_satisfies("0.4.0", "^0.3"))
        self.assertFalse(V.composer_satisfies("1.2.2", "^1.2.3"))

    def test_tilde(self):
        self.assertTrue(V.composer_satisfies("1.9.0", "~1.2"))
        self.assertFalse(V.composer_satisfies("2.0.0", "~1.2"))
        self.assertTrue(V.composer_satisfies("1.2.9", "~1.2.3"))
        self.assertFalse(V.composer_satisfies("1.3.0", "~1.2.3"))

    def test_or_and_wildcard(self):
        self.assertTrue(V.composer_satisfies("2.4.5", "^1.8.3 || ^2.1"))
        self.assertTrue(V.composer_satisfies("1.9.1", "^1.8.3|^2.1"))
        self.assertTrue(V.composer_satisfies("5.4.9", "5.4.*"))
        self.assertFalse(V.composer_satisfies("5.5.0", "5.4.*"))
        self.assertTrue(V.composer_satisfies("1.5", ">=1.0, <2.0"))
        self.assertTrue(V.composer_satisfies("1.5", ">=1.0 <2.0"))
        self.assertFalse(V.composer_satisfies("1.5.0", "!=1.5.0"))


class LineTest(unittest.TestCase):
    def test_same_line(self):
        self.assertTrue(V.same_line("npm", "4.17.1", "4.19.2"))
        self.assertFalse(V.same_line("npm", "2.7.4", "3.1.7"))
        self.assertFalse(V.same_line("npm", "0.3.1", "0.4.0"))
        self.assertTrue(V.same_line("Packagist", "v2.1.0", "2.4.5"))


class DistroTest(unittest.TestCase):
    def test_dpkg(self):
        self.assertEqual(V.dpkg_compare("8.2.29-1~deb12u1", "8.2.29-1"), -1)
        self.assertEqual(V.dpkg_compare("8.2.30-1~deb12u1", "8.2.29-1~deb12u1"), 1)
        self.assertEqual(V.dpkg_compare("1:1.0-1", "2.0-1"), 1)
        self.assertEqual(V.dpkg_compare("1.0~rc1-1", "1.0-1"), -1)
        self.assertEqual(V.dpkg_compare("1.0-1", "1.0-1"), 0)
        self.assertEqual(V.dpkg_compare("1.0.10", "1.0.9"), 1)

    def test_apk(self):
        self.assertEqual(V.apk_compare("8.2.28-r0", "8.2.27-r1"), 1)
        self.assertEqual(V.apk_compare("8.2.28-r1", "8.2.28-r0"), 1)
        self.assertEqual(V.apk_compare("1.0_rc1-r0", "1.0-r0"), -1)


if __name__ == "__main__":
    unittest.main()
