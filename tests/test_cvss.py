import unittest

from tests import helpers  # noqa: F401
from sweep import cvss


class CvssTest(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), 4.0)
        self.assertEqual(cvss.base_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"), 5.9)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_not_v3(self):
        self.assertIsNone(cvss.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertIsNone(cvss.base_score(None))

    def test_labels(self):
        self.assertEqual(cvss.label(9.0), "critical")
        self.assertEqual(cvss.label(8.9), "high")
        self.assertEqual(cvss.label(None), "unknown")


if __name__ == "__main__":
    unittest.main()
