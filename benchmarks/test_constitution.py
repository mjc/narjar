import unittest

from evaluate_constitution import classify, validate_provenance


class ConstitutionTest(unittest.TestCase):
    def test_exact_decision_boundaries(self):
        self.assertEqual(classify(24.999), "reject")
        self.assertEqual(classify(25), "conditional")
        self.assertEqual(classify(49.999), "conditional")
        self.assertEqual(classify(50), "strong")

    def test_missing_provenance_is_rejected(self):
        self.assertIn("commit", validate_provenance({"savings_percent": 25}))
        self.assertIn("repetitions", validate_provenance({"savings_percent": 25}))


if __name__ == "__main__":
    unittest.main()
