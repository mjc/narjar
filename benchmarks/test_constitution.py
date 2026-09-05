import unittest
import json
from pathlib import Path

from evaluate_constitution import classify, validate_metrics, validate_provenance


class ConstitutionTest(unittest.TestCase):
    def test_corpus_manifest_matches_frozen_categories(self):
        root = Path(__file__).parent
        constitution = json.loads((root / "constitution.json").read_text())
        manifest = json.loads((root / "corpus-manifest.json").read_text())
        names = [slice_["name"] for slice_ in manifest["slices"]]
        self.assertEqual(names, constitution["corpus_categories"])
        self.assertEqual(sum(slice_["weight_percent"] for slice_ in manifest["slices"]), 100.0000002)

    def test_exact_decision_boundaries(self):
        self.assertEqual(classify(24.999), "reject")
        self.assertEqual(classify(25), "conditional")
        self.assertEqual(classify(49.999), "conditional")
        self.assertEqual(classify(50), "strong")

    def test_missing_provenance_is_rejected(self):
        self.assertIn("commit", validate_provenance({"savings_percent": 25}))
        self.assertIn("repetitions", validate_provenance({"savings_percent": 25}))

    def test_missing_metrics_is_rejected(self):
        record = {
            "commit": "abc",
            "host": "tina",
            "filesystem": "zfs",
            "command": "benchmark",
            "cache_state": "warm",
            "repetitions": 15,
        }
        self.assertEqual(validate_metrics(record), ["median", "p95", "savings_percent", "unit"])


if __name__ == "__main__":
    unittest.main()
