import unittest
import json
from pathlib import Path

from evaluate_constitution import (
    CONSTITUTION,
    classify,
    validate_metrics,
    validate_provenance,
)


class ConstitutionTest(unittest.TestCase):
    def test_corpus_manifest_matches_frozen_categories(self):
        root = Path(__file__).parent
        constitution = json.loads((root / "constitution.json").read_text())
        manifest = json.loads((root / "corpus-manifest.json").read_text())
        names = [slice_["name"] for slice_ in manifest["slices"]]
        self.assertEqual(names, constitution["corpus_categories"])
        self.assertEqual([slice_["weight"] for slice_ in manifest["slices"]], [1] * 6)
        self.assertEqual(manifest["selection_protocol"]["cherry_picking"], "forbidden")

    def test_distinct_delta_and_read_amplification_gates_are_frozen(self):
        gates = CONSTITUTION["hard_gates"]
        self.assertEqual(gates["gix_delta_additional_savings_percentage_points_min"], 10)
        self.assertEqual(gates["gix_delta_relative_improvement_percent_min"], 15)
        self.assertEqual(gates["aggressive_delta_additional_savings_percent_min"], 15)
        self.assertEqual(gates["read_amplification_additive_mib_max"], 1)

    def test_exact_decision_boundaries(self):
        self.assertEqual(classify(24.999), "reject")
        self.assertEqual(classify(25), "conditional")
        self.assertEqual(classify(49.999), "conditional")
        self.assertEqual(classify(50), "strong")

    def test_missing_provenance_is_rejected(self):
        complete = {field: "present" for field in CONSTITUTION["provenance_required_fields"]}
        self.assertEqual(validate_provenance(complete), [])
        for field in CONSTITUTION["provenance_required_fields"]:
            incomplete = complete | {field: None}
            incomplete.pop(field)
            self.assertIn(field, validate_provenance(incomplete))

    def test_missing_metrics_is_rejected(self):
        complete = {field: 1 for field in CONSTITUTION["metric_required_fields"]}
        self.assertEqual(validate_metrics(complete), [])
        for field in CONSTITUTION["metric_required_fields"]:
            incomplete = complete.copy()
            incomplete.pop(field)
            self.assertIn(field, validate_metrics(incomplete))


if __name__ == "__main__":
    unittest.main()
