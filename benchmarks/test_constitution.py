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
    def test_current_version_preserves_thresholds_and_adds_wire_provenance(self):
        self.assertEqual(CONSTITUTION["version"], 4)
        self.assertEqual(CONSTITUTION["supersedes_version"], 3)
        self.assertIn(
            "wire_compression",
            CONSTITUTION["provenance_required_fields"],
        )
        self.assertEqual(
            CONSTITUTION["primary_savings_gate_percent"],
            {"reject_below": 25, "strong_at_or_above": 50},
        )

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

    def test_hard_gate_matrix_covers_every_frozen_budget(self):
        self.assertEqual(
            set(CONSTITUTION["hard_gates"]),
            {
                "active_memory_per_operation_mib_max",
                "aggressive_delta_additional_savings_percent_min",
                "backup_restore_verify_required",
                "compaction_configured_segments_max",
                "compaction_second_full_cache_copy_allowed",
                "delta_max_chain_depth",
                "delta_max_reconstructed_unit_mib",
                "dependency_advisories_max",
                "dependency_report_required",
                "dependency_rust_minimum",
                "full_get_cpu_ratio_max",
                "full_get_throughput_ratio_min",
                "gix_delta_additional_savings_percentage_points_min",
                "gix_delta_admission_logic",
                "gix_delta_relative_improvement_percent_min",
                "hybrid_cache_max_logical_live_percent",
                "hybrid_cache_trace_hit_rate_min_percent",
                "idle_rss_mib_max",
                "idle_rss_ratio_to_flat_max",
                "ingest_cpu_per_gib_ratio_max",
                "ingest_temporary_space_bounded_required",
                "ingest_wall_ratio_max",
                "ingest_whole_nar_buffering_allowed",
                "offline_peak_rss_mib_max",
                "offline_wall_ratio_max",
                "read_amplification_additive_mib_max",
                "read_amplification_ratio_max",
                "replication_bytes_max_multiplier_new_physical",
                "replication_bytes_max_percent_live_physical",
                "resume_ttfb_p95_ratio_max",
                "security_auth_and_secret_log_tests_required",
                "startup_ms_max",
                "startup_p95_ratio_to_flat_max",
            },
        )

    def test_exact_decision_boundaries(self):
        self.assertEqual(classify(24.999), "reject")
        self.assertEqual(classify(25), "conditional")
        self.assertEqual(classify(49.999), "conditional")
        self.assertEqual(classify(50), "strong")

    def test_missing_provenance_is_rejected(self):
        complete = {field: "present" for field in CONSTITUTION["provenance_required_fields"]}
        self.assertEqual(validate_provenance(complete), [])
        for field in CONSTITUTION["provenance_required_fields"]:
            for missing in (None, "", [], {}):
                with self.subTest(field=field, missing=missing):
                    incomplete = complete | {field: missing}
                    self.assertIn(field, validate_provenance(incomplete))
            incomplete = complete.copy()
            incomplete.pop(field)
            self.assertIn(field, validate_provenance(incomplete))

    def test_missing_metrics_is_rejected(self):
        complete = {field: 1 for field in CONSTITUTION["metric_required_fields"]}
        self.assertEqual(validate_metrics(complete), [])
        for field in CONSTITUTION["metric_required_fields"]:
            for missing in (None, "", [], {}):
                with self.subTest(field=field, missing=missing):
                    incomplete = complete | {field: missing}
                    self.assertIn(field, validate_metrics(incomplete))
            incomplete = complete.copy()
            incomplete.pop(field)
            self.assertIn(field, validate_metrics(incomplete))

    def test_nested_evidence_record_is_validated(self):
        provenance = {
            field: "present" for field in CONSTITUTION["provenance_required_fields"]
        }
        metric = {field: 1 for field in CONSTITUTION["metric_required_fields"]}
        self.assertEqual(
            validate_provenance({"provenance": provenance, "metric": metric}), []
        )
        self.assertEqual(
            validate_metrics({"provenance": provenance, "metric": metric}), []
        )


if __name__ == "__main__":
    unittest.main()
