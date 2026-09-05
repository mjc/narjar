import json
import unittest
from pathlib import Path


class NarVectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parents[1] / "docs/evidence/nar-vectors.json"
        cls.manifest = json.loads(path.read_text())

    def test_golden_vectors_are_nar_streams(self):
        for name, encoded in self.manifest["vectors"].items():
            data = bytes.fromhex(encoded)
            self.assertEqual(data[:21], b"\r\x00\x00\x00\x00\x00\x00\x00nix-archive-1")
            self.assertEqual(data[21:24], b"\x00\x00\x00")
            self.assertGreater(len(data), 16)
            self.assertEqual(len(data) % 8, 0)
            self.assertNotEqual(name, "")

    def test_required_negative_vectors_are_present(self):
        names = {case["name"] for case in self.manifest["negative_cases"]}
        self.assertEqual(
            names,
            {
                "duplicate_name", "out_of_order_name", "bad_length",
                "nonzero_padding", "unknown_tag", "truncated", "trailing_bytes",
                "empty_target", "dot_name", "slash_name", "nul_name",
            },
        )

    def test_ordering_counterexample_is_explicit(self):
        counterexample = self.manifest["ordering_counterexample"]
        self.assertEqual(counterexample["git_order"], "a. < a/")
        self.assertEqual(counterexample["nar_byte_order"], "a < a.")


if __name__ == "__main__":
    unittest.main()
