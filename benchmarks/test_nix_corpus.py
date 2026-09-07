import hashlib
import tempfile
import unittest
from pathlib import Path

from benchmarks.nix_corpus import sri_sha256, validate_manifest


def entry(path: str = "/nix/store/example") -> dict:
    return {
        "path": path,
        "nar_hash": sri_sha256(hashlib.sha256(b"nar").hexdigest()),
        "nar_size": 3,
        "artifact_sha256": hashlib.sha256(b"nar").hexdigest(),
        "artifact": "example.nar",
        "targets": ["generation-1"],
        "machines": ["tina"],
        "families": ["nixos"],
        "generations": ["1"],
        "nixpkgs_revisions": ["abc"],
        "flake_refs": ["flake"],
        "derivations": [],
    }


class CorpusManifestTests(unittest.TestCase):
    def test_valid_manifest_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example.nar").write_bytes(b"nar")
            manifest = {
                "schema_version": 1,
                "requirements": {},
                "subsets": {"core": {"entries": ["/nix/store/example"]}},
                "entries": [entry()],
            }
            self.assertEqual(validate_manifest(manifest, root), [])

    def test_duplicate_and_unknown_subset_are_rejected(self) -> None:
        manifest = {
            "schema_version": 1,
            "requirements": {},
            "subsets": {"core": {"entries": ["/nix/store/missing"]}},
            "entries": [entry(), entry()],
        }
        errors = validate_manifest(manifest)
        self.assertTrue(any("duplicate path" in error for error in errors))
        self.assertTrue(any("unknown paths" in error for error in errors))

    def test_coverage_requirements_are_enforced(self) -> None:
        manifest = {
            "schema_version": 1,
            "requirements": {"min_generations": 2, "min_nixpkgs_revisions": 2},
            "subsets": {"core": {"entries": ["/nix/store/example"]}},
            "entries": [entry()],
        }
        errors = validate_manifest(manifest)
        self.assertTrue(any("generations" in error for error in errors))
        self.assertTrue(any("nixpkgs revisions" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
