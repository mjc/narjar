import tempfile
import unittest
from pathlib import Path

from benchmarks.exact_dedup import aggregate_objects, load_scan, size_bucket


class ExactDedupTests(unittest.TestCase):
    def test_size_buckets_are_stable(self) -> None:
        self.assertEqual(size_bucket(1023), "<1KiB")
        self.assertEqual(size_bucket(1024), "1KiB-1MiB")
        self.assertEqual(size_bucket(1024 * 1024), "1MiB-16MiB")
        self.assertEqual(size_bucket(16 * 1024 * 1024), "16MiB-1GiB")
        self.assertEqual(size_bucket(1024 * 1024 * 1024), ">=1GiB")

    def test_repeated_file_bytes_are_verified_and_counted_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.nar"
            second = Path(directory) / "second.nar"
            first.write_bytes(b"prefixsamepayloadsuffix")
            second.write_bytes(b"other--samepayloadsuffix")
            objects = [
                {
                    "path": str(first),
                    "kind": "file",
                    "size": 12,
                    "digest": "same",
                    "offset": 6,
                    "payload_hex": "",
                },
                {
                    "path": str(second),
                    "kind": "file",
                    "size": 12,
                    "digest": "same",
                    "offset": 7,
                    "payload_hex": "",
                },
            ]
            report = aggregate_objects(objects)
            self.assertEqual(report["unique_payload_bytes"], 12)
            self.assertEqual(report["duplicate_payload_bytes"], 12)
            self.assertEqual(report["collision_count"], 0)

    def test_same_digest_with_different_bytes_is_not_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.nar"
            second = Path(directory) / "second.nar"
            first.write_bytes(b"first")
            second.write_bytes(b"other")
            objects = [
                {
                    "path": str(first),
                    "kind": "file",
                    "size": 5,
                    "digest": "forced-collision",
                    "offset": 0,
                    "payload_hex": "",
                },
                {
                    "path": str(second),
                    "kind": "file",
                    "size": 5,
                    "digest": "forced-collision",
                    "offset": 0,
                    "payload_hex": "",
                },
            ]
            report = aggregate_objects(objects)
            self.assertEqual(report["unique_payload_bytes"], 10)
            self.assertEqual(report["duplicate_payload_bytes"], 0)
            self.assertEqual(report["collision_count"], 1)

    def test_scanner_rows_are_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "scan.tsv"
            scan.write_text(
                "# narjar-nar-scan-v1\n"
                "O\tfoo.nar\tfile\t3\tabc\t10\t0\t\n"
                "N\tfoo.nar\t20\tdeadbeef\tdirectory\t1\t1\t0\n",
                encoding="utf-8",
            )
            nars, objects = load_scan(scan)
            self.assertEqual(nars[0]["raw_size"], 20)
            self.assertEqual(objects[0]["offset"], 10)


if __name__ == "__main__":
    unittest.main()
