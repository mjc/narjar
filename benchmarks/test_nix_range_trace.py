import unittest

from benchmarks.nix_range_trace import range_workload


class RangeTraceTests(unittest.TestCase):
    def test_workload_covers_start_middle_tail_and_last_byte(self) -> None:
        ranges = range_workload(10_000_000)
        starts = {start for start, _end in ranges}
        self.assertIn(0, starts)
        self.assertIn(1, starts)
        self.assertIn(5_000_000, starts)
        self.assertIn(9_000_000, starts)
        self.assertIn(9_999_999, starts)
        self.assertTrue(all(0 <= start <= end < 10_000_000 for start, end in ranges))

    def test_workload_accepts_one_mib_chunks(self) -> None:
        ranges = range_workload(10_000_000, 1_000_001)
        self.assertIn((5_000_000, 6_000_000), ranges)

    def test_rejects_empty_nar(self) -> None:
        with self.assertRaises(ValueError):
            range_workload(0)


if __name__ == "__main__":
    unittest.main()
