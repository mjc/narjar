#!/usr/bin/env python3
"""Measure encoder RSS while streaming regular NAR bodies to a sink."""

import argparse
import json
from pathlib import Path
import subprocess
import time


def parse_size(value: str) -> int:
    units = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
    for suffix, multiplier in units.items():
        if value.endswith(suffix):
            number = value[: -len(suffix)]
            return int(number) * multiplier
    return int(value)


def rss_kib(pid: int) -> int:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except FileNotFoundError:
        return 0
    for line in status.splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return 0


def measure(encoder: Path, size: int) -> dict[str, object]:
    command = [str(encoder), str(size)]
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak = 0
    while process.poll() is None:
        peak = max(peak, rss_kib(process.pid))
        time.sleep(0.01)
    stdout, stderr = process.communicate()
    peak = max(peak, rss_kib(process.pid))
    if process.returncode:
        raise RuntimeError(stderr or stdout)
    fields = dict(item.split("=", 1) for item in stdout.strip().split())
    if int(fields["raw_size"]) < size:
        raise RuntimeError(f"encoder emitted {fields['raw_size']} bytes for {size} bytes")
    return {
        "size_bytes": size,
        "peak_rss_kib": peak,
        "seconds": round(time.monotonic() - started, 3),
        "sha256": fields["sha256"],
        "command": command,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encoder", type=Path, default=Path("target/release/nar-encode-bench"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size", type=parse_size, action="append")
    args = parser.parse_args()

    sizes = args.size or [1 << 20, 1 << 30, 20 << 30]
    report = {
        "schema_version": 1,
        "encoder": str(args.encoder),
        "cases": [measure(args.encoder, size) for size in sizes],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
