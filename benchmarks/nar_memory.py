#!/usr/bin/env python3
"""Measure nar-scan RSS while consuming generated regular-file NAR streams."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from typing import Any


CHUNK_SIZE = 1024 * 1024


def nar_string(value: bytes) -> bytes:
    padding = (-len(value)) % 8
    return len(value).to_bytes(8, "little") + value + bytes(padding)


def nar_prefix(size: int) -> bytes:
    return b"".join(
        (
            nar_string(b"nix-archive-1"),
            nar_string(b"("),
            nar_string(b"type"),
            nar_string(b"regular"),
            nar_string(b"contents"),
            size.to_bytes(8, "little"),
        )
    )


def parse_size(value: str) -> int:
    units = {"": 1, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}
    for suffix, multiplier in sorted(units.items(), key=lambda item: len(item[0]), reverse=True):
        if suffix and value.endswith(suffix):
            number = value[: -len(suffix)] if suffix else value
            size = int(number) * multiplier
            if size <= 0:
                raise argparse.ArgumentTypeError("size must be positive")
            return size
    try:
        size = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("size must use B, KiB, MiB, or GiB") from exc
    if size <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return size


def write_nar(fifo: Path, size: int) -> None:
    with fifo.open("wb", buffering=0) as output:
        output.write(nar_prefix(size))
        zeroes = bytes(CHUNK_SIZE)
        remaining = size
        while remaining:
            amount = min(remaining, len(zeroes))
            output.write(zeroes[:amount])
            remaining -= amount
        output.write(bytes((-size) % 8))
        output.write(nar_string(b")"))


def rss_kib(pid: int) -> int:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except FileNotFoundError:
        return 0
    for line in status.splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return 0


def measure(scanner: Path, size: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="narjar-memory-") as directory:
        root = Path(directory)
        fifo = root / "input.nar"
        input_list = root / "inputs.txt"
        os.mkfifo(fifo)
        input_list.write_text(f"{fifo}\n", encoding="utf-8")
        command = [str(scanner), "--input-list", str(input_list), "--output", os.devnull]
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        writer = threading.Thread(target=write_nar, args=(fifo, size), daemon=True)
        writer.start()
        peak = 0
        while process.poll() is None:
            peak = max(peak, rss_kib(process.pid))
            time.sleep(0.01)
        writer.join()
        stdout, stderr = process.communicate()
        peak = max(peak, rss_kib(process.pid))
        if process.returncode:
            raise RuntimeError(stderr or stdout)
        return {
            "size_bytes": size,
            "peak_rss_kib": peak,
            "seconds": round(time.monotonic() - started, 3),
            "command": command,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", type=Path, default=Path("target/release/nar-scan"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size", type=parse_size, action="append")
    args = parser.parse_args()
    sizes = args.size or [1 << 20, 1 << 30, 20 << 30]
    report = {
        "schema_version": 1,
        "scanner": str(args.scanner),
        "generated_zero_stream": True,
        "results": [measure(args.scanner, size) for size in sizes],
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
