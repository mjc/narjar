#!/usr/bin/env python3
"""Compare decoder-to-encoder output with raw NAR files without buffering them."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time


# Keep each producer write below a normal Linux pipe capacity. The encoder's
# output is consumed immediately after each write, avoiding a stdin/stdout
# pipe deadlock while retaining bounded buffering.
CHUNK_SIZE = 16 * 1024


def read_exact(stream, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def compare(path: Path, reencoder: Path) -> dict[str, object]:
    started = time.monotonic()
    command = [str(reencoder)]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    offset = 0
    first_difference = None
    digest = hashlib.sha256()
    feed_errors: list[BaseException] = []

    def feed() -> None:
        try:
            assert process.stdin is not None
            with path.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    process.stdin.write(chunk)
                    process.stdin.flush()
            process.stdin.close()
        except BaseException as error:  # propagate after stdout is drained
            feed_errors.append(error)

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    try:
        with path.open("rb") as source:
            while chunk := source.read(CHUNK_SIZE):
                digest.update(chunk)
                assert process.stdout is not None
                encoded = read_exact(process.stdout, len(chunk))
                if first_difference is None and encoded != chunk:
                    common = min(len(encoded), len(chunk))
                    for index in range(common):
                        if encoded[index] != chunk[index]:
                            first_difference = offset + index
                            break
                    if first_difference is None:
                        first_difference = offset + common
                offset += len(chunk)
        feeder.join()
        assert process.stdout is not None
        extra = process.stdout.read(1)
        if extra and first_difference is None:
            first_difference = offset
        stderr = process.stderr.read().decode("utf-8", errors="replace") if process.stderr else ""
        returncode = process.wait()
    except Exception:
        process.kill()
        feeder.join()
        process.wait()
        raise
    if feed_errors:
        raise feed_errors[0]

    return {
        "path": str(path),
        "size_bytes": offset,
        "sha256": digest.hexdigest(),
        "equal": first_difference is None and returncode == 0,
        "first_difference": first_difference,
        "returncode": returncode,
        "stderr": stderr.strip(),
        "command": command,
        "seconds": round(time.monotonic() - started, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--reencoder", type=Path, default=Path("target/release/nar-reencode"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    paths = sorted(args.root.rglob("*.nar"))
    results = [compare(path, args.reencoder) for path in paths]
    report = {
        "schema_version": 1,
        "encoder": str(args.reencoder),
        "artifact_root": str(args.root),
        "nar_count": len(results),
        "equal_count": sum(result["equal"] is True for result in results),
        "mismatch_count": sum(result["equal"] is not True for result in results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in report if key != "results"}, indent=2))
    return 0 if report["mismatch_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
