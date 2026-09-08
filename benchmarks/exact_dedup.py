#!/usr/bin/env python3
"""Measure exact regular-file and symlink-target reuse in a NAR corpus.

The Rust ``nar-scan`` binary is the only NAR parser. This script owns corpus
metadata, exact duplicate verification, slices, and the machine-readable
report. It never opens or changes a Narjar data directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Any, Iterable


def hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"invalid hexadecimal payload {value[:32]!r}") from exc


def compare_file_ranges(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left["size"] != right["size"]:
        return False
    if left["kind"] != "file" or right["kind"] != "file":
        return left.get("payload_hex") == right.get("payload_hex")
    length = int(left["size"])
    with Path(left["path"]).open("rb") as left_file, Path(right["path"]).open("rb") as right_file:
        left_file.seek(int(left["offset"]))
        right_file.seek(int(right["offset"]))
        while length:
            amount = min(length, 1024 * 1024)
            if left_file.read(amount) != right_file.read(amount):
                return False
            length -= amount
    return True


def verify_objects(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    representatives: dict[tuple[str, int, str], list[tuple[int, dict[str, Any]]]] = {}
    verified_keys: set[tuple[str, int, str]] = set()
    next_identity = 0
    for object_record in objects:
        key = (object_record["kind"], int(object_record["size"]), object_record["digest"])
        candidates = representatives.setdefault(key, [])
        if key in verified_keys:
            object_record["_identity"] = candidates[0][0]
            object_record["_collision"] = False
            continue
        for identity, representative in candidates:
            if compare_file_ranges(representative, object_record):
                object_record["_identity"] = identity
                object_record["_collision"] = False
                if len(candidates) == 1:
                    verified_keys.add(key)
                break
        else:
            object_record["_identity"] = next_identity
            object_record["_collision"] = bool(candidates)
            candidates.append((next_identity, object_record))
            next_identity += 1
    return objects


def aggregate_objects(objects: Iterable[dict[str, Any]], minimum_size: int = 0) -> dict[str, Any]:
    total_bytes = 0
    unique_bytes = 0
    collisions = 0
    first: dict[tuple[str, int, str | int], dict[str, Any]] = {}
    unique_objects = 0
    occurrences = 0
    for object_record in objects:
        size = int(object_record["size"])
        if size < minimum_size:
            continue
        occurrences += 1
        total_bytes += size
        identity = object_record.get("_identity")
        if identity is not None:
            key = (object_record["kind"], size, int(identity))
        else:
            key = (object_record["kind"], size, object_record["digest"])
        previous = first.get(key)
        if previous is None:
            first[key] = object_record
            unique_objects += 1
            unique_bytes += size
            collisions += int(object_record.get("_collision", False))
        elif identity is not None:
            continue
        elif not compare_file_ranges(previous, object_record):
            collisions += 1
            unique_objects += 1
            unique_bytes += size
    return {
        "occurrences": occurrences,
        "unique_objects": unique_objects,
        "total_payload_bytes": total_bytes,
        "unique_payload_bytes": unique_bytes,
        "duplicate_payload_bytes": total_bytes - unique_bytes,
        "collision_count": collisions,
    }


def aggregate_nars(nars: Iterable[dict[str, Any]]) -> dict[str, Any]:
    records = list(nars)
    logical_bytes = sum(int(record["raw_size"]) for record in records)
    first: dict[tuple[int, str], dict[str, Any]] = {}
    unique_bytes = 0
    collisions = 0
    for record in records:
        key = (int(record["raw_size"]), record["raw_sha256"])
        previous = first.get(key)
        if previous is None:
            first[key] = record
            unique_bytes += int(record["raw_size"])
        elif not compare_file_ranges(
            {
                "kind": "file",
                "size": record["raw_size"],
                "path": record["path"],
                "offset": 0,
            },
            {
                "kind": "file",
                "size": previous["raw_size"],
                "path": previous["path"],
                "offset": 0,
            },
        ):
            collisions += 1
            unique_bytes += int(record["raw_size"])
    return {
        "artifact_occurrences": len(records),
        "logical_nar_bytes": logical_bytes,
        "unique_nar_bytes": unique_bytes,
        "duplicate_nar_bytes": logical_bytes - unique_bytes,
        "collision_count": collisions,
    }


def load_scan(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nars: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            fields = line.rstrip("\n").split("\t")
            if not fields or fields[0].startswith("#"):
                continue
            if fields[0] == "N" and len(fields) == 8:
                nars.append(
                    {
                        "path": fields[1],
                        "raw_size": int(fields[2]),
                        "raw_sha256": fields[3],
                        "root": fields[4],
                        "entries": int(fields[5]),
                        "files": int(fields[6]),
                        "symlinks": int(fields[7]),
                    }
                )
            elif fields[0] == "O" and len(fields) == 8:
                objects.append(
                    {
                        "path": fields[1],
                        "kind": fields[2],
                        "size": int(fields[3]),
                        "digest": fields[4],
                        "offset": None if fields[5] == "-" else int(fields[5]),
                        "executable": bool(int(fields[6])),
                        "payload_hex": fields[7],
                    }
                )
            else:
                raise ValueError(f"invalid scanner row at {path}:{line_number}")
    return nars, objects


def artifact_path(entry: dict[str, Any], artifact_root: Path | None) -> Path:
    original = Path(entry["artifact"])
    if original.exists() or artifact_root is None:
        return original
    return artifact_root / original.name


def values(entry: dict[str, Any], field: str) -> list[str]:
    value = entry.get(field)
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return ["unknown"]
    return [str(value)]


def size_bucket(size: int) -> str:
    if size < 1024:
        return "<1KiB"
    if size < 1024 * 1024:
        return "1KiB-1MiB"
    if size < 16 * 1024 * 1024:
        return "1MiB-16MiB"
    if size < 1024 * 1024 * 1024:
        return "16MiB-1GiB"
    return ">=1GiB"


def build_slices(entries: list[dict[str, Any]]) -> dict[str, dict[str, set[str]]]:
    slices: dict[str, dict[str, set[str]]] = {
        "all": {"all": set()},
        "targets": {},
        "machines": {},
        "families": {},
        "generations": {},
        "subsets": {},
    }
    for entry in entries:
        artifact = str(entry["artifact"])
        slices["all"]["all"].add(artifact)
        for dimension, field in (
            ("targets", "targets"),
            ("machines", "machines"),
            ("families", "families"),
            ("generations", "generations"),
            ("subsets", "subset"),
        ):
            for value in values(entry, field):
                slices[dimension].setdefault(value, set()).add(artifact)
    return slices


def run_scanner(scanner: Path, artifact_paths: list[Path], output: Path, command_log: Path) -> None:
    input_list = output.with_suffix(".inputs.txt")
    input_list.write_text("".join(f"{path}\n" for path in artifact_paths), encoding="utf-8")
    command = [str(scanner), "--input-list", str(input_list), "--output", str(output)]
    with command_log.open("w", encoding="utf-8") as log:
        log.write("$ " + shlex.join(command) + "\n")
        result = subprocess.run(command, text=True, capture_output=True)
        if result.stdout:
            log.write(result.stdout)
        if result.stderr:
            log.write(result.stderr)
        if result.returncode:
            raise RuntimeError(f"scanner failed with exit code {result.returncode}")


def make_report(
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    nars: list[dict[str, Any]],
    objects: list[dict[str, Any]],
    thresholds: list[int],
    object_overhead_bytes: int,
) -> dict[str, Any]:
    by_path = {record["path"]: record for record in nars}
    object_by_path: dict[str, list[dict[str, Any]]] = {}
    for record in objects:
        object_by_path.setdefault(record["path"], []).append(record)

    slices = build_slices(entries)
    slice_reports: dict[str, dict[str, Any]] = {}
    for dimension, groups in slices.items():
        slice_reports[dimension] = {}
        for name, paths in groups.items():
            selected_objects = [
                object_record
                for path in paths
                for object_record in object_by_path.get(path, [])
            ]
            stats = aggregate_objects(selected_objects)
            stats["estimated_object_overhead_bytes"] = (
                stats["unique_objects"] * object_overhead_bytes
            )
            stats["artifact_files"] = len(paths)
            stats["nar"] = aggregate_nars(
                [by_path[path] for path in paths if path in by_path]
            )
            slice_reports[dimension][name] = stats

    report = {
        "schema_version": 1,
        "manifest_schema_version": manifest.get("schema_version"),
        "manifest_entries": len(entries),
        "scanner_artifacts": len(nars),
        "objects": aggregate_objects(objects),
        "size_buckets": {
            bucket: aggregate_objects(
                [record for record in objects if size_bucket(int(record["size"])) == bucket]
            )
            for bucket in ("<1KiB", "1KiB-1MiB", "1MiB-16MiB", "16MiB-1GiB", ">=1GiB")
        },
        "nar": aggregate_nars(nars),
        "slices": slice_reports,
        "thresholds": {
            str(threshold): aggregate_objects(objects, threshold) for threshold in thresholds
        },
        "object_overhead_bytes": object_overhead_bytes,
        "whole_nar_deduplication": {
            "logical_manifest_nar_bytes": sum(int(entry.get("nar_size", 0)) for entry in entries),
            "unique_artifact_nar_bytes": sum(
                int(record["raw_size"]) for record in {record["path"]: record for record in nars}.values()
            ),
        },
    }
    report["whole_nar_deduplication"]["already_whole_nar_deduplicated_bytes"] = (
        report["whole_nar_deduplication"]["logical_manifest_nar_bytes"]
        - report["whole_nar_deduplication"]["unique_artifact_nar_bytes"]
    )
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--scanner", type=Path, default=Path("target/release/nar-scan"))
    parser.add_argument("--scan", type=Path, help="reuse an existing nar-scan TSV")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threshold", type=int, action="append", default=[0])
    parser.add_argument("--object-overhead-bytes", type=int, default=128)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise SystemExit("manifest has no entries")
    artifact_paths = [artifact_path(entry, args.artifact_root) for entry in entries]
    missing = [str(path) for path in sorted(set(artifact_paths)) if not path.is_file()]
    if missing:
        raise SystemExit(f"missing artifact: {missing[0]}")
    args.output.mkdir(parents=True)
    scan_path = args.scan or args.output / "objects.tsv"
    if args.scan is None:
        run_scanner(args.scanner, sorted(set(artifact_paths)), scan_path, args.output / "commands.txt")
    else:
        shutil.copyfile(args.scan, args.output / "objects.tsv")
        (args.output / "commands.txt").write_text(
            "$ reused " + shlex.join([str(args.scan)]) + "\n", encoding="utf-8"
        )
    nars, objects = load_scan(scan_path)
    objects = verify_objects(objects)
    resolved_entries = [
        {**entry, "artifact": str(path)} for entry, path in zip(entries, artifact_paths, strict=True)
    ]
    report = make_report(
        manifest,
        resolved_entries,
        nars,
        objects,
        sorted(set(args.threshold)),
        args.object_overhead_bytes,
    )
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
