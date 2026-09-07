#!/usr/bin/env python3
"""Collect and validate a reproducible corpus of real Nix NARs.

The spec is JSON on purpose: it works in the existing dev shell and keeps the
corpus contract reviewable without adding a parser dependency.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Iterable


SCHEMA_VERSION = 1
REQUIRED_ENTRY_FIELDS = {
    "path",
    "nar_hash",
    "nar_size",
    "artifact_sha256",
    "targets",
    "machines",
    "families",
    "generations",
    "nixpkgs_revisions",
    "flake_refs",
    "derivations",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required command is not installed: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout).strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}") from exc
    return result.stdout


def chunks(values: list[str], size: int = 128) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def path_info(paths: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for batch in chunks(paths):
        payload = json.loads(run(["nix", "path-info", "--json", *batch]))
        if isinstance(payload, list):
            records = payload
        elif isinstance(payload, dict) and "path" not in payload:
            records = [dict(record, path=path) for path, record in payload.items()]
        else:
            records = [payload]
        for record in records:
            if not isinstance(record, dict) or "path" not in record:
                raise ValueError("nix path-info returned an invalid record")
            result[record["path"]] = record
    return result


def closure(root: str) -> list[str]:
    root = os.path.realpath(root)
    paths = run(["nix-store", "--query", "--requisites", root]).splitlines()
    if root not in paths:
        paths.append(root)
    return sorted(set(path for path in paths if path))


def sri_sha256(hex_digest: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def dump_nar(store_path: str, destination: Path | None = None) -> tuple[int, str]:
    process = subprocess.Popen(
        ["nix-store", "--dump", store_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    digest = hashlib.sha256()
    size = 0
    output = destination.open("wb") if destination else None
    try:
        assert process.stdout is not None
        while data := process.stdout.read(1024 * 1024):
            digest.update(data)
            size += len(data)
            if output:
                output.write(data)
        stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
        if process.wait() != 0:
            raise RuntimeError(f"nix-store --dump {store_path} failed: {stderr.strip()}")
    finally:
        if output:
            output.close()
    return size, digest.hexdigest()


def target_fields(target: dict[str, Any]) -> tuple[str, str, list[str], list[str]]:
    required = [
        "id",
        "generation",
        "nixpkgs_revision",
        "flake_ref",
        "machine",
        "families",
        "subset",
    ]
    missing = [field for field in required if field not in target]
    if missing:
        raise ValueError(f"target is missing required fields: {', '.join(missing)}")
    if not target.get("root") and not target.get("flake_attr"):
        raise ValueError(f"target {target.get('id', '<unknown>')} needs root or flake_attr")
    families = target["families"]
    if not isinstance(families, list) or not families or not all(isinstance(x, str) for x in families):
        raise ValueError(f"target {target['id']} must have a non-empty families list")
    return target["id"], target["subset"], families, [str(target["generation"]), target["nixpkgs_revision"]]


def resolve_root(target: dict[str, Any], build: bool) -> str:
    root = target.get("root")
    if build or not root:
        attribute = target.get("flake_attr")
        if not attribute:
            raise ValueError(f"target {target['id']} has no flake_attr for rebuilding")
        output = run(["nix", "build", "--no-link", "--print-out-paths", f"{target['flake_ref']}#{attribute}"])
        roots = [line for line in output.splitlines() if line]
        if len(roots) != 1:
            raise ValueError(f"flake target {target['id']} returned {len(roots)} paths")
        root = roots[0]
    return os.path.realpath(root)


def collect(spec_path: Path, manifest_path: Path, export_dir: Path | None, build: bool) -> None:
    spec = load_json(spec_path)
    if spec.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported spec schema_version: {spec.get('schema_version')!r}")
    targets = spec.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("spec must contain at least one target")

    if export_dir:
        export_dir.mkdir(parents=True, exist_ok=True)

    entries: dict[str, dict[str, Any]] = {}
    subset_paths: dict[str, set[str]] = {}
    target_ids: set[str] = set()
    target_records: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("every target must be an object")
        target_id, subset, families, _ = target_fields(target)
        if target_id in target_ids:
            raise ValueError(f"duplicate target id: {target_id}")
        target_ids.add(target_id)
        resolved_root = resolve_root(target, build)
        target_records.append(dict(target, resolved_root=resolved_root))
        paths = closure(resolved_root)
        metadata = path_info(paths)
        for path in paths:
            info = metadata.get(path)
            if not info:
                raise ValueError(f"nix path-info omitted closure member: {path}")
            nar_hash = info.get("narHash")
            nar_size = info.get("narSize")
            if not isinstance(nar_hash, str) or not isinstance(nar_size, int):
                raise ValueError(f"missing narHash/narSize for {path}")
            entry = entries.setdefault(
                path,
                {
                    "path": path,
                    "nar_hash": nar_hash,
                    "nar_size": nar_size,
                    "artifact_sha256": None,
                    "artifact": None,
                    "targets": [],
                    "machines": [],
                    "families": [],
                    "generations": [],
                    "nixpkgs_revisions": [],
                    "flake_refs": [],
                    "derivations": [],
                },
            )
            for field, value in (
                ("targets", target_id),
                ("machines", target["machine"]),
                ("families", families),
                ("generations", [str(target["generation"])]),
                ("nixpkgs_revisions", [target["nixpkgs_revision"]]),
                ("flake_refs", [target["flake_ref"]]),
            ):
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item not in entry[field]:
                        entry[field].append(item)
            if info.get("deriver") and info["deriver"] not in entry["derivations"]:
                entry["derivations"].append(info["deriver"])
            subset_paths.setdefault(subset, set()).add(path)

    if export_dir:
        for path, entry in sorted(entries.items()):
            artifact = export_dir / (Path(path).name + ".nar")
            size, digest = dump_nar(path, artifact)
            if size != entry["nar_size"]:
                raise ValueError(f"NAR size changed while exporting {path}: {size} != {entry['nar_size']}")
            if sri_sha256(digest) != entry["nar_hash"]:
                raise ValueError(f"NAR hash changed while exporting {path}")
            entry["artifact"] = os.fspath(artifact)
            entry["artifact_sha256"] = digest

    manifest_entries = [entries[path] for path in sorted(entries)]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "corpus_id": spec.get("corpus_id", "narjar-real-nix"),
        "source": spec.get("source", {}),
        "requirements": spec.get("requirements", {}),
        "targets": target_records,
        "coverage": coverage_for_entries(manifest_entries),
        "subsets": {
            name: {
                "weight": spec.get("subsets", {}).get(name, {}).get("weight", 1),
                "entries": sorted(paths),
            }
            for name, paths in sorted(subset_paths.items())
        },
        "entries": manifest_entries,
    }
    issues = validate_manifest(manifest)
    if issues:
        raise ValueError("generated manifest is invalid:\n" + "\n".join(issues))
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {manifest_path}: {len(entries)} unique paths")


def validate_manifest(manifest: dict[str, Any], artifact_root: Path | None = None) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries must be a non-empty list")
        return errors
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entries[{index}] must be an object")
            continue
        missing = REQUIRED_ENTRY_FIELDS - entry.keys()
        if missing:
            errors.append(f"entries[{index}] missing: {', '.join(sorted(missing))}")
        path = entry.get("path")
        if not isinstance(path, str) or not path.startswith("/nix/store/"):
            errors.append(f"entries[{index}] has invalid path")
        elif path in seen:
            errors.append(f"duplicate path: {path}")
        else:
            seen.add(path)
        if not isinstance(entry.get("nar_size"), int) or entry.get("nar_size", 0) < 0:
            errors.append(f"entries[{index}] has invalid nar_size")
        nar_hash = entry.get("nar_hash")
        if not isinstance(nar_hash, str) or not nar_hash.startswith("sha256-"):
            errors.append(f"entries[{index}] has invalid nar_hash")
        artifact_sha256 = entry.get("artifact_sha256")
        if artifact_sha256 is not None and (not isinstance(artifact_sha256, str) or len(artifact_sha256) != 64):
            errors.append(f"entries[{index}] has invalid artifact_sha256")
        for field in (
            "targets",
            "machines",
            "families",
            "generations",
            "nixpkgs_revisions",
            "flake_refs",
        ):
            value = entry.get(field)
            if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
                errors.append(f"entries[{index}] has invalid {field}")
        derivations = entry.get("derivations")
        if not isinstance(derivations, list) or not all(isinstance(item, str) for item in derivations):
            errors.append(f"entries[{index}] has invalid derivations")
        artifact = entry.get("artifact")
        if artifact:
            artifact_path = Path(artifact)
            if artifact_root and not artifact_path.is_absolute():
                artifact_path = artifact_root / artifact_path
            if not artifact_path.is_file():
                errors.append(f"missing artifact: {artifact_path}")
            elif entry.get("artifact_sha256"):
                digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                if digest != entry["artifact_sha256"]:
                    errors.append(f"artifact hash mismatch: {artifact_path}")
                elif sri_sha256(digest) != entry["nar_hash"]:
                    errors.append(f"NAR hash mismatch: {artifact_path}")
            if artifact_path.is_file() and entry.get("nar_size") != artifact_path.stat().st_size:
                errors.append(f"artifact size mismatch: {artifact_path}")
    subsets = manifest.get("subsets", {})
    if not isinstance(subsets, dict):
        errors.append("subsets must be an object")
    else:
        for name, subset in subsets.items():
            if not isinstance(subset, dict) or not isinstance(subset.get("entries"), list):
                errors.append(f"subset {name} must contain an entries list")
                continue
            missing = set(subset["entries"]) - seen
            if missing:
                errors.append(f"subset {name} references unknown paths: {sorted(missing)}")
    requirements = manifest.get("requirements", {})
    generations = {generation for entry in entries if isinstance(entry, dict) for generation in entry.get("generations", [])}
    revisions = {revision for entry in entries if isinstance(entry, dict) for revision in entry.get("nixpkgs_revisions", [])}
    if isinstance(requirements, dict):
        minimum = requirements.get("min_generations")
        if isinstance(minimum, int) and len(generations) < minimum:
            errors.append(f"coverage has {len(generations)} generations, requires {minimum}")
        minimum = requirements.get("min_nixpkgs_revisions")
        if isinstance(minimum, int) and len(revisions) < minimum:
            errors.append(f"coverage has {len(revisions)} nixpkgs revisions, requires {minimum}")
        for family in requirements.get("required_families", []):
            if not any(family in entry.get("families", []) for entry in entries if isinstance(entry, dict)):
                errors.append(f"coverage is missing family: {family}")
    reported_coverage = manifest.get("coverage")
    if reported_coverage is not None:
        actual_coverage = coverage_for_entries([entry for entry in entries if isinstance(entry, dict)])
        if reported_coverage != actual_coverage:
            errors.append("coverage does not match entries")
    return errors


def coverage_for_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = sorted(entry["nar_size"] for entry in entries)

    def quantile(percent: int) -> int:
        return sizes[(len(sizes) - 1) * percent // 100]

    return {
        "entry_count": len(entries),
        "logical_bytes": sum(entry["nar_size"] for entry in entries),
        "generations": sorted({generation for entry in entries for generation in entry["generations"]}),
        "nixpkgs_revisions": sorted({revision for entry in entries for revision in entry["nixpkgs_revisions"]}),
        "machines": sorted({machine for entry in entries for machine in entry["machines"]}),
        "families": sorted({family for entry in entries for family in entry["families"]}),
        "size_quantiles": {"p50": quantile(50), "p90": quantile(90), "p99": quantile(99)},
    }


def validate_command(manifest_path: Path, artifact_root: Path | None, store: bool, rebuild: bool) -> None:
    manifest = load_json(manifest_path)
    errors = validate_manifest(manifest, artifact_root)
    if store:
        for entry in manifest.get("entries", []):
            size, digest = dump_nar(entry["path"])
            if size != entry["nar_size"] or sri_sha256(digest) != entry["nar_hash"]:
                errors.append(f"store bytes differ for {entry['path']}")
            if entry.get("artifact_sha256") and digest != entry["artifact_sha256"]:
                errors.append(f"store/artifact bytes differ for {entry['path']}")
    if rebuild:
        rebuilt: dict[tuple[str, str], str | Exception] = {}
        for target in manifest.get("targets", []):
            key = (target.get("flake_ref", ""), target.get("flake_attr", ""))
            if key in rebuilt:
                result = rebuilt[key]
                if isinstance(result, Exception):
                    errors.append(str(result))
                    continue
                resolved_root = result
            else:
                try:
                    resolved_root = resolve_root(target, True)
                except (RuntimeError, ValueError) as exc:
                    rebuilt[key] = exc
                    errors.append(str(exc))
                    continue
                rebuilt[key] = resolved_root
            expected_root = target.get("resolved_root")
            if expected_root and resolved_root != expected_root:
                errors.append(f"rebuilt root differs for {target['id']}: {resolved_root} != {expected_root}")
    if errors:
        raise ValueError("manifest validation failed:\n" + "\n".join(errors))
    print(f"validated {manifest_path}: {len(manifest['entries'])} unique paths")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--spec", type=Path, required=True)
    collect_parser.add_argument("--manifest", type=Path, required=True)
    collect_parser.add_argument("--export-dir", type=Path)
    collect_parser.add_argument("--build", action="store_true", help="materialize each target from flake_ref#flake_attr")
    validate_parser = commands.add_parser("validate")
    validate_parser.add_argument("--manifest", type=Path, required=True)
    validate_parser.add_argument("--artifact-root", type=Path)
    validate_parser.add_argument("--store", action="store_true", help="re-dump every store path and compare bytes")
    validate_parser.add_argument("--rebuild", action="store_true", help="rebuild every recorded flake target")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "collect":
            collect(args.spec, args.manifest, args.export_dir, args.build)
        else:
            validate_command(args.manifest, args.artifact_root, args.store, args.rebuild)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
