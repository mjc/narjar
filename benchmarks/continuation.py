#!/usr/bin/env python3
"""Prepare a reproducible Narjar/bincache continuation benchmark."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BINCACHE_COMMIT = "556a9c8f97a3c994a9de85f567a2ef16ce6513ab"
BINCACHE_FLAKE = f"github:wyattgill9/bincache/{BINCACHE_COMMIT}"


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def optional_command(*args: str) -> str | None:
    if shutil.which(args[0]) is None:
        return None
    return command(*args)


def resolve_bincache(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()

    output = command(
        "nix",
        "build",
        "--no-write-lock-file",
        "--no-link",
        "--print-out-paths",
        BINCACHE_FLAKE,
    )
    return Path(output.splitlines()[-1]) / "bin" / "bincache"


@dataclass(frozen=True)
class Run:
    output: Path
    repetitions: int
    narjar: Path
    bincache: Path

    @classmethod
    def prepare(cls, args: argparse.Namespace) -> "Run":
        if platform.system() != "Linux":
            raise SystemExit("the continuation benchmark requires Linux /proc")
        if args.repetitions < 15:
            raise SystemExit("--repetitions must be at least 15")
        if args.output.exists():
            raise SystemExit(f"output already exists: {args.output}")

        narjar = os.environ.get("NARJAR_BIN")
        if narjar is None:
            raise SystemExit("NARJAR_BIN must point to the release binary")

        run = cls(
            output=args.output,
            repetitions=args.repetitions,
            narjar=Path(narjar).resolve(),
            bincache=resolve_bincache(args.bincache_bin),
        )
        run.output.mkdir(parents=True)
        return run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a pinned, matched Narjar/bincache benchmark run."
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new directory for environment metadata and raw samples",
    )
    parser.add_argument(
        "--bincache-bin",
        type=Path,
        help="use this bincache binary instead of building the pinned flake",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=15,
        help="measured repetitions per case after warm-up (default: 15)",
    )
    return parser.parse_args()


def main() -> int:
    run = Run.prepare(parse_args())

    metadata = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "platform": platform.platform(),
        "uname": " ".join(platform.uname()),
        "cpu_count": os.cpu_count(),
        "filesystem": command("findmnt", "-T", str(run.output), "-no", "SOURCE,FSTYPE,OPTIONS"),
        "nix": command("nix", "--version"),
        "rustc": optional_command("rustc", "--version"),
        "narjar_binary": str(run.narjar),
        "bincache_binary": str(run.bincache),
        "bincache_commit": BINCACHE_COMMIT,
        "repetitions": run.repetitions,
    }
    (run.output / "environment.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )
    (run.output / "commands.txt").write_text(
        " ".join(
            (
                "nix",
                "build",
                "--no-write-lock-file",
                "--no-link",
                "--print-out-paths",
                BINCACHE_FLAKE,
            )
        )
        + "\n"
    )
    print(run.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
