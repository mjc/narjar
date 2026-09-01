#!/usr/bin/env python3
"""Run the matched Narjar/bincache continuation benchmark."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import platform
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

BINCACHE_COMMIT = "556a9c8f97a3c994a9de85f567a2ef16ce6513ab"
BINCACHE_FLAKE = f"github:wyattgill9/bincache/{BINCACHE_COMMIT}"
SEED = 29030


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


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def read_optional(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


@dataclass(frozen=True)
class Run:
    output: Path
    work: Path
    repetitions: int
    quick: bool
    narjar: Path
    bincache: Path

    @classmethod
    def prepare(cls, args: argparse.Namespace) -> "Run":
        if platform.system() != "Linux":
            raise SystemExit("the continuation benchmark requires Linux /proc")
        if not args.quick and args.repetitions < 15:
            raise SystemExit("--repetitions must be at least 15")
        if args.output.exists():
            raise SystemExit(f"output already exists: {args.output}")

        narjar = os.environ.get("NARJAR_BIN")
        if narjar is None:
            raise SystemExit("NARJAR_BIN must point to the release binary")

        args.output.mkdir(parents=True)
        work = Path(tempfile.mkdtemp(prefix=".continuation-", dir=args.output.parent))
        return cls(
            output=args.output,
            work=work,
            repetitions=1 if args.quick else args.repetitions,
            quick=args.quick,
            narjar=Path(narjar).resolve(),
            bincache=resolve_bincache(args.bincache_bin),
        )


@dataclass
class Candidate:
    name: str
    binary: Path
    root: Path
    log_dir: Path
    process: subprocess.Popen[str] | None = field(default=None, init=False)
    url: str | None = field(default=None, init=False)
    public_key: str = field(default="", init=False)
    netrc: Path = field(init=False)
    _log: Any = field(default=None, init=False, repr=False)

    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    def prepare(self) -> None:
        self.data_dir.mkdir(parents=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        secret = self.root / "secret-key"
        token_file = self.root / "push-token"

        if self.name == "narjar":
            public = self.root / "public-key"
            subprocess.run(
                [
                    "nix-store",
                    "--generate-binary-cache-key",
                    "narjar-benchmark",
                    str(secret),
                    str(public),
                ],
                check=True,
            )
            self.public_key = public.read_text().strip()
            shutil.copyfile(public, self.data_dir / "trusted-public-keys")
            token = command(
                str(self.binary),
                "token",
                "create",
                "--data-dir",
                str(self.data_dir),
                "--scope",
                "write",
                "--name",
                "benchmark",
            )
        else:
            generated = subprocess.run(
                [str(self.binary), "keygen", "--name", "bincache-benchmark"],
                check=True,
                text=True,
                capture_output=True,
            )
            secret.write_text(generated.stdout)
            prefix = "trusted-public-keys entry: "
            public_line = generated.stderr.strip()
            if not public_line.startswith(prefix):
                raise RuntimeError(f"unexpected bincache keygen output: {public_line}")
            self.public_key = public_line.removeprefix(prefix)
            token = command(str(self.binary), "token")

        token_file.write_text(token + "\n")
        self.netrc = self.root / "netrc"
        self.netrc.write_text(
            f"machine 127.0.0.1\nlogin benchmark\npassword {token}\n"
        )
        self.netrc.chmod(0o600)

    def server_command(self, port: int) -> list[str]:
        if self.name == "narjar":
            return [
                str(self.binary),
                "serve",
                "--data-dir",
                str(self.data_dir),
                "--listen",
                f"127.0.0.1:{port}",
                "--workers",
                "1",
            ]
        return [
            str(self.binary),
            "serve",
            "--data-dir",
            str(self.data_dir),
            "--secret-key-file",
            str(self.root / "secret-key"),
            "--push-token-file",
            str(self.root / "push-token"),
            "--listen",
            f"127.0.0.1:{port}",
            "--shards",
            "1",
        ]

    def start(self) -> float:
        if self.process is not None:
            raise RuntimeError(f"{self.name} is already running")

        port = reserve_port()
        self.url = f"http://127.0.0.1:{port}"
        self._log = (self.log_dir / f"{self.name}.log").open("a")
        started = time.perf_counter_ns()
        self.process = subprocess.Popen(
            self.server_command(port),
            stdout=self._log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                log = (self.log_dir / f"{self.name}.log").read_text()
                self.stop()
                raise RuntimeError(f"{self.name} exited during startup:\n{log}")
            try:
                with urllib.request.urlopen(
                    f"{self.url}/nix-cache-info", timeout=0.2
                ) as response:
                    response.read()
                return (time.perf_counter_ns() - started) / 1_000_000
            except (OSError, urllib.error.URLError):
                time.sleep(0.002)

        self.stop()
        raise RuntimeError(f"{self.name} did not become ready")

    def stop(self) -> None:
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            self.process = None
        self.url = None
        if self._log is not None:
            self._log.close()
            self._log = None

    def rss_kib(self) -> int:
        if self.process is None:
            raise RuntimeError(f"{self.name} is not running")
        status = Path(f"/proc/{self.process.pid}/smaps_rollup").read_text()
        for line in status.splitlines():
            if line.startswith("Rss:"):
                return int(line.split()[1])
        raise RuntimeError(f"RSS missing for {self.name}")

    def _sign(self, paths: Sequence[str]) -> None:
        if self.name == "narjar":
            subprocess.run(
                [
                    "nix",
                    "store",
                    "sign",
                    "--key-file",
                    str(self.root / "secret-key"),
                    *paths,
                ],
                check=True,
            )

    def _copy_args(self, paths: Sequence[str]) -> list[str]:
        if self.url is None:
            raise RuntimeError(f"{self.name} is not running")
        return [
            "nix",
            "copy",
            "--refresh",
            "--option",
            "netrc-file",
            str(self.netrc),
            "--to",
            f"{self.url}?compression=none",
            *paths,
        ]

    def publish(self, paths: Sequence[str]) -> None:
        for offset in range(0, len(paths), 128):
            batch = paths[offset : offset + 128]
            self._sign(batch)
            subprocess.run(self._copy_args(batch), check=True)

    def process_cpu_seconds(self) -> float:
        if self.process is None:
            raise RuntimeError(f"{self.name} is not running")
        fields = Path(f"/proc/{self.process.pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
        return ticks / os.sysconf("SC_CLK_TCK")

    def disk_bytes(self) -> int:
        return sum(
            entry.stat().st_size
            for entry in self.data_dir.rglob("*")
            if entry.is_file()
        )

    def publish_timed(self, path: str) -> dict[str, float]:
        self._sign([path])
        before_cpu = self.process_cpu_seconds()
        before_disk = self.disk_bytes()
        peak_rss = [self.rss_kib()]
        finished = threading.Event()

        def sample_rss() -> None:
            while not finished.wait(0.005):
                peak_rss.append(self.rss_kib())

        sampler = threading.Thread(target=sample_rss)
        sampler.start()
        started = time.perf_counter_ns()
        try:
            subprocess.run(
                self._copy_args([path]),
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            finished.set()
            sampler.join()

        return {
            "wall_ms": elapsed_ms,
            "server_cpu_ms": (self.process_cpu_seconds() - before_cpu) * 1_000,
            "peak_rss_kib": max(peak_rss),
            "stored_bytes": self.disk_bytes() - before_disk,
        }

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, float, bytes]:
        if self.url is None:
            raise RuntimeError(f"{self.name} is not running")
        request = urllib.request.Request(
            f"{self.url}/{path.lstrip('/')}",
            method=method,
            headers=headers or {},
        )
        started = time.perf_counter_ns()
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            body = error.read()
            status = error.code
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        return status, elapsed_ms, body

    def nar_info(self, store_path: str) -> tuple[str, int]:
        store_hash = Path(store_path).name.split("-", 1)[0]
        status, _, body = self.request("GET", f"{store_hash}.narinfo")
        if status != 200:
            raise RuntimeError(f"{self.name} returned {status} for {store_hash}.narinfo")
        fields = dict(
            line.split(": ", 1)
            for line in body.decode().splitlines()
            if ": " in line
        )
        return fields["URL"], int(fields["NarSize"])

    def evict_cache(self) -> None:
        for entry in self.data_dir.rglob("*"):
            if not entry.is_file():
                continue
            try:
                with entry.open("rb") as stream:
                    os.posix_fadvise(
                        stream.fileno(),
                        0,
                        0,
                        os.POSIX_FADV_DONTNEED,
                    )
            except OSError:
                pass


class Recorder:
    def __init__(self, output: Path) -> None:
        self.path = output / "samples.jsonl"
        self.rows: list[dict[str, Any]] = []

    def add(
        self,
        case: str,
        candidate: str,
        repetition: int,
        value: float,
        unit: str,
        **context: Any,
    ) -> None:
        row = {
            "case": case,
            "candidate": candidate,
            "repetition": repetition,
            "value": value,
            "unit": unit,
            **context,
        }
        self.rows.append(row)
        with self.path.open("a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")

    def summary(self) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str, str], list[float]] = {}
        for row in self.rows:
            key = (row["case"], row["candidate"], row["unit"])
            groups.setdefault(key, []).append(row["value"])

        result = []
        for (case, candidate, unit), values in sorted(groups.items()):
            ordered = sorted(values)
            result.append(
                {
                    "case": case,
                    "candidate": candidate,
                    "unit": unit,
                    "n": len(values),
                    "median": statistics.median(values),
                    "p95": ordered[math.ceil(0.95 * len(ordered)) - 1],
                    "min": ordered[0],
                    "max": ordered[-1],
                }
            )
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a pinned, matched Narjar/bincache benchmark."
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
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run one repetition over a ten-path corpus; not decision evidence",
    )
    return parser.parse_args()


def environment(run: Run) -> dict[str, Any]:
    cpu_model = None
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu_model = line.partition(":")[2].strip()
            break

    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "platform": platform.platform(),
        "uname": " ".join(platform.uname()),
        "cpu_count": os.cpu_count(),
        "cpu_model": cpu_model,
        "cpu_governor": read_optional(
            Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        ),
        "filesystem": command(
            "findmnt", "-T", str(run.output), "-no", "SOURCE,FSTYPE,OPTIONS"
        ),
        "nix": command("nix", "--version"),
        "rustc": optional_command("rustc", "--version"),
        "narjar_binary": str(run.narjar),
        "narjar_commit": optional_command("git", "rev-parse", "HEAD"),
        "bincache_binary": str(run.bincache),
        "bincache_commit": BINCACHE_COMMIT,
        "repetitions": run.repetitions,
        "random_seed": SEED,
        "quick": run.quick,
    }


def corpus(count: int) -> list[str]:
    expression = (
        "builtins.genList "
        '(i: builtins.toFile ("narjar-continuation-" + builtins.toString i) '
        "(builtins.toString i)) "
        f"{count}"
    )
    return json.loads(command("nix", "eval", "--json", "--expr", expression))


def benchmark_startup(
    run: Run,
    candidates: list[Candidate],
    recorder: Recorder,
    rng: random.Random,
) -> None:
    targets = [0, 10] if run.quick else [0, 100, 1_000, 10_000]
    paths = corpus(targets[-1])
    published = 0

    for target in targets:
        additions = paths[published:target]
        order = candidates.copy()
        rng.shuffle(order)
        for candidate in order:
            if additions:
                candidate.start()
                candidate.publish(additions)
                candidate.stop()
        published = target

        for candidate in candidates:
            candidate.start()
            candidate.stop()

        schedule = [
            candidate
            for candidate in candidates
            for _ in range(run.repetitions)
        ]
        rng.shuffle(schedule)
        repetitions = {candidate.name: 0 for candidate in candidates}
        for order_index, candidate in enumerate(schedule):
            repetition = repetitions[candidate.name]
            repetitions[candidate.name] += 1
            startup_ms = candidate.start()
            time.sleep(0.2)
            recorder.add(
                f"startup_{target}_paths",
                candidate.name,
                repetition,
                startup_ms,
                "ms",
                cache_paths=target,
                order=order_index,
            )
            recorder.add(
                f"settled_idle_rss_{target}_paths",
                candidate.name,
                repetition,
                candidate.rss_kib(),
                "KiB",
                cache_paths=target,
                order=order_index,
            )
            candidate.stop()


def make_payloads(run: Run, count: int, size: int) -> list[str]:
    directory = run.work / "payloads"
    directory.mkdir(exist_ok=True)
    paths = []
    for index in range(count):
        source = directory / f"upload-{size}-{index}.bin"
        generator = random.Random(SEED + size + index)
        remaining = size
        with source.open("wb") as stream:
            while remaining:
                chunk_size = min(1024 * 1024, remaining)
                stream.write(generator.randbytes(chunk_size))
                remaining -= chunk_size
        paths.append(command("nix", "store", "add-file", str(source)))
    return paths


def benchmark_io(
    run: Run,
    candidates: list[Candidate],
    recorder: Recorder,
    rng: random.Random,
) -> None:
    payload_bytes = 1 * 1024 * 1024 if run.quick else 16 * 1024 * 1024
    paths = make_payloads(run, run.repetitions + 1, payload_bytes)

    for candidate in candidates:
        candidate.start()
    try:
        for candidate in candidates:
            candidate.publish([paths[0]])

        schedule = [
            (candidate, path)
            for candidate in candidates
            for path in paths[1:]
        ]
        rng.shuffle(schedule)
        repetitions = {candidate.name: 0 for candidate in candidates}
        for order_index, (candidate, path) in enumerate(schedule):
            repetition = repetitions[candidate.name]
            repetitions[candidate.name] += 1
            result = candidate.publish_timed(path)
            recorder.add(
                "upload_wall",
                candidate.name,
                repetition,
                result["wall_ms"],
                "ms",
                order=order_index,
                payload_bytes=payload_bytes,
            )
            recorder.add(
                "upload_throughput",
                candidate.name,
                repetition,
                payload_bytes / result["wall_ms"] * 1_000 / (1024 * 1024),
                "MiB/s",
                order=order_index,
                payload_bytes=payload_bytes,
            )
            recorder.add(
                "upload_server_cpu",
                candidate.name,
                repetition,
                result["server_cpu_ms"],
                "ms",
                order=order_index,
                payload_bytes=payload_bytes,
            )
            recorder.add(
                "upload_peak_rss",
                candidate.name,
                repetition,
                result["peak_rss_kib"],
                "KiB",
                order=order_index,
                payload_bytes=payload_bytes,
            )
            recorder.add(
                "upload_stored_bytes",
                candidate.name,
                repetition,
                result["stored_bytes"],
                "bytes",
                order=order_index,
                payload_bytes=payload_bytes,
            )

        nar_info = {
            candidate.name: candidate.nar_info(paths[0])
            for candidate in candidates
        }
        operations = [
            ("get_warm", "GET", {}, 200, False),
            ("get_cold", "GET", {}, 200, True),
            ("head_warm", "HEAD", {}, 200, False),
            ("range_warm", "GET", {"Range": "bytes=0-65535"}, 206, False),
            (
                "missing_404",
                "GET",
                {},
                404,
                False,
            ),
        ]
        for case, method, headers, expected, cold in operations:
            for candidate in candidates:
                path = (
                    "00000000000000000000000000000000.narinfo"
                    if case == "missing_404"
                    else nar_info[candidate.name][0]
                )
                if cold:
                    candidate.evict_cache()
                candidate.request(method, path, headers)

            request_schedule = [
                candidate
                for candidate in candidates
                for _ in range(run.repetitions)
            ]
            rng.shuffle(request_schedule)
            repetitions = {candidate.name: 0 for candidate in candidates}
            for order_index, candidate in enumerate(request_schedule):
                repetition = repetitions[candidate.name]
                repetitions[candidate.name] += 1
                path = (
                    "00000000000000000000000000000000.narinfo"
                    if case == "missing_404"
                    else nar_info[candidate.name][0]
                )
                if cold:
                    candidate.evict_cache()
                status, elapsed_ms, body = candidate.request(method, path, headers)
                valid_statuses = {expected}
                if case == "range_warm" and candidate.name == "bincache":
                    valid_statuses.add(200)
                if status not in valid_statuses:
                    raise RuntimeError(
                        f"{candidate.name} {case} returned {status}, "
                        f"expected one of {sorted(valid_statuses)}"
                    )
                recorder.add(
                    f"{case}_status",
                    candidate.name,
                    repetition,
                    status,
                    "HTTP",
                    order=order_index,
                    response_bytes=len(body),
                )
                recorder.add(
                    f"{case}_latency",
                    candidate.name,
                    repetition,
                    elapsed_ms,
                    "ms",
                    order=order_index,
                    response_bytes=len(body),
                )
                if case in {"get_warm", "get_cold"}:
                    logical_bytes = nar_info[candidate.name][1]
                    recorder.add(
                        f"{case}_throughput",
                        candidate.name,
                        repetition,
                        logical_bytes / elapsed_ms * 1_000 / (1024 * 1024),
                        "MiB/s",
                        order=order_index,
                        response_bytes=len(body),
                    )

        widths = [1, 2] if run.quick else [1, 8, 32]
        for width in widths:
            for candidate in candidates:
                path = nar_info[candidate.name][0]
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=width
                ) as executor:
                    list(
                        executor.map(
                            lambda _: candidate.request("GET", path),
                            range(width),
                        )
                    )

            request_schedule = [
                candidate
                for candidate in candidates
                for _ in range(run.repetitions)
            ]
            rng.shuffle(request_schedule)
            repetitions = {candidate.name: 0 for candidate in candidates}
            for order_index, candidate in enumerate(request_schedule):
                repetition = repetitions[candidate.name]
                repetitions[candidate.name] += 1
                path = nar_info[candidate.name][0]
                started = time.perf_counter_ns()
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=width
                ) as executor:
                    responses = list(
                        executor.map(
                            lambda _: candidate.request("GET", path),
                            range(width),
                        )
                    )
                elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                if any(status != 200 for status, _, _ in responses):
                    raise RuntimeError(f"{candidate.name} concurrent GET failed")
                logical_bytes = nar_info[candidate.name][1] * width
                recorder.add(
                    f"concurrent_get_{width}",
                    candidate.name,
                    repetition,
                    logical_bytes / elapsed_ms * 1_000 / (1024 * 1024),
                    "MiB/s",
                    order=order_index,
                )
    finally:
        for candidate in candidates:
            candidate.stop()


def measure_closures(run: Run, recorder: Recorder) -> None:
    binaries = {"narjar": run.narjar, "bincache": run.bincache}
    if not run.quick:
        static_output = command(
            "nix",
            "build",
            "--no-link",
            "--print-out-paths",
            ".#narjar-static",
        ).splitlines()[-1]
        binaries["narjar-static"] = Path(static_output) / "bin" / "narjar"

    for name, binary in binaries.items():
        output = binary.parent.parent
        closure_bytes = int(command("nix", "path-info", "-S", str(output)).split()[-1])
        recorder.add("binary_size", name, 0, binary.stat().st_size, "bytes")
        recorder.add("runtime_closure_size", name, 0, closure_bytes, "bytes")


def write_report(run: Run, recorder: Recorder) -> None:
    summary = recorder.summary()
    (run.output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )

    lines = [
        "# Continuation benchmark",
        "",
        f"- bincache ref: `{BINCACHE_COMMIT}`",
        f"- repetitions: {run.repetitions}",
        f"- random seed: {SEED}",
        f"- quick smoke run: {'yes; not decision evidence' if run.quick else 'no'}",
        "",
        "| Case | Candidate | n | Median | p95 | Min | Max | Unit |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in summary:
        lines.append(
            "| {case} | {candidate} | {n} | {median:.3f} | {p95:.3f} | "
            "{min:.3f} | {max:.3f} | {unit} |".format(**row)
        )
    (run.output / "report.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    run = Run.prepare(parse_args())
    candidates = [
        Candidate("narjar", run.narjar, run.work / "narjar", run.output / "logs"),
        Candidate(
            "bincache",
            run.bincache,
            run.work / "bincache",
            run.output / "logs",
        ),
    ]
    try:
        (run.output / "environment.json").write_text(
            json.dumps(environment(run), indent=2, sort_keys=True) + "\n"
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
        for candidate in candidates:
            candidate.prepare()

        recorder = Recorder(run.output)
        benchmark_startup(run, candidates, recorder, random.Random(SEED))
        benchmark_io(run, candidates, recorder, random.Random(SEED + 1))
        measure_closures(run, recorder)
        write_report(run, recorder)
        print(run.output)
        return 0
    finally:
        for candidate in candidates:
            candidate.stop()
        shutil.rmtree(run.work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
