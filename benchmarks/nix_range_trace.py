#!/usr/bin/env python3
"""Trace Nix copy interruption and retry behaviour through a recording proxy.

The proxy forwards the real Nix HTTP client to a running cache, aborts one NAR
response at a requested fraction, and then lets the same copy resume normally.
Every request, response, Range header, byte count, and client command is kept
in the output directory.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import http.client
import http.server
import json
from pathlib import Path
import shlex
import socket
import socketserver
import subprocess
import threading
import time
from typing import Any
from urllib.parse import urlsplit


def range_workload(length: int, chunk_size: int = 64 * 1024) -> list[tuple[int, int]]:
    if length <= 0:
        raise ValueError("NAR length must be positive")
    if chunk_size <= 0:
        raise ValueError("range size must be positive")
    points = {0, 1, length // 10, length // 2, (length * 9) // 10, length - 1}
    ranges = []
    for start in sorted(points):
        end = min(length - 1, start + chunk_size - 1)
        ranges.append((start, end))
    return ranges


@dataclass
class ProxyState:
    origin: tuple[str, int, bool]
    abort_after: int
    log_path: Path
    lock: threading.Lock = field(default_factory=threading.Lock)
    aborted: bool = False

    def log(self, record: dict[str, Any]) -> None:
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    server: "TraceServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        self.forward(False)

    def do_HEAD(self) -> None:
        self.forward(True)

    def forward(self, head: bool) -> None:
        state = self.server.state
        host, port, secure = state.origin
        connection_class = http.client.HTTPSConnection if secure else http.client.HTTPConnection
        connection = connection_class(host, port, timeout=30)
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"host", "connection", "keep-alive"}
        }
        started = time.perf_counter_ns()
        try:
            connection.request("GET" if not head else "HEAD", self.path, headers=headers)
            response = connection.getresponse()
            response_headers = dict(response.getheaders())
            self.send_response(response.status, response.reason)
            for key, value in response_headers.items():
                if key.lower() not in {"connection", "keep-alive"}:
                    self.send_header(key, value)
            self.end_headers()
            sent = 0
            aborted = False
            while not head:
                with state.lock:
                    first_abort = not state.aborted
                read_limit = (
                    min(1024 * 1024, max(1, state.abort_after - sent))
                    if first_abort
                    else 1024 * 1024
                )
                chunk = response.read(read_limit)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                sent += len(chunk)
                if state.abort_after and sent >= state.abort_after:
                    with state.lock:
                        if not state.aborted and "/nar/" in self.path:
                            state.aborted = True
                            aborted = True
                            break
            state.log(
                {
                    "kind": "response",
                    "method": "HEAD" if head else "GET",
                    "path": self.path,
                    "request_headers": {key.lower(): value for key, value in headers.items()},
                    "response_status": response.status,
                    "response_headers": {key.lower(): value for key, value in response_headers.items()},
                    "bytes_sent": sent,
                    "aborted": aborted,
                    "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
                }
            )
            if aborted:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
        except (BrokenPipeError, ConnectionResetError, OSError) as error:
            state.log(
                {
                    "kind": "proxy_error",
                    "method": "HEAD" if head else "GET",
                    "path": self.path,
                    "error": repr(error),
                    "elapsed_ms": (time.perf_counter_ns() - started) / 1_000_000,
                }
            )
        finally:
            connection.close()


class TraceServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: ProxyState):
        super().__init__(address, ProxyHandler)
        self.state = state


def run_copy(
    cache_url: str,
    destination: Path,
    store_path: str,
    trusted_public_keys: list[str],
    netrc_file: Path | None,
    command_log: Path,
) -> subprocess.CompletedProcess[str]:
    command = [
        "nix",
        "--store",
        f"local?root={destination}",
        "copy",
        "--refresh",
        "--from",
        cache_url,
        "--option",
        "require-sigs",
        "true",
        "--option",
        "trusted-public-keys",
        " ".join(trusted_public_keys),
    ]
    if netrc_file is not None:
        command.extend(["--option", "netrc-file", str(netrc_file)])
    command.append(store_path)
    with command_log.open("a", encoding="utf-8") as log:
        log.write("$ " + shlex.join(command) + "\n")
        result = subprocess.run(command, text=True, capture_output=True)
        log.write(result.stdout)
        log.write(result.stderr)
        log.write(f"exit={result.returncode}\n")
    return result


def run_case(args: argparse.Namespace, fraction: float, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True)
    trace_path = output / "trace.jsonl"
    command_log = output / "commands.txt"
    destination = output / "store"
    destination.mkdir()
    origin = urlsplit(args.cache_url)
    if origin.hostname is None or origin.port is None:
        raise ValueError("--cache-url must include a host and port")
    state = ProxyState(
        origin=(origin.hostname, origin.port, origin.scheme == "https"),
        abort_after=max(1, int(args.nar_bytes * fraction)),
        log_path=trace_path,
    )
    server = TraceServer(("127.0.0.1", 0), state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proxy_url = f"http://127.0.0.1:{server.server_port}"
    try:
        interrupted = run_copy(
            proxy_url,
            destination,
            args.store_path,
            args.trusted_public_key,
            args.netrc_file,
            command_log,
        )
        resumed = run_copy(
            proxy_url,
            destination,
            args.store_path,
            args.trusted_public_key,
            args.netrc_file,
            command_log,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    requests = []
    if trace_path.exists():
        requests = [json.loads(line) for line in trace_path.read_text().splitlines()]
    return {
        "fraction": fraction,
        "abort_after_bytes": state.abort_after,
        "interrupted_returncode": interrupted.returncode,
        "resumed_returncode": resumed.returncode,
        "request_count": len(requests),
        "range_headers": [
            request["request_headers"].get("range")
            for request in requests
            if request.get("kind") == "response" and request["request_headers"].get("range")
        ],
        "trace": str(trace_path),
        "commands": str(command_log),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-url", required=True)
    parser.add_argument("--store-path", required=True)
    parser.add_argument("--nar-bytes", type=int, required=True)
    parser.add_argument("--trusted-public-key", action="append", required=True)
    parser.add_argument("--netrc-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fraction", type=float, action="append", default=[0.1, 0.5, 0.9])
    parser.add_argument("--cold-resumes", type=int, default=32)
    parser.add_argument("--range-size", type=int, action="append")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    if args.cold_resumes < 0:
        raise SystemExit("--cold-resumes must not be negative")
    args.output.mkdir(parents=True)
    fractions = sorted(set(args.fraction))
    range_sizes = sorted(set(args.range_size or [64 * 1024, 1024 * 1024]))
    if args.cold_resumes:
        def run_cold_resume(index: int) -> dict[str, Any]:
            return run_case(
                args,
                fractions[index % len(fractions)],
                args.output / f"cold-resume-{index:02d}",
            )

        with ThreadPoolExecutor(max_workers=min(args.cold_resumes, 32)) as executor:
            cold_resumes = list(executor.map(run_cold_resume, range(args.cold_resumes)))
    else:
        cold_resumes = []
    summary = {
        "cache_url": args.cache_url,
        "store_path": args.store_path,
        "nar_bytes": args.nar_bytes,
        "fractions": [
            run_case(args, fraction, args.output / f"interrupt-{fraction:g}")
            for fraction in fractions
        ],
        "cold_resumes": cold_resumes,
        "range_workloads": {
            str(size): [
                {"start": start, "end": end}
                for start, end in range_workload(args.nar_bytes, size)
            ]
            for size in range_sizes
        },
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
