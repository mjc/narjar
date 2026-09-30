#!/usr/bin/env bash
set -euo pipefail

source ci/cargo-audit-output.sh

if audit_report=$(cargo-audit audit --deny warnings 2>&1); then
  if cargo_audit_report_has_registry_failure "$audit_report"; then
    printf '%s\n' "$audit_report" >&2
    printf '%s\n' \
      'The dependency audit could not check crates.io for yanked releases.' \
      >&2
    exit 1
  fi
  printf '%s\n' "$audit_report"
else
  printf '%s\n' "$audit_report" >&2
  exit 1
fi

if vulnerable_lock_report=$(cargo-audit audit \
  --no-fetch \
  --file ci/fixtures/rustls-vulnerable.lock \
  --deny warnings 2>&1); then
  printf '%s\n' \
    'The historical vulnerable rustls lockfile unexpectedly passed the advisory gate.' \
    >&2
  exit 1
fi

case "$vulnerable_lock_report" in
  *RUSTSEC-2026-0285*)
    printf '%s\n' 'The advisory gate rejects the historical rustls vulnerability.'
    ;;
  *)
    printf '%s\n' "$vulnerable_lock_report" >&2
    printf '%s\n' \
      'The historical lockfile failed for a reason other than RUSTSEC-2026-0285.' \
      >&2
    exit 1
    ;;
esac
