#!/usr/bin/env bash
set -euo pipefail

source ci/cargo-audit-output.sh

incomplete_registry_reports=(
  "warning: couldn't update crates.io index: registry unavailable"
  "error: couldn't check if the package is yanked: package lookup failed"
)

for report in "${incomplete_registry_reports[@]}"; do
  if ! cargo_audit_report_has_registry_failure "$report"; then
    printf 'Expected incomplete registry report to be rejected: %s\n' "$report" >&2
    exit 1
  fi
done

if cargo_audit_report_has_registry_failure \
  'Scanning Cargo.lock for vulnerabilities (111 crate dependencies)'; then
  printf '%s\n' 'A clean audit report was misclassified as an incomplete registry check.' >&2
  exit 1
fi

if incomplete_scan_report=$(
  PATH="$PWD/ci/fixtures/yanked-lookup-failure:$PATH" \
    bash ci/check-cargo-advisories.sh 2>&1
); then
  printf '%s\n' 'The advisory gate accepted an incomplete yanked-release scan.' >&2
  exit 1
fi

case "$incomplete_scan_report" in
  *'The dependency audit could not check crates.io for yanked releases.'*) ;;
  *)
    printf '%s\n' "$incomplete_scan_report" >&2
    printf '%s\n' 'The advisory gate rejected the fixture for the wrong reason.' >&2
    exit 1
    ;;
esac
