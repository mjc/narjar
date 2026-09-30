# shellcheck shell=bash

cargo_audit_report_has_registry_failure() {
  case "$1" in
    *"couldn't update crates.io index"* | *"couldn't check if the package is yanked"*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
