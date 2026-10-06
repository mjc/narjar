#!/usr/bin/env bash
set -euo pipefail

source ci/check-release-candidate.sh

export GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main
export GITHUB_REPOSITORY=mjc/narjar GITHUB_REPOSITORY_OWNER=mjc
export GITHUB_SHA=1111111111111111111111111111111111111111 GITHUB_OUTPUT=/dev/null
unset EXPECTED_RELEASE_COMMIT
unset EXPECTED_RELEASE_TAG_OBJECT

git() {
  case "$1" in
    status) [[ "$scenario" != dirty ]] || printf ' M Cargo.toml\n' ;;
    fetch) ;;
    rev-parse) printf '2222222222222222222222222222222222222222\n' ;;
    cat-file) [[ "$scenario" != lightweight ]] && printf 'tag\n' || printf 'commit\n' ;;
    merge-base) [[ "$scenario" != off-main ]] ;;
    show) printf '[package]\nversion = "0.1.0"\n' ;;
    *) printf 'Unexpected git call: %s\n' "$*" >&2; return 1 ;;
  esac
}

gh() {
  case "$2" in
    */environments/release)
      [[ "$scenario" != missing-environment ]] || return 1
      local owner=mjc self_review=false
      [[ "$scenario" != other-reviewer ]] || owner=someone-else
      [[ "$scenario" != self-review-disabled ]] || self_review=true
      if [[ "$scenario" == no-reviewers ]]; then
        printf '{"protection_rules":[]}\n'
      else
        printf '{"protection_rules":[{"type":"required_reviewers","prevent_self_review":%s,"reviewers":[{"type":"User","reviewer":{"login":"%s"}}]}]}\n' \
          "$self_review" "$owner"
      fi
      ;;
    */git/tags/*)
      local verified=true type=commit tag=v0.1.0
      [[ "$scenario" != unsigned-tag ]] || verified=false
      [[ "$scenario" != nested-tag ]] || type=tag
      [[ "$scenario" != wrong-tag-name ]] || tag=v0.0.0
      printf '{"tag":"%s","verification":{"verified":%s},"object":{"type":"%s","sha":"%s"}}\n' "$tag" "$verified" "$type" "$GITHUB_SHA"
      ;;
    */commits/*)
      local verified=true
      [[ "$scenario" != unsigned-commit ]] || verified=false
      printf '{"commit":{"verification":{"verified":%s}}}\n' "$verified"
      ;;
    *) printf 'Unexpected gh call: %s\n' "$*" >&2; return 1 ;;
  esac
}

nix() {
  [[ "$scenario" != wrong-version ]] && printf '0.1.0' || printf '0.2.0'
}

reject_candidate() {
  local scenario=$1 expected=$2 tag=${3:-v0.1.0} output
  if output=$(check_release_candidate "$tag" 2>&1); then
    printf 'Candidate unexpectedly accepted: %s\n' "$scenario" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    printf 'Candidate %s rejected for the wrong reason:\n%s\n' "$scenario" "$output" >&2
    exit 1
  fi
}

scenario=valid
check_release_candidate v0.1.0
reject_candidate invalid-tag 'stable version tag' v01.0.0
reject_candidate injected-tag 'stable version tag' 'v0.1.0; echo unsafe'
reject_candidate prerelease 'stable version tag' v0.1.0-rc.1
reject_candidate dirty 'checkout must be clean'
reject_candidate missing-environment 'Configure release approval'
reject_candidate no-reviewers 'Configure release approval'
reject_candidate other-reviewer 'Configure release approval'
reject_candidate self-review-disabled 'Configure release approval'
reject_candidate lightweight 'annotated and signed'
reject_candidate unsigned-tag 'verify the release tag'
reject_candidate nested-tag 'verify the release tag'
reject_candidate wrong-tag-name 'verify the release tag'
reject_candidate off-main 'must be on the main history'
reject_candidate unsigned-commit 'verify the release commit'
reject_candidate wrong-version 'package version differ'
GITHUB_EVENT_NAME=push reject_candidate automatic 'manually from main'
GITHUB_REF=refs/heads/other reject_candidate other-branch 'manually from main'
EXPECTED_RELEASE_COMMIT=3333333333333333333333333333333333333333 \
  reject_candidate moved-tag 'changed after candidate validation'
EXPECTED_RELEASE_TAG_OBJECT=3333333333333333333333333333333333333333 \
  reject_candidate resigned-tag 'tag object changed after candidate validation'

printf 'Release candidates require owner approval, signed immutable tags, and matching versions on main.\n'
