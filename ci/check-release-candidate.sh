#!/usr/bin/env bash
set -euo pipefail

require_release_owner_approval() {
  jq -e --arg owner "$GITHUB_REPOSITORY_OWNER" '
    any(.protection_rules[]?;
      .type == "required_reviewers" and
      .prevent_self_review == false and
      (.reviewers | length) == 1 and
      .reviewers[0].type == "User" and
      .reviewers[0].reviewer.login == $owner
    )
  ' >/dev/null || {
    printf 'Configure release approval: repository owner only, self-approval allowed.\n' >&2
    return 1
  }
}

check_release_candidate() {
  local tag=$1 tag_object commit version
  local semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
  if [[ ! "$tag" =~ ^v$semver$ ]]; then
    printf 'Expected a stable version tag such as v0.1.0.\n' >&2
    return 1
  fi
  if [[ "$GITHUB_EVENT_NAME" != workflow_dispatch || "$GITHUB_REF" != refs/heads/main ]]; then
    printf 'Start releases manually from main.\n' >&2
    return 1
  fi
  if [[ -n "$(git status --porcelain)" ]]; then
    printf 'Release checkout must be clean.\n' >&2
    return 1
  fi
  gh api "repos/$GITHUB_REPOSITORY/environments/release" | require_release_owner_approval || return 1
  git fetch --no-tags origin "refs/tags/$tag:refs/tags/$tag" || return 1
  tag_object=$(git rev-parse "refs/tags/$tag")
  if [[ "$(git cat-file -t "$tag_object")" != tag ]]; then
    printf 'Release tag must be annotated and signed.\n' >&2
    return 1
  fi
  if [[ -n "${EXPECTED_RELEASE_TAG_OBJECT:-}" && "$tag_object" != "$EXPECTED_RELEASE_TAG_OBJECT" ]]; then
    printf 'Release tag object changed after candidate validation.\n' >&2
    return 1
  fi
  commit=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$tag_object" | jq -er --arg tag "$tag" '
    select(.verification.verified == true and .object.type == "commit" and .tag == $tag) | .object.sha
  ') || {
    printf 'GitHub must verify the release tag signature.\n' >&2
    return 1
  }
  git merge-base --is-ancestor "$commit" "$GITHUB_SHA" || {
    printf 'Release commit must be on the main history used to start this workflow.\n' >&2
    return 1
  }
  if [[ -n "${EXPECTED_RELEASE_COMMIT:-}" && "$commit" != "$EXPECTED_RELEASE_COMMIT" ]]; then
    printf 'Release tag changed after candidate validation.\n' >&2
    return 1
  fi
  gh api "repos/$GITHUB_REPOSITORY/commits/$commit" | jq -e '.commit.verification.verified == true' >/dev/null || {
    printf 'GitHub must verify the release commit signature.\n' >&2
    return 1
  }
  version=$(RELEASE_MANIFEST="$(git show "$commit:Cargo.toml")" nix eval --impure --raw --expr \
    '(builtins.fromTOML (builtins.getEnv "RELEASE_MANIFEST")).package.version')
  if [[ "$tag" != "v$version" ]]; then
    printf 'Release tag and Cargo package version differ.\n' >&2
    return 1
  fi
  printf 'commit=%s\nversion=%s\ntag_object=%s\n' "$commit" "$version" "$tag_object" >> "$GITHUB_OUTPUT"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  check_release_candidate "$@"
fi
