#!/usr/bin/env bash
set -euo pipefail

find_release_id_including_drafts() {
  gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/releases?per_page=100" | jq -r --arg tag "$RELEASE_TAG" '
    [.[][] | select(.tag_name == $tag)] |
    if length > 1 then error("multiple releases for one tag") else .[0].id // empty end
  '
}

assets=(
  "narjar-$RELEASE_VERSION.crate"
  "narjar-v$RELEASE_VERSION-x86_64-linux.tar.gz"
  SHA256SUMS
)
paths=("${assets[@]/#/target/release/}")

release_id=$(find_release_id_including_drafts)
if [[ -z "$release_id" ]]; then
  gh release create "$RELEASE_TAG" "${paths[@]}" --verify-tag --title "narjar $RELEASE_VERSION" \
    --notes-file target/release/release-notes.md
  exit 0
fi
state=target/github-release.json
gh api "repos/$GITHUB_REPOSITORY/releases/$release_id" > "$state"
release_state=$(jq -r '
  if .draft == true then "draft"
  elif .draft == false then "published"
  else error("missing release draft status")
  end
' "$state")

if [[ "$release_state" == published ]]; then
  mkdir -p target/github-release
  for asset in "${assets[@]}"; do
    gh release download "$RELEASE_TAG" --pattern "$asset" --dir target/github-release
    cmp "target/github-release/$asset" "target/release/$asset"
  done
  printf 'GitHub release already published with identical assets.\n'
else
  gh release upload "$RELEASE_TAG" "${paths[@]}" --clobber
  gh release edit "$RELEASE_TAG" --draft=false --notes-file target/release/release-notes.md
fi
