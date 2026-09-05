#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# `scripts/check-contribution-signing.sh`, run against a fixture repository.
#
# The check is the first gate of every merge request, so what it accepts and
# refuses is pinned here rather than discovered by a contributor whose branch
# it rejects for the wrong reason. Run it from anywhere; it writes only to a
# temporary directory and removes it.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="$root/scripts/check-contribution-signing.sh"
author="contributor@example.com"
account="gitlab.com/example-contributor"
passed=0 failed=0

fixture() {                       # fixture -> prints the fixture path
  local dir; dir="$(mktemp -d)"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.name Example
  git -C "$dir" config user.email "$author"
  [[ -f "$root/CLA.md" ]] && cp "$root/CLA.md" "$dir/CLA.md"
  printf '# Contributors who have agreed to CLA.md\n' > "$dir/CLA-SIGNERS.md"
  printf 'gitlab.com/r5e-tjones\n' > "$dir/MAINTAINERS"
  git -C "$dir" add -A && git -C "$dir" commit -qm base
  git -C "$dir" rev-parse HEAD > "$dir.base"
  printf '%s' "$dir"
}

expect() {                        # expect <name> <want-status> <dir> <require-cla> <account>
  local name="$1" want="$2" dir="$3" require="$4" who="${5:-}" out status
  out="$(cd "$dir" && env -u CI_MERGE_REQUEST_DIFF_BASE_SHA -u CI_COMMIT_SHA \
        -u GITLAB_USER_LOGIN R5E_REQUIRE_CLA="$require" \
        "$check" "$(cat "$dir.base")" "$who" 2>&1)"
  status=$?
  if [[ "$status" == "$want" ]]; then
    passed=$((passed + 1)); echo "ok   - $name"
  else
    failed=$((failed + 1)); echo "FAIL - $name (exit $status, wanted $want)"; echo "$out" | sed 's/^/       /'
  fi
  rm -rf "$dir" "$dir.base"
}

commit() {                        # commit <dir> <message>
  printf '%s\n' "$2" > "$1/change.txt"
  git -C "$1" add change.txt && git -C "$1" commit -qm "$2"
}

sign() {                          # sign <dir> <account> <digest>
  printf '%s v1.0 cla:sha256:%s 2026-09-05 countersigned-by:gitlab.com/r5e-tjones\n' \
    "$2" "$3" >> "$1/CLA-SIGNERS.md"
}

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
digest_of() { (cd "$1" && sha256_of CLA.md); }

# --- DCO -------------------------------------------------------------------
d="$(fixture)"; commit "$d" "no signoff"
expect "a commit without a signoff fails" 1 "$d" 0

d="$(fixture)"; commit "$d" "signed

Signed-off-by: Example <$author>"
expect "a signed-off commit passes" 0 "$d" 0

d="$(fixture)"; commit "$d" "wrong signer

Signed-off-by: Other <other@example.com>"
expect "a signoff for a different author does not count" 1 "$d" 0

# --- CLA -------------------------------------------------------------------
if [[ -f "$root/CLA.md" ]]; then
  d="$(fixture)"; commit "$d" "signed

Signed-off-by: Example <$author>"
  expect "the CLA is only required when asked for" 0 "$d" 0 "$account"

  d="$(fixture)"; commit "$d" "signed

Signed-off-by: Example <$author>"
  expect "an unsigned account fails" 1 "$d" 1 "$account"

  d="$(fixture)"; sign "$d" "$account" "$(digest_of "$d")"; commit "$d" "signed

Signed-off-by: Example <$author>"
  expect "a signed account passes" 0 "$d" 1 "$account"

  d="$(fixture)"; sign "$d" "$account" "$(printf '0%.0s' {1..64})"; commit "$d" "signed

Signed-off-by: Example <$author>"
  expect "a signature against an older CLA text does not count" 1 "$d" 1 "$account"

  d="$(fixture)"; commit "$d" "signed

Signed-off-by: Example <$author>"
  expect "a maintainer needs no CLA line" 0 "$d" 1 "gitlab.com/r5e-tjones"

  # The shipped signers file agrees with the shipped CLA text.
  want="$(cd "$root" && sha256_of CLA.md)"
  if grep -q "cla:sha256:$want" "$root/CLA-SIGNERS.md"; then
    passed=$((passed + 1)); echo "ok   - the shipped signers file agrees with the shipped CLA"
  else
    failed=$((failed + 1)); echo "FAIL - the shipped signers file does not carry sha256 $want"
  fi
fi

echo "passed $passed, failed $failed"
[[ $failed -eq 0 ]]
