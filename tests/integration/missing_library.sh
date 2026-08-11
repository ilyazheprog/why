#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
patch_fixture=${2:?patch fixture is required}
test_tmp=$(mktemp -d)
report=$(mktemp)
trap 'rm -rf -- "$test_tmp"; rm -f "$report"' EXIT

library=$($patch_fixture /bin/true "$test_tmp/missing-library")
set +e
"$why_binary" --json -- "$test_tmp/missing-library" >"$report"
status=$?
set -e
if [[ $status -ne 1 ]]; then
  echo "expected diagnosed missing-library failure, got $status" >&2
  sed -n '1,240p' "$report" >&2
  exit 1
fi
grep -q '"id": "elf.library_missing"' "$report"
grep -q "\"needed\": \"$library\"" "$report"
grep -q '"confidence": "certain"' "$report"
grep -q '"errno": "ENOENT"' "$report"
