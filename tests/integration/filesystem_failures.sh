#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
fixture=${2:?file fixture is required}
test_tmp=$(mktemp -d)
report=$(mktemp)
trap 'chmod 0700 "$test_tmp/denied" 2>/dev/null || true; rm -rf -- "$test_tmp"; rm -f "$report"' EXIT

mkdir "$test_tmp/directory"
printf 'data' > "$test_tmp/denied"
chmod 000 "$test_tmp/denied"
printf 'data' > "$test_tmp/not-directory"

check_failure() {
  local id=$1
  local errno=$2
  shift 2
  set +e
  "$why_binary" --json -- "$fixture" "$@" >"$report"
  local status=$?
  set -e
  if [[ $status -ne 1 ]]; then
    echo "expected diagnosed failure for $id, got $status" >&2
    sed -n '1,200p' "$report" >&2
    exit 1
  fi
  grep -q "\"id\": \"$id\"" "$report"
  grep -q "\"errno\": \"$errno\"" "$report"
  grep -q '"confidence": "likely"' "$report"
}

check_failure filesystem.path_missing ENOENT open "$test_tmp/missing"
check_failure filesystem.permission_denied EACCES open "$test_tmp/denied"
check_failure filesystem.path_is_directory EISDIR write "$test_tmp/directory"
check_failure filesystem.path_component_not_directory ENOTDIR open "$test_tmp/not-directory/child"
check_failure resource.file_descriptor_limit EMFILE emfile /dev/null

set +e
"$why_binary" --json -- "$fixture" recover "$test_tmp/recovered" >"$report"
status=$?
set -e
if [[ $status -ne 2 ]]; then
  echo "expected unknown failure after successful retry, got $status" >&2
  sed -n '1,200p' "$report" >&2
  exit 1
fi
grep -q '"confidence": "unknown"' "$report"
if grep -q 'filesystem.path_missing' "$report"; then
  echo "recovered file failure was incorrectly diagnosed" >&2
  exit 1
fi
