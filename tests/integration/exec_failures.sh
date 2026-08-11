#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
repo_root=${2:?repository root is required}
report=$(mktemp)
trap 'rm -f "$report"' EXIT

check_exec_failure() {
  local diagnosis_id=$1
  shift

  set +e
  "$why_binary" --json -- "$@" >"$report"
  local why_status=$?
  set -e

  if [[ "$why_status" -ne 1 ]]; then
    echo "expected diagnosed-failure exit code 1 for $diagnosis_id, got $why_status" >&2
    sed -n '1,200p' "$report" >&2
    exit 1
  fi

  grep -q '"result": "failed"' "$report"
  grep -q '"exec_failed": true' "$report"
  grep -q "\"id\": \"$diagnosis_id\"" "$report"
  grep -q '"confidence": "certain"' "$report"
}

check_exec_failure exec.command_not_found "$repo_root/tests/fixtures/exec/does-not-exist"
check_exec_failure exec.permission_denied "$repo_root/tests/fixtures/exec/permission_denied"
check_exec_failure exec.invalid_executable "$repo_root/tests/fixtures/exec/invalid_executable"
check_exec_failure exec.interpreter_missing "$repo_root/tests/fixtures/exec/missing_interpreter"
