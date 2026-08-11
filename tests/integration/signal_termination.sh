#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
report=$(mktemp)
trap 'rm -f "$report"' EXIT

check_signal() {
  local shell_signal=$1
  local signal=$2
  local diagnosis_id=$3

  set +e
  "$why_binary" --json -- sh -c "kill -$shell_signal \$\$" >"$report"
  local why_status=$?
  set -e

  if [[ "$why_status" -ne 1 ]]; then
    echo "expected diagnosed-failure exit code 1 for $signal, got $why_status" >&2
    sed -n '1,200p' "$report" >&2
    exit 1
  fi

  grep -q "\"id\": \"$diagnosis_id\"" "$report"
  grep -q "\"signal\": \"$signal\"" "$report"
  grep -q '"confidence": "certain"' "$report"
}

check_signal SEGV SIGSEGV process.sigsegv
check_signal ABRT SIGABRT process.sigabrt
check_signal KILL SIGKILL process.sigkill

if grep -qi 'oom' "$report"; then
  echo "SIGKILL was incorrectly attributed to OOM" >&2
  exit 1
fi
