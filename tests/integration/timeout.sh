#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
report=$(mktemp)
trap 'rm -f "$report"' EXIT

SECONDS=0
set +e
"$why_binary" --json --timeout 250ms -- sh -c 'sleep 10 & wait' >"$report"
status=$?
set -e

if [[ $status -ne 124 ]]; then
  echo "expected Why timeout exit code 124, got $status" >&2
  sed -n '1,200p' "$report" >&2
  exit 1
fi
if [[ $SECONDS -ge 5 ]]; then
  echo "timeout did not terminate the process tree promptly" >&2
  exit 1
fi
grep -q '"timed_out": true' "$report"
grep -q '"timeout_ms": 250' "$report"
grep -q '"id": "process.timeout"' "$report"
if grep -q '"id": "process.sigkill"' "$report"; then
  echo "Why-induced SIGKILL was misdiagnosed as target failure" >&2
  exit 1
fi
