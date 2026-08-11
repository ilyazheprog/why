#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
fixture_binary=${2:?fixture binary is required}
report=$(mktemp)
address_file=$(mktemp)
listener_pid=

cleanup() {
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  rm -f "$report"
  rm -f "$address_file"
}
trap cleanup EXIT

WHY_FIXTURE_HOLD=1 WHY_FIXTURE_ADDRESS_FILE="$address_file" "$fixture_binary" 127.0.0.1:0 &
listener_pid=$!

for _ in {1..50}; do
  if [[ -s "$address_file" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -s "$address_file" ]]; then
  echo "listener fixture did not publish its address" >&2
  exit 1
fi
address=$(<"$address_file")

set +e
"$why_binary" --json --no-suggestions -- "$fixture_binary" "$address" >"$report"
why_status=$?
set -e

if [[ "$why_status" -ne 1 ]]; then
  echo "expected diagnosed-failure exit code 1, got $why_status" >&2
  sed -n '1,200p' "$report" >&2
  exit 1
fi

grep -q '"schema_version": "1"' "$report"
grep -q '"id": "network.bind.address_in_use"' "$report"
grep -q '"errno": "EADDRINUSE"' "$report"
grep -q '"confidence": "certain"' "$report"
