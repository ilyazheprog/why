#!/usr/bin/env bash
set -euo pipefail

why_binary=${1:?why binary is required}
listener_fixture=${2:?listener fixture is required}
connect_fixture=${3:?connect fixture is required}
report=$(mktemp)
address_file=$(mktemp)
listener_pid=

cleanup() {
  if [[ -n "$listener_pid" ]]; then kill "$listener_pid" 2>/dev/null || true; fi
  rm -f "$report" "$address_file"
}
trap cleanup EXIT

WHY_FIXTURE_HOLD=1 WHY_FIXTURE_ADDRESS_FILE="$address_file" "$listener_fixture" 127.0.0.1:0 &
listener_pid=$!
for _ in {1..50}; do
  [[ -s "$address_file" ]] && break
  sleep 0.1
done
if [[ ! -s "$address_file" ]]; then echo "listener did not publish its address" >&2; exit 1; fi
address=$(<"$address_file")
kill "$listener_pid"
wait "$listener_pid" 2>/dev/null || true
listener_pid=

set +e
"$why_binary" --json -- "$connect_fixture" "$address" >"$report"
why_status=$?
set -e
if [[ "$why_status" -ne 1 ]]; then
  echo "expected diagnosed-failure exit code 1, got $why_status" >&2
  sed -n '1,200p' "$report" >&2
  exit 1
fi
grep -q '"id": "network.connection_refused"' "$report"
grep -q '"name": "connect"' "$report"
grep -q '"errno": "ECONNREFUSED"' "$report"

WHY_FIXTURE_RECOVER=1 "$why_binary" --json -- "$connect_fixture" "$address" >"$report"
grep -q '"result": "succeeded"' "$report"
grep -q '"confidence": "unknown"' "$report"
if grep -q 'network.connection_refused' "$report"; then
  echo "recovered connection failure was incorrectly diagnosed" >&2
  exit 1
fi
