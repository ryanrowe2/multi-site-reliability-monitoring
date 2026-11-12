#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
run() {
  local label="$1" response="$2" timestamp="$3"
  printf '\n### %s (%s)\n' "$label" "$timestamp"
  php "$ROOT/bin/monitor.php" uptime --config "$ROOT/config/demo.json" --responses "$ROOT/examples/responses/$response.json" --state "$TMP/state.json" --at "$timestamp"
}
run 'Healthy' healthy 2026-01-01T00:00:00Z
run 'New failure' failure 2026-01-01T00:30:00Z
run 'Unchanged failure' failure 2026-01-01T01:00:00Z
run 'Six-hour reminder' failure 2026-01-01T06:30:00Z
run 'Changed failure' changed 2026-01-01T07:00:00Z
run 'Recovered' healthy 2026-01-01T07:30:00Z
