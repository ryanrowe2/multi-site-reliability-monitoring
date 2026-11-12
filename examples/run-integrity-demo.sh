#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp -R "$ROOT/examples/fixtures/sites" "$TMP/sites"
cat > "$TMP/config.json" <<'JSON'
{
  "hosts": ["site-a.example.com", "site-b.example.org"],
  "reminder_seconds": {"uptime": 21600, "integrity": 86400},
  "expected_interval_seconds": {"integrity": 86400},
  "integrity": {
    "root": "sites",
    "sites": ["site-a.example.com", "site-b.example.org"],
    "core_version": "9.1.0-demo",
    "pro_header_version": "9.2.0-demo",
    "pro_runtime_version": "9.2.0-demo",
    "update_lock": "site-update-lock.php",
    "update_lock_sha256": "f30630b97d330c686cca81ca72bff1f61c84b6b06f2c96022a7d14281b173895",
    "baseline_sha256": "3625c8c415435440c2d2f9abbf1637c8b6122554932034daac4fb186b803ff08",
    "core_baseline_sha256": "399574badc069e33068531bb6baf3cd574d8e9469a4a8311bd1c7bcbd65602e4"
  }
}
JSON
run() {
  printf '\n### %s\n' "$1"
  php "$ROOT/bin/monitor.php" integrity --config "$TMP/config.json" --state "$TMP/state.json" --at "$2"
}
ASSET="$TMP/sites/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt"
run 'Consistent fleet' 2026-01-01T00:00:00Z
printf 'intentionally divergent synthetic content\n' > "$ASSET"
run 'Fingerprint divergence' 2026-01-01T00:30:00Z
cp "$ROOT/examples/fixtures/sites/site-a.example.com/wp-content/plugins/elementor-pro/synthetic-asset.txt" "$ASSET"
run 'Restored matching fingerprints' 2026-01-01T01:00:00Z
