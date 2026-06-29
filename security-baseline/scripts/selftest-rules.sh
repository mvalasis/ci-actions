#!/usr/bin/env bash
# Offline regression guard for the vendored semgrep rule packs: validates each config and runs
# `semgrep --test` against its fixture (bad fixtures must fire, good fixtures must stay silent).
# Needs semgrep on PATH (or $SEMGREP_BIN). Run locally or in CI before the @v1 tag moves.
set -uo pipefail
SG="${SEMGREP_BIN:-semgrep}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # security-baseline/
cd "$DIR"
fail=0
strip() { grep -vE "NotOpenSSLWarning|warnings.warn|urllib3"; }

run() { # <rule-yaml> <fixture>
  echo "── validate $1"
  "$SG" --validate --config "$1" 2>&1 | strip | grep -E "Configuration is (valid|invalid)" || true
  if ! "$SG" --validate --config "$1" >/dev/null 2>&1; then echo "  ❌ invalid config: $1"; fail=1; return; fi
  echo "── test     $1  ×  $2"
  if "$SG" --test --config "$1" "$2" 2>&1 | strip | grep -qE "All tests passed|✓"; then
    echo "  ✅ $2"
  else
    echo "  ❌ rule self-test FAILED for $2"; "$SG" --test --config "$1" "$2" 2>&1 | strip | tail -8; fail=1
  fi
}

run rules/wp-php.yaml     rules/selftest/wp-php.php
run rules/astro-ts.yaml   rules/selftest/astro-ts.ts
run rules/astro-ts.yaml   rules/selftest/astro-ts.tsx
run rules/gha.yaml        rules/selftest/gha.yml

if [ "$fail" -eq 0 ]; then echo "✅ all rule self-tests passed"; else echo "❌ rule self-tests failed"; fi
exit "$fail"
