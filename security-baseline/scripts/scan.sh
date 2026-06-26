#!/usr/bin/env bash
# security-baseline: semgrep SAST + gitleaks secret scan.
# Air-gapped: no telemetry (SEMGREP_SEND_METRICS=off), no version pings, no SaaS.
# Exits non-zero (blocks the gate) on any blocking semgrep finding or detected secret.
set -uo pipefail

SEMGREP_CONFIG="${SEMGREP_CONFIG:-p/security-audit}"
SEMGREP_SEVERITY="${SEMGREP_SEVERITY:-ERROR}"
SCAN_SCOPE="${SCAN_SCOPE:-diff}"
BASE_REF="${BASE_REF:-}"
FAIL_ON_SECRETS="${FAIL_ON_SECRETS:-true}"
export SEMGREP_SEND_METRICS=off

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
note() { printf '%s\n' "$*" >>"$summary"; }

# --- resolve diff base ---
if [ -z "$BASE_REF" ]; then
  if [ -n "${GITHUB_BASE_REF:-}" ]; then
    BASE_REF="origin/${GITHUB_BASE_REF}"
  else
    BASE_REF="$(git rev-parse --verify --quiet HEAD~1 || true)"
  fi
fi

changed=""
if [ "$SCAN_SCOPE" = "diff" ] && [ -n "$BASE_REF" ]; then
  changed="$(git diff --name-only --diff-filter=d "${BASE_REF}...HEAD" 2>/dev/null || true)"
fi

note "## 🔒 security-baseline"

sg_fail=0
gl_fail=0

# --- semgrep (SAST) ---
if [ "$SCAN_SCOPE" = "diff" ]; then
  if [ -n "$changed" ]; then
    # shellcheck disable=SC2086
    semgrep scan --config "$SEMGREP_CONFIG" --severity "$SEMGREP_SEVERITY" \
      --error --metrics=off --disable-version-check --quiet $changed || sg_fail=1
  else
    note "- semgrep: no changed files in diff — skipped"
  fi
else
  semgrep scan --config "$SEMGREP_CONFIG" --severity "$SEMGREP_SEVERITY" \
    --error --metrics=off --disable-version-check --quiet . || sg_fail=1
fi
if [ "$SCAN_SCOPE" != "diff" ] || [ -n "$changed" ]; then
  [ "$sg_fail" = "0" ] && note "- ✅ semgrep: clean (severity ≥ ${SEMGREP_SEVERITY})" \
                       || note "- ❌ semgrep: blocking findings (severity ≥ ${SEMGREP_SEVERITY})"
fi

# --- gitleaks (secrets) ---
if [ "$FAIL_ON_SECRETS" = "true" ]; then
  gl_args=(detect --redact --no-banner --exit-code 1)
  if [ "$SCAN_SCOPE" = "diff" ] && [ -n "$BASE_REF" ]; then
    gl_args+=(--log-opts="${BASE_REF}..HEAD")
  fi
  gitleaks "${gl_args[@]}" || gl_fail=1
  [ "$gl_fail" = "0" ] && note "- ✅ gitleaks: no secrets" \
                       || note "- ❌ gitleaks: secret(s) detected"
fi

if [ $((sg_fail + gl_fail)) -eq 0 ]; then
  note ""
  note "**PASS**"
  exit 0
fi
note ""
note "**BLOCKED** — fix the findings above, or deliberately waive with documented rationale."
exit 1
