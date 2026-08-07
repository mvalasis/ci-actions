#!/usr/bin/env bash
# Offline self-test for a11y-audit — the CRASH-GUARD + ATTRIBUTION layer.
#
# No network, no Chromium, no real pa11y-ci: every case stubs `pa11y-ci` on PATH
# and runs the REAL audit.sh, then reads the exit code and the step summary an
# operator would actually see.
#
# WHY BEHAVIOURAL. The guard is a `trap … EXIT` plus a sentinel, and both halves
# fail silently when wrong: a trap armed one line too late still LOOKS armed, and
# a `grep -q 'trap.*EXIT' audit.sh` cannot tell the difference. The first draft of
# this guard really was armed below the config block, and case (B) below — an
# unbound variable injected ABOVE the old position — is what caught it. Assert by
# crashing the script, never by reading it.
#
# Run: bash a11y-audit/scripts/selftest.sh   (exit 0 = pass, 1 = a regression)
# Written for bash 3.2 (macOS) as well as bash 5 — no assoc arrays, no mapfile.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AUDIT="$HERE/audit.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fails=0
check() {  # $1 = name, $2 = 0/1 condition result
  if [ "$2" -eq 0 ]; then
    printf '  ✅ %s\n' "$1"
  else
    printf '  ❌ %s\n' "$1"
    fails=$((fails + 1))
  fi
}

# Write a `pa11y-ci` stub that prints $2… and exits $1.
stub_pa11y() {
  local rc="$1"; shift
  mkdir -p "$WORK/bin"
  {
    printf '#!/usr/bin/env bash\n'
    for line in "$@"; do printf 'printf "%%s\\n" %q\n' "$line"; done
    printf 'exit %s\n' "$rc"
  } > "$WORK/bin/pa11y-ci"
  chmod +x "$WORK/bin/pa11y-ci"
}

# Run audit.sh in a clean env. $1 = script path, $2 = fail-on-violations,
# rest = extra KEY=VAL. Sets: RC, SUMMARY (file), STDERR (file).
run_audit_sh() {
  local script="$1" fov="$2"; shift 2
  SUMMARY="$WORK/summary.md"; STDERR="$WORK/stderr.txt"
  : > "$SUMMARY"; : > "$STDERR"
  env -i PATH="$WORK/bin:/usr/bin:/bin" \
      GITHUB_STEP_SUMMARY="$SUMMARY" \
      FAIL_ON_VIOLATIONS="$fov" \
      "$@" \
      bash "$script" >/dev/null 2>"$STDERR"
  RC=$?
}

in_summary() { grep -qi -- "$1" "$SUMMARY"; }

echo
echo "# (A) pa11y-ci missing (exit 127) — a TOOL fault, not WCAG debt"
stub_pa11y 0 >/dev/null 2>&1; rm -f "$WORK/bin/pa11y-ci"   # ensure absent
run_audit_sh "$AUDIT" false URLS=https://example.com/
check "report mode exits 0 (a scanner fault must not block a report-mode caller)" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…and the crash is reported" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"
check "…and is NOT misattributed as WCAG errors" "$(in_summary 'WCAG errors found' && echo 1 || echo 0)"
run_audit_sh "$AUDIT" true URLS=https://example.com/
check "fail-on-violations exits 1 (conservative for an enforcing caller)" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…and the enforcing crash is reported too" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"

echo
echo "# (B) unbound variable under \`set -u\` — the class an ERR trap CANNOT catch"
# Injected into the CONFIG block, which sits ABOVE where a naively-placed guard
# would be armed. This is the regression test for guard POSITION: move the trap
# back below the config block and these two go red while everything else stays
# green. `set -u` aborts without firing ERR, so this also pins the EXIT choice.
sed 's|^STANDARD="${STANDARD:-WCAG2AA}"|STANDARD="${DELIBERATELY_UNBOUND_XYZ}"|' "$AUDIT" > "$WORK/audit-unbound.sh"
grep -q 'DELIBERATELY_UNBOUND_XYZ' "$WORK/audit-unbound.sh"
check "fault injection applied (fails closed if the config block was renamed)" $?
stub_pa11y 0 "> https://example.com/ - 0 errors"
run_audit_sh "$WORK/audit-unbound.sh" false URLS=https://example.com/
check "report mode exits 0 on an abort above the config block" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…and the abort is reported as a crash" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"
run_audit_sh "$WORK/audit-unbound.sh" true URLS=https://example.com/
check "fail-on-violations exits 1 on the same abort" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
# The exit code ALONE is vacuous here: an unguarded `set -u` abort also exits 1,
# so that assertion passes whether or not the guard ran (verified by mutation —
# it stayed green with the trap moved below the config block AND with it on ERR).
# The report is the only evidence that distinguishes the two.
check "…and reports the crash, which the bare abort would not" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"

echo
echo "# (C) real WCAG violations — a VERDICT, and the guard must keep its hands off"
stub_pa11y 2 "> https://example.com/ - 3 errors" " • Error: Images must have alternate text"
run_audit_sh "$AUDIT" false URLS=https://example.com/
check "report mode exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…reports WCAG errors" "$(in_summary 'WCAG errors found' && echo 0 || echo 1)"
check "…and does NOT claim a crash" "$(in_summary 'a11y-audit crashed' && echo 1 || echo 0)"
run_audit_sh "$AUDIT" true URLS=https://example.com/
check "fail-on-violations BLOCKS with exit 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…reports BLOCKING" "$(in_summary 'BLOCKING' && echo 0 || echo 1)"
check "…and still does NOT claim a crash" "$(in_summary 'a11y-audit crashed' && echo 1 || echo 0)"

echo
echo "# (D) clean audit — the sentinel must let a PASS through untouched"
stub_pa11y 0 "> https://example.com/ - 0 errors"
run_audit_sh "$AUDIT" true URLS=https://example.com/
check "exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "reports the PASS" "$(in_summary 'no WCAG' && echo 0 || echo 1)"
check "no crash claimed" "$(in_summary 'a11y-audit crashed' && echo 1 || echo 0)"

echo
echo "# (E) pa11y-ci ran but could not load the page (persistent 'Failed to run')"
# The page was never audited, so there is no WCAG verdict to report. Before the
# fix this fell through to 'WCAG errors found' and BLOCKED an enforcing caller on
# a verdict that was never reached.
stub_pa11y 1 "> https://example.com/ - Failed to run"
run_audit_sh "$AUDIT" true URLS=https://example.com/
check "enforcing mode exits 1 (loud, as before)" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…but reports a TOOL fault, not WCAG debt" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"
check "…and says no page was audited" "$(in_summary 'No page was audited' && echo 0 || echo 1)"
check "…and does NOT say WCAG errors found" "$(in_summary 'WCAG errors found' && echo 1 || echo 0)"
run_audit_sh "$AUDIT" false URLS=https://example.com/
check "report mode exits 0 on the same run error" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"

echo
echo "# (F) no URLs — a deliberate skip, not a crash"
stub_pa11y 0 "> x - 0 errors"
run_audit_sh "$AUDIT" true
check "exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "reports the skip" "$(in_summary 'no URLs to audit' && echo 0 || echo 1)"
check "no crash claimed" "$(in_summary 'a11y-audit crashed' && echo 1 || echo 0)"

echo
echo "# (G) the summary sink itself is unwritable — the diagnostic must survive"
# `note` swallows its own write failure so the reporter cannot fail while
# reporting; the stderr mirror is then the only surviving copy. Without it this
# fault would be completely silent.
rm -f "$WORK/bin/pa11y-ci"
: > "$WORK/stderr.txt"
env -i PATH="$WORK/bin:/usr/bin:/bin" \
    GITHUB_STEP_SUMMARY=/nonexistent-dir/summary.md \
    FAIL_ON_VIOLATIONS=false URLS=https://example.com/ \
    bash "$AUDIT" >/dev/null 2>"$WORK/stderr.txt"
rc=$?
check "still exits 0 in report mode with an unwritable summary" "$([ "$rc" -eq 0 ] && echo 0 || echo 1)"
grep -q 'a11y-audit crashed' "$WORK/stderr.txt"
check "the crash reaches stderr when the summary cannot be written" $?

echo
if [ "$fails" -eq 0 ]; then
  echo "✅ all a11y-audit self-tests passed"
  exit 0
fi
echo "❌ $fails a11y-audit self-test(s) failed"
exit 1
