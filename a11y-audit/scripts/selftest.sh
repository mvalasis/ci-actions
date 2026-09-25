#!/usr/bin/env bash
# Offline self-test for a11y-audit — the CRASH-GUARD + ATTRIBUTION layer, and
# (cases H–I) where the verify-token may and may not go.
#
# No network, no Chromium, no real pa11y-ci: every case stubs `pa11y-ci` on PATH
# and runs the REAL audit.sh, then reads the exit code and the step summary an
# operator would actually see. H–I also stand in `curl` and `mktemp`.
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
echo "# (H) the verify-token stays out of argv, the environment and readable files"
# Before v1.15.1 the token rode curl's ARGV (-H "X-Verify-Source: $VERIFY_TOKEN"),
# which `ps` shows to every process on the runner and an argv-logging wrapper on
# PATH records; it sat in /tmp/pa11y-ci.json under the default umask, never
# removed; and it stayed exported into pa11y-ci, Chromium and their npm deps.
# Each stand-in records what one of those surfaces saw: `curl` logs its argv and
# the headers it was told to send, `pa11y-ci` records its environment and stats
# its --config WHILE audit.sh runs, and `mktemp` logs every dir it makes, so a dir
# left behind on any exit path is caught. They find their log dir from their own
# path, so nothing is added to the environment under test.
# A canary, minted per run. A fixed literal here is exactly the shape gitleaks'
# generic-api-key matches (a key-named variable, a 10+ char value), and the
# security-baseline self-scan reported the old one as a T0 critical.
TOKEN="a11y-canary-$$-$RANDOM"
cat > "$WORK/bin/curl" <<'EOF'
#!/usr/bin/env bash
W="$(cd "$(dirname "$0")/.." && pwd)"
{ printf 'curl'; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } >> "$W/curl-argv.log"
prev=""
for a in "$@"; do
  if [ "$prev" = "-H" ] || [ "$prev" = "--header" ]; then
    case "$a" in
      @*) ls -l "${a#@}" | cut -c1-10 >> "$W/curl-hdrfile-mode.log"; cat "${a#@}" >> "$W/curl-headers.log" ;;
      *) printf '%s\n' "$a" >> "$W/curl-headers.log" ;;
    esac
  fi
  prev="$a"
done
printf '<urlset><url><loc>https://example.com/</loc></url></urlset>\n'
EOF
cat > "$WORK/bin/mktemp" <<'EOF'
#!/usr/bin/env bash
W="$(cd "$(dirname "$0")/.." && pwd)"
if [ -e "$W/mktemp-fail" ]; then echo "mktemp: injected failure" >&2; exit 1; fi
out=$(/usr/bin/mktemp "$@") || exit $?
printf '%s\n' "$out" >> "$W/mktemp-made.log"
printf '%s\n' "$out"
EOF
cat > "$WORK/bin/pa11y-ci" <<'EOF'
#!/usr/bin/env bash
W="$(cd "$(dirname "$0")/.." && pwd)"
env > "$W/pa11y-env.txt"
cfg=""
while [ $# -gt 0 ]; do case "$1" in --config) cfg="$2"; shift 2 ;; *) shift ;; esac; done
printf '%s\n' "$cfg" > "$W/pa11y-cfg-path.txt"
if [ -f "$cfg" ]; then
  ls -l "$cfg" | cut -c1-10 > "$W/pa11y-cfg-mode.txt"
  ls -ld "$(dirname "$cfg")" | cut -c1-10 > "$W/pa11y-cfgdir-mode.txt"
  cp "$cfg" "$W/pa11y-cfg-seen.json"
fi
[ -e "$W/pa11y-fault" ] && exit 1
echo "> https://example.com/ - 0 errors"
exit 0
EOF
chmod +x "$WORK/bin/curl" "$WORK/bin/mktemp" "$WORK/bin/pa11y-ci"
reset_h() {
  rm -f "$WORK"/curl-argv.log "$WORK"/curl-headers.log "$WORK"/curl-hdrfile-mode.log \
        "$WORK"/mktemp-made.log "$WORK"/mktemp-fail "$WORK"/pa11y-fault "$WORK"/pa11y-env.txt \
        "$WORK"/pa11y-cfg-path.txt "$WORK"/pa11y-cfg-mode.txt "$WORK"/pa11y-cfgdir-mode.txt \
        "$WORK"/pa11y-cfg-seen.json
}
# every dir the mktemp stand-in made is gone (fails closed when it made none)
workdirs_gone() {
  [ -s "$WORK/mktemp-made.log" ] || return 1
  while IFS= read -r d; do [ -e "$d" ] && return 1; done < "$WORK/mktemp-made.log"
  return 0
}
in_file() { [ -f "$2" ] && grep -qF -- "$1" "$2"; }

reset_h; mkdir -p "$WORK/tmp-h"
run_audit_sh "$AUDIT" true VERIFY_TOKEN="$TOKEN" SITEMAP_URL=https://example.com/sitemap.xml TMPDIR="$WORK/tmp-h"
check "a clean audit still exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
# A bare `mktemp -d` ignores $TMPDIR on macOS; only an explicit template honours it.
tmpl=1
if [ -f "$WORK/mktemp-made.log" ]; then
  while IFS= read -r d; do case "$d" in "$WORK/tmp-h/a11y-audit."*) tmpl=0 ;; esac; done < "$WORK/mktemp-made.log"
fi
check "the work dir honours \$TMPDIR (an explicit mktemp template)" "$tmpl"
check "curl fetched the sitemap (the token path was exercised)" "$([ -s "$WORK/curl-argv.log" ] && echo 0 || echo 1)"
check "the token is NOT in curl's argv (what ps, or an argv-logging wrapper, sees)" "$(in_file "$TOKEN" "$WORK/curl-argv.log" && echo 1 || echo 0)"
check "…yet curl still sends X-Verify-Source: <token>" "$([ -f "$WORK/curl-headers.log" ] && grep -qxF "X-Verify-Source: $TOKEN" "$WORK/curl-headers.log" && echo 0 || echo 1)"
check "…read from a mode-600 file" "$(grep -qx -- '-rw-------' "$WORK/curl-hdrfile-mode.log" 2>/dev/null && echo 0 || echo 1)"
# -L would replay the token to whatever host a 3xx names; so would a cluster like -fsSL.
check "…and follows no redirect (no -L / --location)" "$(grep -qE '\[(-[A-Za-z]*L[A-Za-z]*|--location|--location-trusted)\]' "$WORK/curl-argv.log" 2>/dev/null && echo 1 || echo 0)"
check "pa11y-ci does NOT inherit the token (nor do Chromium and its deps)" "$(in_file "$TOKEN" "$WORK/pa11y-env.txt" && echo 1 || echo 0)"
check "…but its config still sends X-Verify-Source to the audited page" "$(in_file "\"X-Verify-Source\": \"$TOKEN\"" "$WORK/pa11y-cfg-seen.json" && echo 0 || echo 1)"
# `\?` is a GNU BRE extension that BSD sed reads as a literal `?`. Until v1.15.3
# the <loc> strip was `sed 's#</\?loc>##g'`, so on macOS both tags survived and
# the config handed pa11y-ci "<loc>https://…</loc>" to load. GNU sed stripped
# them, so only the macOS leg can go red here.
check "the sitemap's URL reaches the config bare (\"https://example.com/\")" "$(in_file '"https://example.com/"' "$WORK/pa11y-cfg-seen.json" && echo 0 || echo 1)"
check "…with no <loc> or </loc> left in it" "$([ -s "$WORK/pa11y-cfg-seen.json" ] && ! grep -qF 'loc>' "$WORK/pa11y-cfg-seen.json" && echo 0 || echo 1)"
check "the config is not the shared, fixed /tmp/pa11y-ci.json" "$([ -s "$WORK/pa11y-cfg-path.txt" ] && ! grep -qx '/tmp/pa11y-ci.json' "$WORK/pa11y-cfg-path.txt" && echo 0 || echo 1)"
check "…it is mode 600 while the script runs" "$(grep -qx -- '-rw-------' "$WORK/pa11y-cfg-mode.txt" 2>/dev/null && echo 0 || echo 1)"
check "…inside a 0700 dir" "$(grep -qx 'drwx------' "$WORK/pa11y-cfgdir-mode.txt" 2>/dev/null && echo 0 || echo 1)"
check "…which is gone after exit" "$(workdirs_gone && echo 0 || echo 1)"
check "the token reaches neither the step summary nor stderr" "$( { in_file "$TOKEN" "$SUMMARY" || in_file "$TOKEN" "$STDERR"; } && echo 1 || echo 0)"

reset_h
run_audit_sh "$AUDIT" true SITEMAP_URL=https://example.com/sitemap.xml
# bash 3.2 reads "${arr[@]}" on an empty array as unbound under `set -u`: with no
# token the sitemap command substitution died before curl ran, and the run
# reported a clean skip. Only the macOS (3.2) leg can go red here.
check "no token: the sitemap is still fetched (bash 3.2 empty-array abort)" "$([ -s "$WORK/curl-argv.log" ] && echo 0 || echo 1)"
check "…and audited, not reported as a skip" "$(in_summary 'no URLs to audit' && echo 1 || echo 0)"
check "…with no X-Verify-Source header" "$(in_file 'X-Verify-Source' "$WORK/curl-headers.log" && echo 1 || echo 0)"

reset_h; touch "$WORK/pa11y-fault"
run_audit_sh "$AUDIT" true VERIFY_TOKEN="$TOKEN" URLS=https://example.com/
check "a pa11y-ci fault is still a crash, not a verdict" "$(in_summary 'a11y-audit crashed' && echo 0 || echo 1)"
check "…and the work dir holding the token is still removed" "$(workdirs_gone && echo 0 || echo 1)"
reset_h
run_audit_sh "$AUDIT" true VERIFY_TOKEN="$TOKEN"
check "a no-URL skip removes the work dir too" "$(in_summary 'no URLs to audit' && workdirs_gone && echo 0 || echo 1)"

echo
echo "# (I) no private work dir (mktemp fails) — a TOOL fault, and nothing is written"
reset_h; touch "$WORK/mktemp-fail"
run_audit_sh "$AUDIT" false VERIFY_TOKEN="$TOKEN" URLS=https://example.com/
check "report mode exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…and reports the crash, naming the work dir" "$(in_summary 'a11y-audit crashed' && in_summary 'private work dir' && echo 0 || echo 1)"
check "…and pa11y-ci never ran" "$([ -e "$WORK/pa11y-env.txt" ] && echo 1 || echo 0)"
touch "$WORK/mktemp-fail"
run_audit_sh "$AUDIT" true VERIFY_TOKEN="$TOKEN" URLS=https://example.com/
check "fail-on-violations exits 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
reset_h
rm -f "$WORK/bin/curl" "$WORK/bin/mktemp"

echo
if [ "$fails" -eq 0 ]; then
  echo "✅ all a11y-audit self-tests passed"
  exit 0
fi
echo "❌ $fails a11y-audit self-test(s) failed"
exit 1
