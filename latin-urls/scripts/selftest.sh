#!/usr/bin/env bash
# Offline self-test for latin-urls — behaviour, never spelling.
#
# Builds throwaway trees and runs the REAL audit.sh against them. The bracket
# expression it guards (`[^]a-zA-Z0-9._/[-]`) has been a permanent no-op once
# already (2026-07-31, both copies in the fleet's pre-push hook): a `grep -q` over the
# script cannot tell a working set from a broken one, so every case here asserts an
# exit code plus the line an operator would read. Written for bash 3.2 (macOS) and
# bash 5 (CI) — no assoc arrays, no mapfile.
#
# Run: bash latin-urls/scripts/selftest.sh   (exit 0 = pass, 1 = a regression)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AUDIT="$HERE/audit.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fails=0
check() {  # $1 = name, $2 = 0/1 condition result
  if [ "$2" -eq 0 ]; then printf '  ✅ %s\n' "$1"; else printf '  ❌ %s\n' "$1"; fails=$((fails + 1)); fi
}

# run_audit <script> <tree-dir> [KEY=VAL ...] → sets RC, SUMMARY (file), STDERR (file)
run_audit() {
  local script="$1" tree="$2"; shift 2
  SUMMARY="$WORK/summary.md"; STDERR="$WORK/stderr.txt"
  : > "$SUMMARY"; : > "$STDERR"
  ( cd "$tree" && env -i PATH="/usr/bin:/bin" GITHUB_STEP_SUMMARY="$SUMMARY" "$@" bash "$script" ) >/dev/null 2>"$STDERR"
  RC=$?
}
in_summary() { grep -qi -- "$1" "$SUMMARY"; }
in_stderr()  { grep -qi -- "$1" "$STDERR"; }
mktree() {  # mktree <name> → path with an ASCII-clean dist + src/pages
  local d="$WORK/$1"
  mkdir -p "$d/src/pages/about" "$d/dist/about" "$d/dist/wp-content/uploads/2026"
  : > "$d/dist/index.html"; : > "$d/dist/about/index.html"
  printf '%s' "$d"
}

echo "# (A) clean tree → exit 0"
T=$(mktree clean)
run_audit "$AUDIT" "$T"
check "clean tree exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…and the summary says clean" "$(in_summary 'clean' && echo 0 || echo 1)"

echo
echo "# (B) non-ASCII directory under src/pages → exit 1 (the headline no-op of 2026-07-31)"
T=$(mktree pages-greek); mkdir -p "$T/src/pages/ελληνικά"
run_audit "$AUDIT" "$T"
check "Greek src/pages dir exits 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…names the src/pages finding" "$(in_stderr 'src/pages has non-ASCII' && echo 0 || echo 1)"

echo
echo "# (C) non-ASCII page path under dist/ → exit 1"
T=$(mktree dist-greek); mkdir -p "$T/dist/προϊόντα"; : > "$T/dist/προϊόντα/index.html"
run_audit "$AUDIT" "$T"
check "Greek dist/ path exits 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…names the dist/ finding" "$(in_stderr 'dist/ has non-ASCII' && echo 0 || echo 1)"

echo
echo "# (D) Astro dynamic routes + ASCII punctuation are NOT findings"
T=$(mktree dynamic); mkdir -p "$T/src/pages/[slug]" "$T/src/pages/[...path]" "$T/src/pages/blog/my-post_v2.old" "$T/dist/[slug]" "$T/dist/about-us"
: > "$T/dist/[slug]/index.html"; : > "$T/dist/about-us/index.html"
run_audit "$AUDIT" "$T"
check "[slug] / [...path] / my-post_v2.old / about-us exit 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"

echo
echo "# (E) greek-urls-ok=true exempts src/pages + dist/ (intentional Greek slugs)"
T=$(mktree exempt); mkdir -p "$T/src/pages/ελληνικά" "$T/dist/προϊόντα"; : > "$T/dist/προϊόντα/index.html"
run_audit "$AUDIT" "$T" GREEK_URLS_OK=true
check "exempt site exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "…and the summary says exempt" "$(in_summary 'exempt' && echo 0 || echo 1)"

echo
echo "# (F) the uploads carve-out: a Greek filename under /wp-content/uploads/ is a download"
T=$(mktree uploads); : > "$T/dist/wp-content/uploads/2026/τιμοκατάλογος.pdf"
run_audit "$AUDIT" "$T"
check "Greek upload filename exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"

echo
echo "# (G) product slugs: non-ASCII or %-encoded → exit 1; ASCII → 0; still audited when exempt"
T=$(mktree products-bad); mkdir -p "$T/src/content/products"; : > "$T/src/content/products/λάμπα-led.json"; : > "$T/src/content/products/ok-slug.json"
run_audit "$AUDIT" "$T"
check "Greek product slug exits 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…names the product finding" "$(in_stderr 'slugs' && echo 0 || echo 1)"
T=$(mktree products-pct); mkdir -p "$T/src/content/products"; : > "$T/src/content/products/%CE%BB-lamp.json"
run_audit "$AUDIT" "$T"
check "%-encoded product slug exits 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
T=$(mktree products-ok); mkdir -p "$T/src/content/products"; : > "$T/src/content/products/led-lamp_v2.json"
run_audit "$AUDIT" "$T"
check "ASCII product slug exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
T=$(mktree products-exempt); mkdir -p "$T/src/content/products"; : > "$T/src/content/products/λάμπα.json"
run_audit "$AUDIT" "$T" GREEK_URLS_OK=true
check "greek-urls-ok does NOT exempt product slugs (they 404 regardless)" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"

echo
echo "# (H) no dist/ → exit 2, a FAULT, never a verdict"
T="$WORK/nodist"; mkdir -p "$T/src/pages"
run_audit "$AUDIT" "$T"
check "missing dist exits 2" "$([ "$RC" -eq 2 ] && echo 0 || echo 1)"
check "…and is reported as no verdict" "$(in_stderr 'no verdict' && echo 0 || echo 1)"

echo
echo "# (I) unbound variable under set -u, injected ABOVE the config block → exit 2 + crash report"
sed 's|^DIST="${DIST:-dist}"|DIST="${DELIBERATELY_UNBOUND_XYZ}"|' "$AUDIT" > "$WORK/audit-unbound.sh"
grep -q 'DELIBERATELY_UNBOUND_XYZ' "$WORK/audit-unbound.sh"
check "fault injection applied (fails closed if the config line was renamed)" $?
T=$(mktree crash)
run_audit "$WORK/audit-unbound.sh" "$T"
check "abort exits 2 (not 0, not 1)" "$([ "$RC" -eq 2 ] && echo 0 || echo 1)"
check "…and reports a crash, which a bare set -u abort would not" "$(in_summary 'crashed' && echo 0 || echo 1)"

echo
echo "# (J) the bracket-expression regression: the BROKEN set must be caught by (B)"
sed "s|^NON_ASCII='\[^\]a-zA-Z0-9._/\[-\]'|NON_ASCII='[^a-zA-Z0-9._/\\\\[\\\\]-]'|" "$AUDIT" > "$WORK/audit-broken.sh"
if grep -q "NON_ASCII='\[^a-zA-Z0-9._/" "$WORK/audit-broken.sh"; then
  T=$(mktree broken); mkdir -p "$T/src/pages/ελληνικά"
  run_audit "$WORK/audit-broken.sh" "$T"
  check "mutation control: the 2026-07-31 broken set would pass a Greek dir (so (B) is load-bearing)" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
else
  check "mutation control could not be applied (NON_ASCII line renamed?)" 1
fi

# greek_paths <tree> <pages> <dist> <products> → that many bad paths for each audit
greek_paths() {
  local t="$1" i
  mkdir -p "$t/src/content/products"
  for ((i = 1; i <= $2; i++)); do mkdir -p "$t/src/pages/σελίδα-$i"; done
  for ((i = 1; i <= $3; i++)); do mkdir -p "$t/dist/σελίδα-$i"; : > "$t/dist/σελίδα-$i/index.html"; done
  for ((i = 1; i <= $4; i++)); do : > "$t/src/content/products/λάμπα-$i.json"; done
}
rows_per_audit() {  # the summary's path rows under each ### title, space-separated
  # shellcheck disable=SC2016  # the backtick is Markdown, not a command substitution
  awk '/^### /{if (s) printf "%d ", c; s = 1; c = 0; next} /^- `/{c++} END{if (s) printf "%d", c}' "$SUMMARY"
}

echo
echo "# (K) every bad path is counted, 20 are listed: 21 / 22 / 23 (until v1.29.8 each read (20))"
T=$(mktree many); greek_paths "$T" 21 22 23
run_audit "$AUDIT" "$T"
check "21 + 22 + 23 bad paths exit 1" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
check "…each log title counts every path: (21), (22), (23)" "$(in_stderr 'non-ASCII directories.*(21)$' && in_stderr 'non-ASCII page paths.*(22)$' && in_stderr 'slugs.*(23)$' && echo 0 || echo 1)"
check "…and so does each summary title" "$(in_summary '^### .*non-ASCII directories.*(21)$' && in_summary '^### .*non-ASCII page paths.*(22)$' && in_summary '^### .*slugs.*(23)$' && echo 0 || echo 1)"
check "…the findings total is 66" "$(in_summary '\*\*66 finding(s)' && echo 0 || echo 1)"
check "…the summary lists 20 paths under each title" "$([ "$(rows_per_audit)" = "20 20 20" ] && echo 0 || echo 1)"
check "…then says how many more: 1, 2, 3" "$(in_summary '^- …and 1 more$' && in_summary '^- …and 2 more$' && in_summary '^- …and 3 more$' && echo 0 || echo 1)"
check "…and so does the log" "$(in_stderr '^  …and 1 more$' && in_stderr '^  …and 2 more$' && in_stderr '^  …and 3 more$' && echo 0 || echo 1)"
check "…which lists 20 paths under each title too" "$([ "$(grep -c '^  .*σελίδα-' "$STDERR")" -eq 40 ] && [ "$(grep -c '^  λάμπα-' "$STDERR")" -eq 20 ] && echo 0 || echo 1)"

echo
echo "# (L) exactly 20 per audit: every path listed, no 'more' row"
T=$(mktree twenty); greek_paths "$T" 20 20 20
run_audit "$AUDIT" "$T"
check "each title says (20), the total 60" "$(in_stderr 'non-ASCII directories.*(20)$' && in_stderr 'non-ASCII page paths.*(20)$' && in_stderr 'slugs.*(20)$' && in_summary '\*\*60 finding(s)' && echo 0 || echo 1)"
check "…the summary lists all 20 under each title" "$([ "$(rows_per_audit)" = "20 20 20" ] && echo 0 || echo 1)"
check "…and neither the summary nor the log has a 'more' row" "$( { in_summary 'and [0-9]* more' || in_stderr 'and [0-9]* more'; } && echo 1 || echo 0)"

echo
if [ "$fails" -eq 0 ]; then echo "latin-urls selftest: all green"; exit 0; fi
echo "latin-urls selftest: $fails regression(s)"; exit 1
