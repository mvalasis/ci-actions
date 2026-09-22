#!/usr/bin/env bash
# Offline self-test for pull-tier — every branch of `decide`, the `record` marker,
# and the crash guard, against a throwaway git repo. bash 3.2 + bash 5.
# Run: bash pull-tier/scripts/selftest.sh   (exit 0 = pass, 1 = a regression)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TIER="$HERE/tier.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
check() { if [ "$2" -eq 0 ]; then printf '  ✅ %s\n' "$1"; else printf '  ❌ %s\n' "$1"; fails=$((fails + 1)); fi; }

R="$WORK/repo"; mkdir -p "$R"; cd "$R" || exit 1
git init -q .; git config user.email t@t; git config user.name t
mkdir -p src/content/posts src/content/pages src/lib scripts content-cache
printf 'a\n' > src/content/posts/a.md; printf 'b\n' > src/content/posts/b.md; printf 'p\n' > src/content/pages/p.md
printf '// pull\n' > scripts/migrate-wp.ts; printf 'x\n' > src/lib/wp-record.ts; printf 'h\n' > src/pages.astro
git add -A; git commit -qm base; BASE=$(git rev-parse HEAD)
printf 'h2\n' > src/pages.astro; git commit -qam "template change"; HEAD1=$(git rev-parse HEAD)

PATHS_IN=$'scripts/migrate-*.ts\nsrc/lib/**\nsrc/content.config.ts\n.github/workflows/deploy.yml'
COUNTS=$'src/content/posts\nsrc/content/pages'
run_tier() {  # run_tier <script> <mode> [KEY=VAL ...] → OUT (file), STDERR (file), RC
  local script="$1" mode="$2"; shift 2
  OUT="$WORK/out.txt"; STDERR="$WORK/err.txt"; : > "$OUT"; : > "$STDERR"
  env -i PATH="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin" HOME="$WORK" GITHUB_OUTPUT="$OUT" \
      MODE="$mode" PATHS="$PATHS_IN" COUNT_PATHS="$COUNTS" MARKER="content-cache/pull-marker.json" \
      HEAD_SHA="$(git rev-parse HEAD)" "$@" bash "$script" >/dev/null 2>"$STDERR"
  RC=$?
}
pull_is() { grep -qx "pull=$1" "$OUT"; }
reason_has() { grep -qi -- "$1" "$OUT"; }

echo "# record → marker"
run_tier "$TIER" record
check "record exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
check "marker written with the fingerprint" "$(grep -q '"fingerprint":\["src/content/posts 2","src/content/pages 1"\]' content-cache/pull-marker.json && echo 0 || echo 1)"

echo; echo "# decide: a template-only push with an intact, fresh marker → pull=false"
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$BASE"
check "pull=false" "$(pull_is false && echo 0 || echo 1)"; check "…reason says intact" "$(reason_has 'intact' && echo 0 || echo 1)"

echo; echo "# decide: content events always pull"
for ev in repository_dispatch schedule workflow_dispatch; do
  run_tier "$TIER" decide EVENT_NAME="$ev" BEFORE_SHA="$BASE"
  check "$ev → pull=true" "$(pull_is true && echo 0 || echo 1)"
done

echo; echo "# decide: a push that touched a pull input → pull=true (glob forms)"
printf '// pull2\n' > scripts/migrate-wp.ts; git commit -qam "pull script"; HEAD2=$(git rev-parse HEAD)
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD1"
check "scripts/migrate-*.ts changed → pull=true" "$(pull_is true && reason_has 'pull input' && echo 0 || echo 1)"
mkdir -p src/lib/deep; printf 'y\n' > src/lib/deep/z.ts; git add -A; git commit -qm "lib deep"; HEAD3=$(git rev-parse HEAD)
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD2"
check "src/lib/** matches a nested file → pull=true" "$(pull_is true && echo 0 || echo 1)"
run_tier "$TIER" decide EVENT_NAME=pull_request PR_BASE_SHA="$HEAD2"
check "pull_request diffs against the PR base sha" "$(pull_is true && echo 0 || echo 1)"
run_tier "$TIER" decide EVENT_NAME=pull_request PR_BASE_SHA="$HEAD3"
check "pull_request with no input change and a fresh marker → pull=false" "$(pull_is false && echo 0 || echo 1)"

echo; echo "# decide: the cache must vouch for itself"
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA=0000000000000000000000000000000000000000
check "all-zero base → pull=true" "$(pull_is true && reason_has 'no known base' && echo 0 || echo 1)"
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
check "unknown base sha → pull=true" "$(pull_is true && echo 0 || echo 1)"
rm src/content/posts/b.md
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD3"
check "fingerprint mismatch (a file gone) → pull=true" "$(pull_is true && reason_has 'fingerprint' && echo 0 || echo 1)"
printf 'b\n' > src/content/posts/b.md
old=$(( $(date +%s) - 9*86400 )); sed -i.bak "s/\"at\":[0-9]*/\"at\":$old/" content-cache/pull-marker.json; rm -f content-cache/pull-marker.json.bak
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD3"
check "9-day-old marker → pull=true" "$(pull_is true && reason_has 'old' && echo 0 || echo 1)"
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD3" MAX_AGE_DAYS=30
check "…unless max-age-days allows it" "$(pull_is false && echo 0 || echo 1)"
rm content-cache/pull-marker.json
run_tier "$TIER" decide EVENT_NAME=push BEFORE_SHA="$HEAD3"
check "no marker → pull=true" "$(pull_is true && reason_has 'no marker' && echo 0 || echo 1)"

echo; echo "# crash guard: an abort resolves to pull=true, exit 0, and says so"
sed 's|^MAX_AGE_DAYS="${MAX_AGE_DAYS:-8}"|MAX_AGE_DAYS="${DELIBERATELY_UNBOUND_XYZ}"|' "$TIER" > "$WORK/tier-unbound.sh"
grep -q DELIBERATELY_UNBOUND_XYZ "$WORK/tier-unbound.sh"; check "fault injection applied" $?
run_tier "$WORK/tier-unbound.sh" decide EVENT_NAME=push BEFORE_SHA="$HEAD3"
check "abort exits 0 with pull=true" "$([ "$RC" -eq 0 ] && pull_is true && echo 0 || echo 1)"
check "…and the reason names the fault" "$(reason_has 'faulted' && grep -q 'FAULT' "$STDERR" && echo 0 || echo 1)"

echo; if [ "$fails" -eq 0 ]; then echo "pull-tier selftest: all green"; exit 0; fi
echo "pull-tier selftest: $fails regression(s)"; exit 1
