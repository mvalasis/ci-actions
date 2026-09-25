#!/usr/bin/env bash
# pull-tier: does this deploy run need to re-pull the CMS content?
#
# `decide` writes pull=true|false (+ reason) to $GITHUB_OUTPUT. `record` writes the
# marker after a successful pull. Every unknown, every fault, resolves to PULL —
# a needless pull costs minutes; a skipped one ships stale content.
#
# Why: on the fleet's Astro sites a CODE push re-pulled the whole catalogue (44–136 s
# measured 2026-09-21) although content changes arrive by repository_dispatch,
# incrementally, and actions/cache had already restored the last pulled state. The
# cache is trusted only on its own evidence: the marker `record` left, young enough,
# whose fingerprint still matches the files on disk.
set -uo pipefail

# ---- crash guard — armed before EVERY other statement ------------------------
# A fault here must become "pull", loudly, never a silent skip: the handler reads
# only environment values with defaults (a script variable may be unassigned at the
# abort) and writes the fail-safe output itself. `trap … EXIT`, not ERR — `set -u`
# aborts without firing ERR (ci-actions README, "A tool fault is never a finding").
_finished=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
_on_exit() {
  local rc=$?
  [ -n "$_finished" ] && return 0
  echo "::warning title=pull-tier FAULT::tier.sh aborted (rc=$rc, mode=${MODE:-?}) — resolving to pull=true (fail-safe); fix the action" >&2
  # lint-allow-stdio-path: the same local-run fallback as $out below, and swallowed if it fails
  { printf 'pull=true\nreason=pull-tier faulted (rc=%s) — fail-safe pull\n' "$rc"; } >> "${GITHUB_OUTPUT:-/dev/stdout}" 2>/dev/null || true
  exit 0
}
trap _on_exit EXIT
finish() { _finished=1; exit "$1"; }

MODE="${MODE:-decide}"
PATHS="${PATHS:-}"
COUNT_PATHS="${COUNT_PATHS:-}"
MARKER="${MARKER:-content-cache/pull-marker.json}"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-8}"
FORCE_EVENTS="${FORCE_EVENTS:-repository_dispatch schedule workflow_dispatch}"
EVENT_NAME="${EVENT_NAME:-}"
BEFORE_SHA="${BEFORE_SHA:-}"
PR_BASE_SHA="${PR_BASE_SHA:-}"
HEAD_SHA="${HEAD_SHA:-}"
# The /dev/stdout fallback serves local runs only: Actions always sets GITHUB_OUTPUT. By
# hand, stdout is where the step outputs show; stderr carries the human line. decide()'s
# append is not guarded, but errexit is off and every path exits 0, so where /dev/stdout
# will not open (ENXIO on Linux when stdout is a socket) bash prints its error and the
# run goes on: the decision still reaches stderr, and the exit code is unchanged.
# lint-allow-stdio-path: the outputs' one local copy; a failed open cannot change the exit
out="${GITHUB_OUTPUT:-/dev/stdout}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

decide() {  # decide <pull:true|false> <reason>
  printf 'pull=%s\nreason=%s\n' "$1" "$2" >> "$out"
  printf '%s\n' "pull-tier: pull=$1 — $2" >&2
  printf -- '- pull-tier: **pull=%s** — %s\n' "$1" "$2" >> "$summary" 2>/dev/null || true
  finish 0
}

# fingerprint → one line per count-path: "<path> <n>"; a dir counts files, a file its bytes,
# an absent path 0. Order = input order, so two fingerprints compare as strings.
fingerprint() {
  local p n
  printf '%s\n' "$COUNT_PATHS" | while IFS= read -r p; do
    p=${p## }; p=${p%% }
    [ -n "$p" ] || continue
    if [ -d "$p" ]; then n=$(find "$p" -type f 2>/dev/null | wc -l | tr -d ' ')
    elif [ -f "$p" ]; then n=$(wc -c < "$p" | tr -d ' ')
    else n=0; fi
    printf '%s %s\n' "$p" "$n"
  done
}

# GitHub `paths:` glob → bash case pattern: `**` matches across `/` (a bare `*` in
# `case` already does), so the translation is `**`→`*`. `**/x` → `*/x` does NOT match a
# top-level `x` — that errs toward "not matched", i.e. toward the fail-safe when this
# is used to skip; here a miss means NOT forcing a pull, so callers list top-level
# files explicitly (the fleet's lists do).
matches_any() {  # matches_any <file> ; reads $PATHS
  local f="$1" g pat
  printf '%s\n' "$PATHS" | while IFS= read -r g; do
    g=${g## }; g=${g%% }
    [ -n "$g" ] || continue
    pat=${g//\*\*/\*}
    # shellcheck disable=SC2254  # the pattern is meant to glob
    case "$f" in $pat) echo hit; return 0 ;; esac
  done | grep -q hit
}

case "$MODE" in
  record)
    mkdir -p "$(dirname "$MARKER")" 2>/dev/null || true
    {
      printf '{"at":%s,"sha":"%s","fingerprint":[' "$(date +%s)" "$HEAD_SHA"
      first=1
      fingerprint | while IFS= read -r line; do
        [ "$first" = 1 ] && first=0 || printf ','
        printf '"%s"' "$line"
      done
      printf ']}\n'
    } > "$MARKER"
    printf '%s\n' "pull-tier: marker recorded at $MARKER ($(fingerprint | tr '\n' ';'))" >&2
    finish 0 ;;
  decide) ;;
  *) echo "::warning title=pull-tier::unknown mode '$MODE' — resolving to pull" >&2; decide true "unknown mode '$MODE'" ;;
esac

# 1. Content events always pull.
for ev in $FORCE_EVENTS; do
  [ "$EVENT_NAME" = "$ev" ] && decide true "event '$EVENT_NAME' is a content event"
done

# 2. A push/PR that touched a pull input pulls. Unknown base → pull.
base=""
case "$EVENT_NAME" in
  pull_request) base="$PR_BASE_SHA" ;;
  push)         base="$BEFORE_SHA" ;;
esac
case "$base" in ""|0000000000000000000000000000000000000000) decide true "no known base for '$EVENT_NAME' (first push / new branch)" ;; esac
git cat-file -e "$base^{commit}" 2>/dev/null || decide true "base $base is not in this checkout (shallow clone?)"
changed=$(git diff --name-only "$base" "$HEAD_SHA" 2>/dev/null) || decide true "git diff $base..$HEAD_SHA failed"
if [ -n "$PATHS" ] && [ -n "$changed" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if matches_any "$f"; then decide true "'$f' is a pull input (changed in $base..$HEAD_SHA)"; fi
  done <<< "$changed"
fi

# 3. The cache must vouch for itself: marker present, young, fingerprint intact.
[ -f "$MARKER" ] || decide true "no marker at $MARKER (cold cache, evicted, or first run)"
at=$(sed -n 's/.*"at":\([0-9]*\).*/\1/p' "$MARKER" | head -1)
case "$at" in ''|*[!0-9]*) decide true "marker at $MARKER is unreadable" ;; esac
age_days=$(( ( $(date +%s) - at ) / 86400 ))
[ "$age_days" -le "$MAX_AGE_DAYS" ] || decide true "marker is ${age_days}d old (max ${MAX_AGE_DAYS}d)"
want=$(sed -n 's/.*"fingerprint":\[\(.*\)\].*/\1/p' "$MARKER" | head -1 | tr -d '"' | tr ',' '\n')
have=$(fingerprint)
[ "$want" = "$have" ] || decide true "on-disk fingerprint differs from the marker's ($(printf '%s' "$have" | tr '\n' ';') vs $(printf '%s' "$want" | tr '\n' ';'))"
decide false "cached content is ${age_days}d old and intact ($(printf '%s' "$have" | tr '\n' ';')); no pull input changed"
