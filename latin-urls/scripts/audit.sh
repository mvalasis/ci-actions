#!/usr/bin/env bash
# latin-urls: ASCII page-URL gate for Astro sites.
#
# Shareable PAGE URLs must be ASCII: a non-ASCII path percent-encodes, which breaks
# WhatsApp/SMS/email link previews, and a product slug outside [a-zA-Z0-9._-] 404s
# in prod. These three audits ran in the fleet's pre-push hook (~/.claude
# hooks/guard-git-push.sh, astro archetype) on a LOCAL `bun run build`; this action
# is the same verdict taken where the build already happens — the deploy job, after
# `astro build`, before wrangler. Nothing non-ASCII can reach Cloudflare Pages
# through a job that carries this step.
#
# Exit 0 = clean · 1 = a finding (block the deploy) · 2 = the gate FAULTED, no verdict.
set -uo pipefail

# ---- crash guard — armed before EVERY other statement ------------------------
# A fault in this script is a fault in the GATE, not a finding about the site, and
# it must not read as either "clean" or "non-ASCII URLs". `trap … EXIT`, not ERR:
# `set -u` aborts WITHOUT firing ERR, and with errexit off ERR fires on the
# deliberate no-match greps below. Every value the handler needs is read from the
# ENVIRONMENT with a default — a script variable may not be assigned yet when the
# abort happens above its assignment (ci-actions README, "A tool fault is never a
# finding about the caller's site").
_finished=""
# shellcheck disable=SC2329  # invoked by the EXIT trap below
_on_exit() {
  local rc=$?
  [ -n "$_finished" ] && return 0
  echo "::error title=latin-urls FAULT (no verdict)::audit.sh aborted with rc=$rc before it could grade anything. This is a fault in the gate, not a finding about the site — the deploy is still refused (exit 2) because an ungraded dist must not ship." >&2
  # The same local-run fallback as $summary below, read from the env because an abort
  # can come before that line. The ::error line above carries the fault either way.
  # lint-allow-stdio-path: the crash note's local copy, and a failed append is swallowed
  { printf '## latin-urls: crashed (no verdict)\n\nThe audit aborted with rc=%s before grading anything. Exit 2 — fix the action, do not treat this as clean.\n' "$rc"; } >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}" 2>/dev/null || true
  exit 2
}
trap _on_exit EXIT
finish() { _finished=1; exit "$1"; }

# ---- config (env, with defaults; the action.yml maps its inputs here) --------
DIST="${DIST:-dist}"
PAGES_DIR="${PAGES_DIR:-src/pages}"
PRODUCTS_DIR="${PRODUCTS_DIR:-src/content/products}"
GREEK_URLS_OK="${GREEK_URLS_OK:-false}"
UPLOADS_EXCLUDE="${UPLOADS_EXCLUDE:-/wp-content/uploads/}"
# The /dev/stdout fallback serves local runs only: Actions always sets
# GITHUB_STEP_SUMMARY. The notes are then a local run's only copy of the per-audit ✓
# lines and the verdict, and note() swallows a failed append, so where /dev/stdout
# will not open (ENXIO on Linux when stdout is a socket) only the notes are lost —
# the findings' stderr mirror and the exit code are not. Kept on purpose (README,
# v1.19.3).
# lint-allow-stdio-path: the notes' one local copy, and a failed append is swallowed
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
note() { printf '%s\n' "$*" >> "$summary" 2>/dev/null || true; }

# REGRESSION ANCHOR (the fleet hook's 2026-07-31 lesson): the set MUST stay
# `[^]a-zA-Z0-9._/[-]` — literal `]` FIRST, literal `-` LAST, no backslashes. POSIX
# makes backslash LITERAL inside a bracket expression, so `[^a-zA-Z0-9._/\[\]-]`
# closes at the `]` of `\]` and the gate becomes a permanent no-op on every grep
# (BSD, GNU, busybox alike). `[` and `]` stay ALLOWED on purpose: Astro dynamic
# routes are literal `[slug]` / `[...path]` directories. selftest.sh pins both.
NON_ASCII='[^]a-zA-Z0-9._/[-]'

findings=0
report() {  # report <title> <lines>
  local title="$1" lines="$2" n
  n=$(printf '%s\n' "$lines" | grep -c . || true)
  findings=$((findings + n))
  echo "::error title=latin-urls::$title ($n)" >&2
  printf '%s\n' "$lines" | sed 's/^/  /' >&2
  note "### ✗ $title ($n)"
  note ""
  # shellcheck disable=SC2016  # the backticks are Markdown, not a command substitution
  printf '%s\n' "$lines" | sed 's/^/- `/; s/$/`/' >> "$summary" 2>/dev/null || true
  note ""
}

note "## latin-urls"
note ""

if [ "$GREEK_URLS_OK" = "true" ]; then
  note "- src/pages + dist/ audits: **exempt** (greek-urls-ok=true — intentional Greek slugs)"
else
  if [ -d "$PAGES_DIR" ]; then
    bad=$(find "$PAGES_DIR" -type d | LC_ALL=C grep -E "$NON_ASCII" | head -20 || true)
    if [ -n "$bad" ]; then
      report "$PAGES_DIR has non-ASCII directories — page URLs must be Latin-only" "$bad"
    else
      note "- \`$PAGES_DIR\`: ✓ every directory name is ASCII"
    fi
  else
    note "- \`$PAGES_DIR\`: (absent — nothing to audit)"
  fi

  if [ ! -d "$DIST" ]; then
    echo "::error title=latin-urls FAULT (no verdict)::'$DIST' does not exist — this action must run AFTER the build step, and the build must write there. Refusing to grade nothing." >&2
    note "- \`$DIST\`: **missing** — run this action after the build step (exit 2, no verdict)"
    finish 2
  fi
  bad=$(find "$DIST" -type f | grep -v -F -- "$UPLOADS_EXCLUDE" | LC_ALL=C grep -E "$NON_ASCII" | head -20 || true)
  if [ -n "$bad" ]; then
    report "$DIST/ has non-ASCII page paths — they would percent-encode in shared URLs" "$bad"
  else
    note "- \`$DIST/\`: ✓ every page path is ASCII (\`$UPLOADS_EXCLUDE\` exempt — downloads, not page URLs)"
  fi
fi

if [ -d "$PRODUCTS_DIR" ]; then
  bad=$(find "$PRODUCTS_DIR" -mindepth 1 -maxdepth 1 -exec basename {} \; 2>/dev/null \
        | LC_ALL=C grep -E '%|[^a-zA-Z0-9._-]' | head -20 || true)
  if [ -n "$bad" ]; then
    report "$PRODUCTS_DIR has non-ASCII or %-encoded slugs — they would 404 in prod (re-run the pull with the current slugify)" "$bad"
  else
    note "- \`$PRODUCTS_DIR\`: ✓ every product slug is [a-zA-Z0-9._-]"
  fi
else
  note "- \`$PRODUCTS_DIR\`: (absent — content site, no product audit)"
fi

if [ "$findings" -gt 0 ]; then
  note ""
  note "**$findings finding(s) — the deploy is refused.** Fix the slug/route (or, for a deliberately Greek site, set \`greek-urls-ok: 'true'\`)."
  finish 1
fi
note ""
note "**clean** — no non-ASCII page URLs."
echo "latin-urls: clean ✓" >&2
finish 0
