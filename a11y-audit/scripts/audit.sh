#!/usr/bin/env bash
# a11y-audit: WCAG audit of live URLs via pa11y-ci (axe + HTML_CodeSniffer).
# Report-mode by default; FAIL_ON_VIOLATIONS=true makes it BLOCK.
# VERIFY_TOKEN (optional) → X-Verify-Source header, to clear a WAF/CF bot-challenge.
set -uo pipefail

STANDARD="${STANDARD:-WCAG2AA}"
RUNNER="${RUNNER:-axe htmlcs}"
FAIL_ON_VIOLATIONS="${FAIL_ON_VIOLATIONS:-false}"
MAX_URLS="${MAX_URLS:-25}"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
note() { printf '%s\n' "$*" >>"$summary"; }

# Header for sitemap fetch (pa11y gets it via the config below).
hdr=()
[ -n "${VERIFY_TOKEN:-}" ] && hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")

# Build the URL list (sitemap expansion + explicit urls).
urls=""
if [ -n "${SITEMAP_URL:-}" ]; then
  urls=$(curl -fsS --max-time 30 "${hdr[@]}" "$SITEMAP_URL" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed 's#</\?loc>##g')
fi
if [ -n "${URLS:-}" ]; then
  urls=$(printf '%s\n%s\n' "$urls" "$URLS")
fi
urls=$(printf '%s\n' "$urls" | tr ' ' '\n' | sed '/^$/d' | sort -u | head -n "$MAX_URLS")

note "## ♿ a11y-audit"
if [ -z "$urls" ]; then note "- no URLs to audit — skipped"; exit 0; fi
count=$(printf '%s\n' "$urls" | wc -l | tr -d ' ')
note "- standard: \`$STANDARD\` · runners: \`$RUNNER\` · URLs: $count"

# Generate the pa11y-ci config (JSON).
runners_json=$(printf '"%s",' $RUNNER | sed 's/,$//')
urls_json=$(printf '%s\n' "$urls" | sed 's#.*#"&"#' | paste -sd, -)
# headers: a dummy `_lscache_vary` cookie makes LiteSpeed "Guest Mode" SKIP its
# first-visit JS reload — the client only reloads when that cookie is absent, and
# on a cookie-less CI runner the reload navigates mid-audit and throws "Execution
# context was destroyed", failing the gate on a compliant page (wait alone loses
# the race; the cookie removes the reload deterministically). Harmless without
# Guest Mode. X-Verify-Source is added when a token is set (WAF/CF bypass).
hdr_pairs='"Cookie": "_lscache_vary=1"'
[ -n "${VERIFY_TOKEN:-}" ] && hdr_pairs="$hdr_pairs, \"X-Verify-Source\": \"$VERIFY_TOKEN\""
headers_json="\"headers\": { $hdr_pairs }, "
# levelCapWhenNeedsReview: cap axe "incomplete" (needsFurtherReview) findings
# to a warning. axe emits these when it CAN'T determine pass/fail automatically
# (e.g. text over a position:fixed overlay, gradients, bg images) — they are
# judgment items, not confirmed violations, so a hard gate must not BLOCK on
# them (DISCIPLINES.md: mechanical → gate, judgment → advisory). Confirmed
# axe violations + htmlcs errors still report as errors and block.
# wait: a short settle so any post-load entrance animation finishes first.
cat > /tmp/pa11y-ci.json <<EOF
{ "defaults": { ${headers_json}"standard": "$STANDARD", "runners": [$runners_json], "timeout": 60000,
    "wait": 3000,
    "levelCapWhenNeedsReview": "warning",
    "chromeLaunchConfig": { "args": ["--no-sandbox", "--disable-dev-shm-usage"] } },
  "urls": [ $urls_json ] }
EOF

# Run pa11y-ci, capturing the log so we can tell a flaky *run* error apart from a
# URL that ran and reported violations. pa11y-ci prints one structured summary
# line per URL: "> <url> - Failed to run" for a run error, "> <url> - N errors"
# for a real violation. We key off those reporter lines (not free text) so the
# audited page's own HTML — which is echoed in the error detail and could contain
# strings like "Failed to run" — can never spoof the decision.
# NO_COLOR + ANSI strip: pa11y-ci's reporter (kleur) emits colour when a CI sets
# FORCE_COLOR even on a non-TTY pipe; the ">"-anchored greps below would then
# match nothing and silently disable the retry. Force plain output and strip any
# stray escapes so summary-line detection is deterministic across colour envs.
# Capture pa11y-ci's real exit via PIPESTATUS[0] (the pipe ends in sed|tee).
run_audit() { NO_COLOR=1 pa11y-ci --config /tmp/pa11y-ci.json 2>&1 | sed $'s/\x1b\\[[0-9;]*m//g' | tee /tmp/pa11y-out.txt; return "${PIPESTATUS[0]}"; }

# A genuine WCAG violation is always a "> <url> - N errors" line; a transient
# failure is a "> <url> - Failed to run" line. Anchor to the reporter's per-URL
# summary shape (leading ">") so error-detail lines (which start with " • " or
# whitespace, never ">") can't match even when the page HTML echoes these words.
ran_errline='^[[:space:]]*>[[:space:]].*-[[:space:]]Failed to run[[:space:]]*$'
viol_errline='^[[:space:]]*>[[:space:]].*-[[:space:]][0-9]+[[:space:]]error'

set +e
run_audit
rc=$?
# Retry ONCE only when the failure was purely a flaky run error AND no URL
# reported real violations. The "no violations" guard is the safety invariant:
# if any "- N errors" line is present, we never retry, so a passing re-run can
# never clear a real WCAG failure (which would be worse than the flake itself).
# A persistent run error (both attempts fail) still falls through non-zero, so
# enforce mode blocks.
if [ "$rc" -ne 0 ] \
   && grep -qE "$ran_errline" /tmp/pa11y-out.txt \
   && ! grep -qE "$viol_errline" /tmp/pa11y-out.txt; then
  note "- ⚠️ transient run error only (no WCAG violations) — retrying once"
  run_audit
  rc=$?
fi
set -e

if [ "$rc" -eq 0 ]; then
  note "- ✅ no WCAG $STANDARD errors"
  exit 0
fi
if [ "$FAIL_ON_VIOLATIONS" = "true" ]; then
  note "- ❌ WCAG errors found (see log) — BLOCKING"
  exit 1
fi
note "- ⚠️ WCAG errors found (see log) — report-only; set \`fail-on-violations: true\` to block once clean"
exit 0
