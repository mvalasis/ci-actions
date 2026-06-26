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

set +e
pa11y-ci --config /tmp/pa11y-ci.json
rc=$?
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
