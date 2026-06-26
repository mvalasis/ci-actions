#!/usr/bin/env bash
# seo-aeo: technical SEO + AEO checks over live URLs (JS-disabled / raw curl).
# title + h1 are crawlability-critical; meta-desc / canonical / JSON-LD / llms.txt are WARN.
# VERIFY_TOKEN (optional) → X-Verify-Source header, to clear a WAF/CF bot-challenge.
set -uo pipefail

FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-false}"
MAX_URLS="${MAX_URLS:-15}"

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
note() { printf '%s\n' "$*" >>"$summary"; }

hdr=()
[ -n "${VERIFY_TOKEN:-}" ] && hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")

urls=""
if [ -n "${SITEMAP_URL:-}" ]; then
  urls=$(curl -fsS --max-time 30 "${hdr[@]}" "$SITEMAP_URL" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed 's#</\?loc>##g')
fi
if [ -n "${URLS:-}" ]; then
  urls=$(printf '%s\n%s\n' "$urls" "$URLS")
fi
urls=$(printf '%s\n' "$urls" | tr ' ' '\n' | sed '/^$/d' | sort -u | head -n "$MAX_URLS")

note "## 🔎 seo-aeo (JS-disabled / crawler view)"
if [ -z "$urls" ]; then note "- no URLs — skipped"; exit 0; fi

crit=0
warn=0
while IFS= read -r url; do
  [ -z "$url" ] && continue
  html=$(curl -fsSL --max-time 25 "${hdr[@]}" "$url" 2>/dev/null || true)
  if [ -z "$html" ]; then note "- ⚠️ $url — fetch failed"; warn=$((warn + 1)); continue; fi
  title=$(printf '%s' "$html" | grep -ioE '<title[^>]*>[^<]+</title>' | head -1)
  desc=$(printf '%s' "$html"  | grep -ioE '<meta[^>]+name=["'\'']?description["'\'']?[^>]*>' | head -1)
  canon=$(printf '%s' "$html" | grep -ioE '<link[^>]+rel=["'\'']?canonical["'\'']?[^>]*>' | head -1)
  h1=$(printf '%s' "$html"    | grep -ioE '<h1[ >]' | head -1)
  jsonld=$(printf '%s' "$html"| grep -ioE 'application/ld\+json' | head -1)
  issues=""
  [ -z "$title" ]  && { issues="$issues title✗";     crit=$((crit + 1)); }
  [ -z "$h1" ]     && { issues="$issues h1✗";        crit=$((crit + 1)); }
  [ -z "$desc" ]   && { issues="$issues meta-desc⚠"; warn=$((warn + 1)); }
  [ -z "$canon" ]  && { issues="$issues canonical⚠"; warn=$((warn + 1)); }
  [ -z "$jsonld" ] && { issues="$issues json-ld⚠";   warn=$((warn + 1)); }
  if [ -z "$issues" ]; then note "- ✅ $url"; else note "- $url —$issues"; fi
done <<EOF
$urls
EOF

# AEO: llms.txt at the host root (first URL's origin).
host=$(printf '%s\n' "$urls" | head -1 | sed -E 's#(https?://[^/]+).*#\1#')
if [ -n "$host" ]; then
  if curl -fsS --max-time 15 "${hdr[@]}" "$host/llms.txt" >/dev/null 2>&1; then
    note "- ✅ llms.txt present"
  else
    note "- ⚠️ llms.txt missing ($host/llms.txt) — AEO artifact"
    warn=$((warn + 1))
  fi
fi

note ""
note "**critical: $crit · warnings: $warn**"
if [ "$crit" -gt 0 ] && [ "$FAIL_ON_CRITICAL" = "true" ]; then
  note "BLOCKED — missing title/h1 on $crit page(s)."
  exit 1
fi
exit 0
