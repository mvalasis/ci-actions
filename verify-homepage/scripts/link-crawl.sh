#!/usr/bin/env bash
# link-crawl.sh — homepage link crawl (the T1 tier of verify-homepage), now
# the CANONICAL copy. Fetches each URL in $@, extracts every same-origin
# <a href>, HEAD-checks each, fails loud on any non-2xx/3xx.
#
# This is the one canonical copy of the crawl the per-repo
# `scripts/verify-homepage-t1.sh` files duplicate (ci-actions README roadmap).
# It mirrors the inline T1 logic in ~/.claude/skills/verify-homepage/SKILL.md
# so CI runners can execute the same check Claude follows interactively.
# Invoked by action.yml when `checks` includes `links`.
#
# Usage:
#   bash scripts/link-crawl.sh https://www.lampakia.gr/
#   bash scripts/link-crawl.sh https://www.lux-airport.lu/ https://www.lux-airport.lu/fr/ https://www.lux-airport.lu/de/
#
# Exit codes: 0 = all green, 1 = at least one URL or one followed link failed.

set -uo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <homepage-url> [more URLs...]" >&2
  exit 2
fi

# Real-browser UA — Cloudflare's "Bot Fight Mode" / WAF challenges
# arbitrary UAs from cloud runner IP ranges, 403'ing the crawl before
# T1 starts (observed on prevedourou.gr from a GitHub Actions runner).
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

# The CF Bot Fight Mode bypass header (`X-Verify-Source: <secret>`) is matched by
# a Custom WAF Rule on the zone to skip the SBFM/BFM phase so the crawl isn't
# 403'd on cloud-runner IPs (HEADLESS-ASTRO.md §14). It is a SECRET, so it is
# sent ONLY to the target host + its www/apex variants — never carried across a
# cross-host redirect (an open-redirect or a `/go/partner` shortlink would
# otherwise egress it to a third party). The link checks follow redirects
# MANUALLY, re-evaluating the host (and dropping the token) at every hop —
# mirroring the Playwright tier's per-request ALLOWED_HOSTS scoping.

# Per-homepage allowed-host set (set inside the loop): origin host + www/apex.
ORIGIN_HOST=""
APEX=""
token_host_allowed() {  # $1 = host → 0 if the token may be sent to it
  local host="$1"
  [[ -z "${VERIFY_HOMEPAGE_TOKEN:-}" ]] && return 1
  [[ "$host" == "$ORIGIN_HOST" || "$host" == "$APEX" || "$host" == "www.$APEX" ]]
}
host_of() { printf '%s' "$1" | awk -F/ '{print $3}'; }

# Resolve a URL's final HTTP code by following redirects MANUALLY, sending the
# WAF token only while the hop stays on an allowed host. A redirect that leaves
# the allowed set is NOT followed (the token must not egress); the 3xx itself
# counts as reachable (the link works — its off-host target is external and not
# this gate's concern). Caps at 10 hops.
resolve_code() {
  local url="$1" hops=0 out code loc nhost host hdr
  while :; do
    host=$(host_of "$url")
    hdr=()
    token_host_allowed "$host" && hdr=(-H "X-Verify-Source: $VERIFY_HOMEPAGE_TOKEN")
    out=$(curl -s -A "$UA" ${hdr[@]+"${hdr[@]}"} -o /dev/null -w '%{http_code} %{redirect_url}' "$url")
    code=${out%% *}
    loc=${out#* }
    if [[ "$code" -ge 300 && "$code" -lt 400 && -n "$loc" && "$loc" != "$code" ]]; then
      nhost=$(host_of "$loc")
      token_host_allowed "$nhost" || { printf '%s' "$code"; return; }
      url="$loc"
      hops=$((hops + 1))
      [[ $hops -ge 10 ]] && { printf '%s' "$code"; return; }
      continue
    fi
    printf '%s' "$code"
    return
  done
}

overall_fail=0

# One temp pair, reused per URL, cleaned once on exit (a per-loop `trap … EXIT`
# only ever removes the LAST iteration's files — leaks the rest).
TMP_HTML=$(mktemp)
TMP_LINKS=$(mktemp)
trap 'rm -f "$TMP_HTML" "$TMP_LINKS"' EXIT

for HOMEPAGE_URL in "$@"; do
  echo
  echo "── T1: $HOMEPAGE_URL"

  ORIGIN_HOST=$(host_of "$HOMEPAGE_URL")
  APEX=${ORIGIN_HOST#www.}

  # Homepage body fetch keeps -L (the configured origin only ever redirects
  # within its own www/apex; --max-redirs caps a misconfig loop). The token is
  # in CURL_HEADER_ARGS only when set; the homepage host is allowed by construction.
  HOME_HDR=()
  token_host_allowed "$ORIGIN_HOST" && HOME_HDR=(-H "X-Verify-Source: $VERIFY_HOMEPAGE_TOKEN")
  home_code=$(curl -sL --max-redirs 10 -A "$UA" ${HOME_HDR[@]+"${HOME_HDR[@]}"} -o "$TMP_HTML" -w "%{http_code}" "$HOMEPAGE_URL")
  if [[ "$home_code" -lt 200 || "$home_code" -ge 400 ]]; then
    echo "  ✗ homepage itself returned $home_code"
    overall_fail=1
    continue
  fi

  ORIGIN=$(printf '%s' "$HOMEPAGE_URL" | awk -F/ '{print $1"//"$3}')
  python3 - "$TMP_HTML" "$ORIGIN" > "$TMP_LINKS" <<'PY'
import html, re, sys
path, origin = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8", errors="ignore") as f:
    raw = f.read()
# Strip <script> and <style> blocks before extracting links — they often
# contain JS template literals like `href="/x/${slug}/"` that look like
# links to a regex but are runtime-interpolated client-side.
stripped = re.sub(r'<script\b[^>]*>.*?</script>', '', raw, flags=re.I | re.S)
stripped = re.sub(r'<style\b[^>]*>.*?</style>',  '', stripped, flags=re.I | re.S)
links = set()
for m in re.finditer(r'<a\b[^>]*\bhref="([^"#]+)"', stripped, flags=re.I):
    href = html.unescape(m.group(1))
    if href.startswith(("javascript:", "mailto:", "tel:")):
        continue
    if "add-to-cart=" in href or "remove_item=" in href or "logout" in href:
        continue
    # Skip any link with an unresolved JS template literal — defence in depth
    # even after the <script> strip above.
    if "${" in href:
        continue
    if href.startswith("//"):
        href = "https:" + href
    if href.startswith("/"):
        href = origin + href
    if not href.startswith(origin):
        continue
    links.add(href.split("#")[0])
for u in sorted(links):
    print(u)
PY

  TOTAL=$(wc -l < "$TMP_LINKS" | tr -d ' ')
  echo "  crawling $TOTAL unique same-origin links"

  fail=0
  while IFS= read -r link; do
    [[ -z "$link" ]] && continue
    code=$(resolve_code "$link")
    if [[ "$code" -lt 200 || "$code" -ge 400 ]]; then
      printf "    ✗ %s  %s\n" "$code" "$link"
      fail=$((fail + 1))
    fi
  done < "$TMP_LINKS"

  if [[ $fail -eq 0 ]]; then
    echo "  ✓ all $TOTAL links 2xx/3xx"
  else
    echo "  ✗ $fail broken (out of $TOTAL)"
    overall_fail=1
  fi
done

echo
if [[ $overall_fail -eq 0 ]]; then
  echo "verify-homepage T1: PASS"
  exit 0
else
  echo "verify-homepage T1: FAIL"
  exit 1
fi
