#!/usr/bin/env python3
"""Expand a sitemap (index or urlset) into a flat list of page URLs.

Usage:
    sitemap-urls.py <sitemap-url> [<sitemap-url> ...]

Prints one page URL per line (deduped, sorted). Recurses into a
<sitemapindex> to reach every child <urlset>, so a single Rank Math
`sitemap_index.xml` expands to every public post-type URL. Handles
gzipped sitemaps. Sends the X-Verify-Source header (CF Bot-Fight-Mode
bypass) ONLY to the internal host (LINKCHECK_HOST, or the seed sitemap
hosts) and its subdomains, re-scoped per redirect hop — never to a
cross-host child-sitemap <loc> or redirect target. Uses a real-browser
UA so the fetch isn't challenged on cloud-runner IPs.
"""
import gzip
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
TOKEN = os.environ.get("VERIFY_HOMEPAGE_TOKEN", "")
INTERNAL = os.environ.get("LINKCHECK_HOST", "").lower()
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
MAX_HOPS = 8

# Hosts allowed to receive the WAF-bypass token. Seeded in main() from
# LINKCHECK_HOST (when the action passes it) plus every seed sitemap URL's host,
# so a child <loc> on the same site or a subdomain still gets the token while a
# cross-host one never does. The token is a secret (VERIFY_HOMEPAGE_TOKEN); curl
# re-sends a custom -H header across a cross-host redirect (it only strips
# Cookie/Authorization), so we gate by host ourselves and follow hops manually.
ALLOWED = set()


def _seed_allowed(host):
    h = (host or "").lower()
    if h:
        ALLOWED.add(h[4:] if h.startswith("www.") else h)   # collapse www. → apex


def is_allowed(url):
    h = (urlsplit(url).hostname or "").lower()
    return bool(h) and any(h == a or h.endswith("." + a) for a in ALLOWED)


def fetch(url):
    # Shell out to curl rather than urllib: the WP edge can enforce a hardened
    # TLS floor that macOS's bundled LibreSSL-Python fails to negotiate; curl
    # handles modern TLS everywhere (local + CI runner). Redirects are followed
    # MANUALLY (no -L) so the token is re-scoped per hop and never rides a
    # cross-host redirect; %{redirect_url} gives curl's resolved next hop.
    cur, data = url, b""
    for _ in range(MAX_HOPS):
        with tempfile.NamedTemporaryFile() as tf:
            cmd = ["curl", "-sS", "--compressed", "--max-time", "30", "-A", UA,
                   "-o", tf.name, "-w", "%{http_code} %{redirect_url}"]
            if TOKEN and is_allowed(cur):
                cmd += ["-H", f"X-Verify-Source: {TOKEN}"]
            wo = subprocess.run(cmd + [cur], capture_output=True,
                                check=True).stdout.decode("utf-8", "ignore").split()
            data = open(tf.name, "rb").read()
        code = int(wo[0]) if wo and wo[0].isdigit() else 0
        nxt = wo[1] if len(wo) > 1 else ""
        if 300 <= code < 400 and nxt:
            cur = nxt
            continue
        break
    if cur.endswith(".gz") or data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def collect(url, seen_sitemaps, pages):
    if url in seen_sitemaps:
        return
    seen_sitemaps.add(url)
    try:
        root = ET.fromstring(fetch(url))
    except Exception as exc:  # noqa: BLE001 — one bad child shouldn't abort the run
        print(f"WARN: failed to fetch/parse {url}: {exc}", file=sys.stderr)
        return
    tag = root.tag.split("}")[-1]
    if tag == "sitemapindex":
        for loc in root.findall(".//sm:sitemap/sm:loc", NS):
            if loc.text:
                collect(loc.text.strip(), seen_sitemaps, pages)
    else:  # urlset
        for loc in root.findall(".//sm:url/sm:loc", NS):
            if loc.text:
                pages.add(loc.text.strip())


def main():
    if len(sys.argv) < 2:
        print("usage: sitemap-urls.py <sitemap-url> [...]", file=sys.stderr)
        sys.exit(2)
    # Seed the token-allowed host set BEFORE crawling: the configured internal
    # host (if the action passed it) + every seed sitemap host, so same-host /
    # subdomain children get the token regardless of recursion order.
    _seed_allowed(INTERNAL)
    for arg in sys.argv[1:]:
        _seed_allowed(urlsplit(arg).hostname)
    pages, seen = set(), set()
    for arg in sys.argv[1:]:
        collect(arg, seen, pages)
    for url in sorted(pages):
        print(url)


if __name__ == "__main__":
    main()
