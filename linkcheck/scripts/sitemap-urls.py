#!/usr/bin/env python3
"""Expand a sitemap (index or urlset) into a flat list of page URLs.

Usage:
    sitemap-urls.py <sitemap-url> [<sitemap-url> ...]

Prints one page URL per line (deduped, sorted). Recurses into a
<sitemapindex> to reach every child <urlset>, so a single Rank Math
`sitemap_index.xml` expands to every public post-type URL. Handles
gzipped sitemaps. Sends the X-Verify-Source header (CF Bot-Fight-Mode
bypass) when VERIFY_HOMEPAGE_TOKEN is set, plus a real-browser UA so the
fetch isn't challenged on cloud-runner IPs.
"""
import gzip
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
TOKEN = os.environ.get("VERIFY_HOMEPAGE_TOKEN", "")
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def fetch(url):
    # Shell out to curl rather than urllib: the WP edge can enforce a hardened
    # TLS floor that macOS's bundled LibreSSL-Python fails to negotiate; curl
    # handles modern TLS everywhere (local + CI runner).
    cmd = ["curl", "-sSL", "--compressed", "--max-time", "30", "-A", UA]
    if TOKEN:
        cmd += ["-H", f"X-Verify-Source: {TOKEN}"]
    cmd.append(url)
    data = subprocess.run(cmd, capture_output=True, check=True).stdout
    if url.endswith(".gz") or data[:2] == b"\x1f\x8b":
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
    pages, seen = set(), set()
    for arg in sys.argv[1:]:
        collect(arg, seen, pages)
    for url in sorted(pages):
        print(url)


if __name__ == "__main__":
    main()
