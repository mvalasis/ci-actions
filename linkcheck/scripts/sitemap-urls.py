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
cross-host child-sitemap <loc> or redirect target. curl reads the header
from a mode-600 file, never from its argv or env. Uses a real-browser
UA so the fetch isn't challenged on cloud-runner IPs. A body that
declares a DOCTYPE, or runs past the protocol's 50 MB before or after
gunzip, is refused before it is parsed (see parse()).

# lint-allow-no-crash-guard: this is a PIPELINE STAGE, not a gate, and it has no
# report-mode input to consult. Its whole output is the URL list the crawl runs
# on, so a fault here means the page set is UNKNOWN — continuing would hand the
# crawler an empty or partial list and produce a false-clean run over pages that
# were never checked, which is strictly worse than stopping. It is also already
# attributed correctly: action.yml asserts `[ "$N" -gt 0 ]` on this script's
# output and fails with `::error::sitemap expansion produced no URLs (sitemap
# down?)`, naming the real cause. Nothing here is laundered into a verdict about
# the caller's links — and misattribution, not the exit code, is what rule 3
# exists to catch. Contrast linkcheck.py, which IS guarded despite equally having
# no report mode, because its wrapper DID misattribute (it filed a false
# "broken links found" issue on a crawler crash).
"""
import atexit
import gzip
import io
import os
import shutil
import subprocess
import sys
import tempfile
# semgrep's use-defused-xml flags the stdlib import itself; it cannot see parse(),
# which refuses a DTD before ElementTree reads a byte. defusedxml would be this
# repo's first Python dependency, for one handler.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from urllib.parse import urlsplit
from xml.parsers import expat  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
TOKEN = os.environ.get("VERIFY_HOMEPAGE_TOKEN", "")
INTERNAL = os.environ.get("LINKCHECK_HOST", "").lower()
NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
MAX_HOPS = 8
MAX_SITEMAP_BYTES = 52_428_800   # the protocol's own per-file limit (sitemaps.org: 50 MB)

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


# The token on the RUNNER, as in linkcheck.py: curl reads the header from a
# mode-600 file in a private dir removed at exit, never as an argv string (`ps`
# shows argv to every process on the runner), and runs without
# VERIFY_HOMEPAGE_TOKEN in its environment. Made lazily, once; single-threaded.
_HDR_PATH = ""


def _token_header():
    """Path of the mode-600 `X-Verify-Source: <token>` file ('' with no token)."""
    global _HDR_PATH
    if TOKEN and not _HDR_PATH:
        d = tempfile.mkdtemp(prefix="sitemap-urls.")   # 0700
        atexit.register(shutil.rmtree, d, True)
        p = os.path.join(d, "token-header")
        with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(f"X-Verify-Source: {TOKEN}\n")
        _HDR_PATH = p
    return _HDR_PATH


# A hostile or broken sitemap must not be able to exhaust the machine parsing it.
# The body can come from any host a sitemap index or a redirect names, not only
# from the caller's own site.
#
# ENTITY EXPANSION (billion laughs). ElementTree never resolves an EXTERNAL entity,
# but it leaves internal expansion to whatever libexpat Python links, and only
# expat >= 2.4.1 bounds it. macOS's system Python 3.9 links 2.2.8, where 487 bytes
# expanded to 30 MB in half a second (2026-09-25). An entity can be declared only
# inside a DTD, and a sitemap never has one (the protocol is XML-Schema-defined),
# so parse() refuses any DOCTYPE outright. The refusal runs INSIDE expat, over the
# bytes ElementTree then parses, so a UTF-16 body or a BOM cannot hide the
# declaration from it the way they would from a byte search.
#
# SIZE. The body is capped at the protocol's 50 MB twice: as read back from curl,
# and again as gunzip inflates it, so a small .gz cannot inflate past the cap.
class Refused(ValueError):
    """A body this script will not parse: a DOCTYPE, or over MAX_SITEMAP_BYTES."""


def _refuse_doctype(name, *_):
    # StartDoctypeDeclHandler fires as the DOCTYPE opens, before its internal
    # subset (where every entity would be declared) is read.
    raise Refused(f"refused: it declares <!DOCTYPE {name}>, which a sitemap never "
                  "does (an HTML page, or an entity-expansion payload)")


def _capped(data, what):
    if len(data) > MAX_SITEMAP_BYTES:
        raise Refused(f"refused: {what} is over the sitemap protocol's "
                      f"{MAX_SITEMAP_BYTES:,}-byte cap")
    return data


def parse(data):
    """The ElementTree root of a sitemap body, refusing any DOCTYPE first."""
    guard = expat.ParserCreate()
    guard.StartDoctypeDeclHandler = _refuse_doctype
    guard.Parse(data, True)
    return ET.fromstring(data)


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
                cmd += ["-H", "@" + _token_header()]
            env = {k: v for k, v in os.environ.items() if k != "VERIFY_HOMEPAGE_TOKEN"}
            wo = subprocess.run(cmd + [cur], capture_output=True, check=True,
                                env=env).stdout.decode("utf-8", "ignore").split()
            with open(tf.name, "rb") as f:
                data = _capped(f.read(MAX_SITEMAP_BYTES + 1), "the body")
        code = int(wo[0]) if wo and wo[0].isdigit() else 0
        nxt = wo[1] if len(wo) > 1 else ""
        if 300 <= code < 400 and nxt:
            cur = nxt
            continue
        break
    if cur.endswith(".gz") or data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            data = _capped(gz.read(MAX_SITEMAP_BYTES + 1), "the gunzipped body")
    return data


def collect(url, seen_sitemaps, pages):
    if url in seen_sitemaps:
        return
    seen_sitemaps.add(url)
    try:
        root = parse(fetch(url))
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
