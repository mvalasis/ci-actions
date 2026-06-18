#!/usr/bin/env python3
"""Full-site link / image / outbound checker (curl-based, robust).

Reads page URLs (CLI args, or one-per-line on stdin), fetches each with
curl, extracts every <a href> and <img src>, dedupes the targets across
all pages, and checks each unique URL once.

Why curl and not a Rust/Go link checker: lychee 0.24.2 hard-panics on
CF/Kinsta edges when a connection closes without a TLS close_notify
("cannot send response to queue / peer closed connection"). curl tolerates
that — the on-deploy homepage crawls have used it for months without a
single such failure.

Configure via environment:
  LINKCHECK_HOST     the internal host (required) — links to this host and
                     its subdomains are fatal if broken; everything else is
                     treated as outbound.
  LINKCHECK_WORKERS  concurrent curl workers (default 10).
  LINKCHECK_ALLOW    path to a baselined-known-broken URL list (one per
                     line); defaults to linkcheck-allow.txt beside this
                     script. Set it to the caller's own list in CI.
  VERIFY_HOMEPAGE_TOKEN  WAF-bypass token, sent as X-Verify-Source ONLY to
                     the internal host, never to third parties.

Exit status:
  0  no fatal breakage
  1  one or more fatal broken links/images

Policy (tuned so external rot never cries wolf on a weekly cron):
  * INTERNAL link/image not OK            -> FATAL (our own site must work)
  * EXTERNAL link returning 404 or 410    -> FATAL (clearly dead outbound)
  * EXTERNAL anything else not OK         -> WARN  (timeout / 5xx / no-conn)
  OK = 2xx/3xx, or an "alive but blocking" code (401/403/429/503/999).

Excludes (never checked): WP internals (xmlrpc/wp-admin/wp-login/wp-json),
Woo action URLs (add-to-cart / cart / checkout / logout), and bot-hostile
social domains that 403/429/999 crawlers.
"""
import concurrent.futures
import os
import re
import subprocess
import sys
from urllib.parse import urldefrag, urljoin, urlsplit

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
TOKEN = os.environ.get("VERIFY_HOMEPAGE_TOKEN", "")
INTERNAL = os.environ.get("LINKCHECK_HOST", "")
WORKERS = int(os.environ.get("LINKCHECK_WORKERS", "10"))

# Baselined known-broken URLs (one per line) — treated as OK so legacy cruft
# we deliberately left in place doesn't fail the run. Path is overridable via
# LINKCHECK_ALLOW so a shared script can read the *caller's* per-repo list.
ALLOW = set()
_allow = os.environ.get("LINKCHECK_ALLOW") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "linkcheck-allow.txt")
if os.path.exists(_allow):
    with open(_allow, encoding="utf-8") as _f:
        ALLOW = {ln.strip() for ln in _f if ln.strip() and not ln.startswith("#")}

EXCLUDE = re.compile("|".join([
    r"xmlrpc\.php", r"/wp-login\.php", r"/wp-admin", r"/wp-json",
    r"add-to-cart=", r"/cart/?(\?|$)", r"/checkout/?(\?|$)", r"\blogout\b",
    # Bot-hostile social domains — they 403/429/999 crawlers; never fatal
    # anyway (they're outbound), so skip them to keep the report quiet.
    r"^https?://([a-z0-9-]+\.)*(linkedin|facebook|fb|instagram|twitter|x|youtube|youtu|tiktok|pinterest)\.(com|be)\b",
]), re.I)
A_RE = re.compile(r'<a\b[^>]*\bhref="([^"]+)"', re.I)
IMG_RE = re.compile(r'<img\b[^>]*\bsrc="([^"]+)"', re.I)
SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
ACCEPT = {401, 403, 429, 503, 999}  # non-2xx/3xx but the host is alive


def is_internal(url):
    h = (urlsplit(url).hostname or "").lower()
    return h == INTERNAL or h.endswith("." + INTERNAL)


def curl(extra, url):
    cmd = ["curl", "-sS", "-A", UA, "--max-time", "25"]
    if TOKEN and is_internal(url):
        cmd += ["-H", f"X-Verify-Source: {TOKEN}"]
    return subprocess.run(cmd + extra + [url], capture_output=True)


def fetch_html(url):
    r = curl(["-L", "--compressed"], url)
    return r.stdout.decode("utf-8", "ignore") if r.returncode == 0 else ""


def extract(page_url, page_html):
    body = SCRIPT_STYLE.sub("", page_html)
    found = set()
    for rx in (A_RE, IMG_RE):
        for m in rx.finditer(body):
            raw = m.group(1).strip()
            if (not raw or " " in raw
                    or raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#"))
                    or "${" in raw):
                continue
            absu = urldefrag(urljoin(page_url, raw))[0]
            host = (urlsplit(absu).hostname or "").lower()
            if (absu.startswith("http") and "." in host
                    and re.fullmatch(r"[a-z0-9.-]+", host)
                    and not EXCLUDE.search(absu)):
                found.add(absu)
    return found


def status(url):
    """HTTP status code (int) for url, 0 if no response. HEAD, GET fallback."""
    def one(method):
        r = curl(["-o", "/dev/null", "-w", "%{http_code}", "-L"] + method, url)
        try:
            return int(r.stdout.decode().strip()[:3])
        except (ValueError, AttributeError):
            return 0
    code = one(["-I"])
    if code in (0, 403, 405, 501):  # hosts that dislike HEAD — confirm with GET
        g = one([])
        if g:
            code = g
    if code in (0, 502, 503, 504):  # one retry for transient
        r = one(["-I"]) or one([])
        if r:
            code = r
    return code


def verdict(url, code):
    if url in ALLOW:
        return "ok"
    if 200 <= code < 400 or code in ACCEPT:
        return "ok"
    if is_internal(url):
        return "fatal"
    return "fatal" if code in (404, 410) else "warn"


def main():
    if not INTERNAL:
        print("error: set LINKCHECK_HOST=<your-domain> (the internal host)", file=sys.stderr)
        sys.exit(2)
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        pages = sys.argv[1:]
    else:
        pages = [ln.strip() for ln in sys.stdin if ln.strip()]
    print(f"Crawling {len(pages)} pages with {WORKERS} workers...", file=sys.stderr)

    targets = {}  # url -> set(source pages)
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        for page, html in zip(pages, ex.map(fetch_html, pages)):
            for u in extract(page, html):
                targets.setdefault(u, set()).add(page)
    print(f"Checking {len(targets)} unique links/images...", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        codes = dict(zip(targets, ex.map(status, targets)))

    fatal, warn = [], []
    for url, code in sorted(codes.items()):
        v = verdict(url, code)
        if v == "fatal":
            fatal.append((url, code))
        elif v == "warn":
            warn.append((url, code))

    def show(title, rows):
        print(f"\n{title} ({len(rows)})")
        for url, code in rows:
            src = next(iter(targets[url]))
            n = len(targets[url])
            where = f"{src}" + (f" (+{n - 1} more)" if n > 1 else "")
            print(f"  [{code or 'conn-fail'}] {url}\n      on: {where}")

    print(f"\n=== link check: {len(targets)} checked | "
          f"{len(fatal)} fatal | {len(warn)} warn ===")
    if warn:
        show("WARN (external, non-fatal)", warn)
    if fatal:
        show("FATAL (broken)", fatal)
        print("\nlink check: FAIL")
        sys.exit(1)
    print("\nlink check: PASS")


if __name__ == "__main__":
    main()
