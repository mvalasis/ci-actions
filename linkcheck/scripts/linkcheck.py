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
  * ANY response with a WAF fingerprint   -> REVIEW (status untrusted: a block
                                                    or challenge, not a verdict)
  OK = 2xx/3xx, or an "alive but blocking" code (401/403/429/503/999).

REVIEW URLs (WAF-fronted, status unknowable from a datacenter IP) are written
to linkcheck-review.txt and are NON-fatal — an out-of-band browser verifier on
a residential IP gives the real verdict.

Excludes (never checked): WP internals (xmlrpc/wp-admin/wp-login/wp-json),
the Cloudflare /cdn-cgi/ email-obfuscation shim, Woo action URLs
(add-to-cart / cart / checkout / logout), and bot-hostile social domains
that 403/429/999 crawlers.
"""
import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile
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
    # Cloudflare email-obfuscation shim injected into scraped HTML, not a real
    # content link — 404s on CF-proxied zones when Scrape Shield is off.
    r"/cdn-cgi/",
    r"add-to-cart=", r"/cart/?(\?|$)", r"/checkout/?(\?|$)", r"\blogout\b",
    # Bot-hostile social domains — they 403/429/999 crawlers; never fatal
    # anyway (they're outbound), so skip them to keep the report quiet.
    r"^https?://([a-z0-9-]+\.)*(linkedin|facebook|fb|instagram|twitter|x|youtube|youtu|tiktok|pinterest)\.(com|be)\b",
]), re.I)
A_RE = re.compile(r'<a\b[^>]*\bhref="([^"]+)"', re.I)
IMG_RE = re.compile(r'<img\b[^>]*\bsrc="([^"]+)"', re.I)
SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
ACCEPT = {401, 403, 429, 503, 999}  # non-2xx/3xx but the host is alive

# Response-header fingerprint of an anti-bot WAF / CDN edge that served a
# bot-block or JS-challenge instead of the origin's real answer. When present,
# the HTTP status is UNTRUSTWORTHY from CI — a 404 may be a block, a 202/200 a
# challenge masking a dead page — identically for LIVE and DEAD URLs. Such URLs
# are routed to REVIEW (verified out-of-band by a real browser on a residential
# IP), never silently failed or passed. BEHAVIOURAL, not a domain allowlist:
# any WAF-fronted host trips it. Verified 2026-06-22 from a datacenter IP —
# eur-lex.europa.eu (AWS WAF behind CloudFront) returns x-amzn-waf-action +
# `X-Cache: Error from cloudfront`.
WAF_BLOCK_RE = re.compile(
    r"^x-amzn-waf-action:"                       # AWS WAF (challenge/captcha/block)
    r"|^cf-mitigated:|^cf-chl-bypass:"           # Cloudflare challenge
    r"|^x-cache:\s*error from cloudfront",       # CloudFront edge error (WAF/block)
    re.I | re.M,
)


def is_internal(url):
    h = (urlsplit(url).hostname or "").lower()
    return h == INTERNAL or h.endswith("." + INTERNAL)


# Manual redirect following with PER-HOP token re-scoping. `curl -L` re-sends a
# custom -H header to a cross-host redirect target — it strips only Cookie and
# Authorization on a cross-origin hop, never an arbitrary X-* header (verified:
# curl 8.7.1 forwarded X-Verify-Source across a localhost->127.0.0.1 301 while
# dropping Cookie/Authorization). So following with -L would carry the WAF token
# off our origin to whatever an internal page redirects to. Instead we follow
# hop-by-hop and attach the token only when the CURRENT hop is internal — it
# never leaves our host, exactly as the seo-aeo gate scopes it.
MAX_HOPS = 10


def _token_args(url):
    """['-H', 'X-Verify-Source: …'] only when url is on our host, else []."""
    return ["-H", f"X-Verify-Source: {TOKEN}"] if (TOKEN and is_internal(url)) else []


def _hop(url, method, body_path=None):
    """One curl request, redirects NOT followed. Token attached iff `url` is
    internal. `method` is [] (GET) or ["-I"] (HEAD). When `body_path` is set the
    response body is written there (each hop overwrites it, so after the chain it
    holds the FINAL page). Returns (http_code:int, next_url:str, header_text:str);
    http_code 0 = no response. `next_url` is curl's resolved absolute redirect
    target (handles relative Location), empty on a non-redirect."""
    out = "/dev/null" if body_path is None else body_path
    cmd = ["curl", "-sS", "-A", UA, "--max-time", "25", "-o", out, "-D", "-",
           "-w", "\n__LC__%{http_code} %{redirect_url}"]
    if body_path is not None:
        cmd.append("--compressed")   # decode Content-Encoding for the body we keep (fetch_html)
    cmd += _token_args(url) + method + [url]
    out_s = subprocess.run(cmd, capture_output=True).stdout.decode("utf-8", "ignore")
    m = re.search(r"__LC__(\d{3}) (\S*)\s*$", out_s)
    return (int(m.group(1)) if m else 0), (m.group(2) if (m and m.group(2)) else ""), out_s


def _follow(start_url, method, body_path=None):
    """Follow redirects manually, re-scoping the token at each hop. Returns
    (final_http_code, concatenated header text of every hop) — the all-hops
    concat preserves the prior `-L -D -` behaviour the WAF fingerprint keys on.
    Exhausting MAX_HOPS while still on a 3xx (a redirect loop) returns code 0, so
    a loop is treated as no-final-answer exactly like the old `-L --max-redirs`."""
    url, hdrs = start_url, []
    for _ in range(MAX_HOPS):
        code, nxt, out_s = _hop(url, method, body_path)
        hdrs.append(out_s)
        if 300 <= code < 400 and nxt:
            url = nxt
            continue
        return code, "\n".join(hdrs)
    return 0, "\n".join(hdrs)


def fetch_html(url):
    with tempfile.NamedTemporaryFile(suffix=".html") as tf:
        code, _ = _follow(url, [], body_path=tf.name)
        if not code:                       # transport failure, no HTTP response
            return ""
        tf.seek(0)
        return tf.read().decode("utf-8", "ignore")


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
    """(code, blocked) for url. code = final HTTP status after the redirect chain
    (0 = no response); blocked = the response carried an anti-bot WAF fingerprint,
    so the status is untrusted. HEAD first, GET fallback for HEAD-hostile codes.
    Redirects are followed manually (_follow), so the token never rides a cross-
    host hop, and `hdrs` accumulates EVERY hop's headers — the WAF fingerprint
    still fires on a block emitted at any hop, as the old `-L -D -` dump did."""
    code, hdrs = _follow(url, ["-I"])
    if code in (0, 403, 405, 500, 501):  # HEAD-hostile (incl. flaky CF 500-on-HEAD) — confirm with GET
        g_code, g_hdrs = _follow(url, [])
        if g_code:
            code, hdrs = g_code, g_hdrs
    if code in (0, 500, 502, 503, 504):  # one re-check for transient 5xx (CF/Kinsta edge)
        r_code, r_hdrs = _follow(url, ["-I"])
        if not r_code:
            r_code, r_hdrs = _follow(url, [])
        if r_code:
            code, hdrs = r_code, r_hdrs
    return code, bool(WAF_BLOCK_RE.search(hdrs))


def verdict(url, code, blocked):
    if url in ALLOW:
        return "ok"
    # A WAF fingerprint means the status is untrustworthy (a block wearing a 404,
    # or a challenge wearing a 2xx) — for our own host too. Route to REVIEW for
    # out-of-band browser verification rather than guess fatal/ok.
    if blocked:
        return "review"
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
        results = dict(zip(targets, ex.map(status, targets)))  # url -> (code, blocked)

    fatal, warn, review = [], [], []
    for url, (code, blocked) in sorted(results.items()):
        v = verdict(url, code, blocked)
        if v == "fatal":
            fatal.append((url, code))
        elif v == "warn":
            warn.append((url, code))
        elif v == "review":
            review.append((url, code))

    def show(title, rows):
        print(f"\n{title} ({len(rows)})")
        for url, code in rows:
            src = next(iter(targets[url]))
            n = len(targets[url])
            where = f"{src}" + (f" (+{n - 1} more)" if n > 1 else "")
            print(f"  [{code or 'conn-fail'}] {url}\n      on: {where}")

    # REVIEW queue: URLs whose CI status can't be trusted (WAF-fronted). Written
    # for the out-of-band browser verifier (residential IP); NON-fatal so the
    # weekly cron stays green on WAF noise alone.
    if review:
        with open("linkcheck-review.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(url for url, _ in review) + "\n")

    print(f"\n=== link check: {len(targets)} checked | "
          f"{len(fatal)} fatal | {len(warn)} warn | {len(review)} review ===")
    if warn:
        show("WARN (external, non-fatal)", warn)
    if review:
        show("REVIEW (WAF status untrusted — verify in a browser)", review)
    if fatal:
        show("FATAL (broken)", fatal)
        print("\nlink check: FAIL")
        sys.exit(1)
    print(f"\nlink check: PASS{f' — {len(review)} queued for browser review' if review else ''}")


if __name__ == "__main__":
    main()
