#!/usr/bin/env python3
"""Offline self-test for the linkcheck verify-token scoping fix (no network).

Spins up two loopback HTTP servers on DIFFERENT hostnames — `localhost` is the
"internal" host (LINKCHECK_HOST), `127.0.0.1` is an "external" third party — and
drives the REAL linkcheck.py / sitemap-urls.py fetch primitives across cross-host
redirect chains. It asserts the WAF-bypass token (`X-Verify-Source`) is attached
ONLY to internal hops and is NEVER carried to the external host.

This is the regression guard for the cross-origin token leak: `curl -L` re-sends
a custom `-H` header to a cross-host redirect target (it strips only Cookie /
Authorization), so following with `-L` would disclose the secret. The fix follows
redirects manually and re-scopes the token per hop. Mirrors seo-aeo/selftest.mjs.

It also guards where the token may sit on the RUNNER (v1.15.2): an argv-logging
`curl` stands first on PATH for the whole run and records each call's argv, its
environment and the mode of any `-H @file` it is handed.

And that a hostile sitemap cannot exhaust the machine parsing it (v1.16.1): a
DOCTYPE is refused inside expat before ElementTree runs, and the body is capped at
the protocol's 50 MB as read and as gunzipped (hostile_sitemap_checks).

And that a sitemap page's OWN response is a verdict (v1.29.1): one that 404s or
500s fails the run named `on: sitemap` even when nothing links to it, graded as a
link to it would be — one re-check for a transient 5xx, a WAF fingerprint to
REVIEW, an excluded path not at all — and counted once when it is also a link
target (page_outcome_checks).

And that the broken-links issue still gets posted when the report is huge
(v1.29.2): a body over 60,000 bytes keeps the summary and as many whole rows as
fit, FATAL first, and says how many it left out; one under that is posted
byte-identical to before (issue_body_checks).

And that the crawl step's summary is still written when the report is huge
(v1.29.3): over 900,000 bytes it gets the issue body's cut, both being
scripts/fit-report.py's, and the cut keeps the verdict line and a collapsed
crawl's notice; under that it is written byte-identical to before
(step_summary_checks).

Run: `python3 linkcheck/scripts/selftest.py`  (exit 0 = pass, 1 = a leak/regression)
"""
import atexit
import contextlib
import http.server
import importlib.util
import io
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = "SELFTEST-SECRET-TOKEN"

INT_PORT = 0   # the "internal" host (localhost) — token-allowed
EXT_PORT = 0   # the "external" host (127.0.0.1) — must NEVER receive the token

REC = []                       # [{server, method, path, token}]
REC_LOCK = threading.Lock()
FLAPPED = set()                # /sm/flaky* paths that have served their one transient 502


def _first_hit(path):
    with REC_LOCK:
        first = path not in FLAPPED
        FLAPPED.add(path)
        return first


def _record(server, handler):
    with REC_LOCK:
        REC.append({"server": server, "method": handler.command,
                    "path": urlsplit(handler.path).path,
                    "token": handler.headers.get("X-Verify-Source")})


def _make_handler(label):
    class H(http.server.BaseHTTPRequestHandler):
        def _redirect(self, location):
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _ok(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _status(self, code, body, extra=()):
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _gzip(self, body):
            import gzip as _gz
            gz = _gz.compress(body)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(gz)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(gz)

        def _serve(self):
            _record(label, self)
            p = urlsplit(self.path).path
            if p == "/to-external":      # internal page that 3xx-redirects off-host
                self._redirect(f"http://127.0.0.1:{EXT_PORT}/ext-landing")
            elif p == "/gz-html":        # Content-Encoding: gzip — fetch_html must decode it
                self._gzip(b'<html><a href="http://sub.localhost/gz-link">x</a></html>')
            elif p == "/loop":           # self-redirect → exercises the MAX_HOPS cap
                self._redirect(f"http://localhost:{INT_PORT}/loop")
            elif p == "/to-internal":    # external page that 3xx-redirects back on-host
                self._redirect(f"http://localhost:{INT_PORT}/int-landing")
            elif p == "/ext-landing":
                self._ok(b"<html>EXTERNAL-LANDING</html>")
            elif p == "/int-landing":
                self._ok(b"<html>INTERNAL-LANDING</html>")
            elif p == "/sitemap.xml":    # end to end: one page on the internal host
                self._ok(('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/'
                          'schemas/sitemap/0.9"><url><loc>http://localhost:'
                          f'{INT_PORT}/page-a</loc></url></urlset>').encode())
            elif p == "/page-a":         # end to end: one internal and one external link
                self._ok((f'<html><a href="http://a.localhost:{INT_PORT}/int-landing">i</a>'
                          f'<a href="http://127.0.0.1:{EXT_PORT}/ext-landing">e</a></html>').encode())
            elif p.startswith("/bytes-"):    # n bytes as-is — the body cap
                self._ok(b"x" * int(p[len("/bytes-"):]))
            elif p.startswith("/gz-"):       # n bytes, gzipped, no Content-Encoding — the inflate cap
                import gzip as _gz
                self._ok(_gz.compress(b"\0" * int(p[len("/gz-"):])))
            elif p == "/dtd-index.xml":      # end to end: a DOCTYPE child beside a real one
                self._ok(('<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/'
                          f'schemas/sitemap/0.9"><sitemap><loc>http://localhost:{INT_PORT}/'
                          f'dtd-child.xml</loc></sitemap><sitemap><loc>http://localhost:{INT_PORT}'
                          '/sitemap.xml</loc></sitemap></sitemapindex>').encode())
            elif p.startswith("/sm/"):       # sitemap PAGES graded on their own response (v1.29.1)
                # Every body carries the same working nav link, as a theme's 404 or
                # error template does, so only the page's own status can fail it.
                nav = f'<html><a href="http://a.localhost:{INT_PORT}/int-landing">home</a>'
                if p == "/sm/home":
                    self._ok((nav + "</html>").encode())
                elif p == "/sm/links-to-404":   # links to a page the sitemap ALSO lists
                    self._ok((nav + f'<a href="http://a.localhost:{INT_PORT}/sm/linked-404">'
                              'x</a></html>').encode())
                elif p in ("/sm/404", "/sm/linked-404"):
                    self._status(404, (nav + "</html>").encode())
                elif p in ("/sm/500", "/sm/cart/"):   # /cart/ is an EXCLUDE path
                    self._status(500, (nav + "</html>").encode())
                elif p.startswith("/sm/flaky"):  # one transient edge 502 per path, then 200
                    self._status(502 if _first_hit(p) else 200, (nav + "</html>").encode())
                elif p == "/sm/waf":             # a Cloudflare challenge on our own page
                    self._status(403, b"<html>Just a moment...</html>",
                                 [("cf-mitigated", "challenge")])
                else:
                    self._status(404, b"<html>no such fixture</html>")
            elif p == "/dtd-child.xml":      # a HARMLESS entity: only the refusal keeps its URL out
                self._ok(('<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY u "http://localhost:'
                          f'{INT_PORT}/from-a-dtd">]><urlset xmlns="http://www.sitemaps.org/'
                          'schemas/sitemap/0.9"><url><loc>&u;</loc></url></urlset>').encode())
            else:
                self._ok(b"<html>DIRECT</html>")

        do_GET = _serve
        do_HEAD = _serve

        def log_message(self, *a):
            pass
    return H


def _start(label):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(label))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tokens(server):
    return {r["token"] for r in REC if r["server"] == server}


def _page(linkcheck, url):
    """fetch_html()'s (code, blocked, html). Any other shape comes back as
    (None, None, html), so a regression reads as failed checks, not a traceback
    that hides every check after it."""
    r = linkcheck.fetch_html(url)
    if isinstance(r, tuple) and len(r) == 3:
        return r
    return None, None, r if isinstance(r, str) else ""


def _hits(path, method):
    return sum(1 for r in REC if r["path"] == path and r["method"] == method)


SHIM_LOG = ""


def _install_curl_shim():
    """Put an argv-logging `curl` first on PATH, in a dir removed at exit. Each call
    appends ONE line (a single write, so worker threads never interleave): its
    argv, ENV-VAR / ENV-VALUE when the token's variable or value is in its
    environment, and for a `-H @file` the file's mode, its dir's mode and the dir.
    Then it execs the real curl."""
    global SHIM_LOG
    real = shutil.which("curl")
    d = tempfile.mkdtemp(prefix="lc-selftest-shim.")
    atexit.register(shutil.rmtree, d, True)   # on every exit, a crash in a later section too
    SHIM_LOG = os.path.join(d, "curl.log")
    with open(os.path.join(d, "curl"), "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            line="argv"
            for a in "$@"; do line="$line [$a]"; done
            case "$(env)" in *VERIFY_HOMEPAGE_TOKEN=*) line="$line ENV-VAR" ;; esac
            case "$(env)" in *{TOKEN}*) line="$line ENV-VALUE" ;; esac
            prev=""
            for a in "$@"; do
              if [ "$prev" = "-H" ]; then
                case "$a" in
                  @*) f="${{a#@}}"; dir=$(dirname "$f")
                      line="$line HDRFILE $(ls -l "$f" | cut -c1-10) $(ls -ld "$dir" | cut -c1-10) $dir" ;;
                esac
              fi
              prev="$a"
            done
            printf '%s\\n' "$line" >> {shlex.quote(SHIM_LOG)}
            exec {shlex.quote(real)} "$@"
            """))
    os.chmod(os.path.join(d, "curl"), 0o755)
    os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")


def _shim_lines():
    try:
        with open(SHIM_LOG, encoding="utf-8") as f:
            return f.read().splitlines()
    except OSError:
        return []


def runner_checks():
    """Where the token sits on the RUNNER, as distinct from which host receives it.

    Before v1.15.2 both scripts handed curl `-H "X-Verify-Source: <token>"`, so the
    token was in the argv of every internal fetch — thousands per run, each one
    readable by `ps` from any process on the runner and recorded verbatim by any
    argv-logging wrapper on PATH — and every curl inherited VERIFY_HOMEPAGE_TOKEN.
    Both halves are asserted over every curl this run makes, the direct calls
    above included. The end-to-end legs go through main(), which the direct calls
    never reach, and prove the private dir is gone once each script exits."""
    print("the token on the runner — curl's argv, its environment, the header file")
    runs = _shim_lines()
    check("curl ran through the argv-logging stand-in", len(runs) > 0)
    check("the token is never in curl's argv (what ps, or a wrapper on PATH, sees)",
          not any(TOKEN in r for r in runs))
    hdr = [r for r in runs if " HDRFILE " in r]
    check("…internal hops were handed the header as a file (-H @…)", len(hdr) > 0)
    check("…mode 600, inside a 0700 dir",
          bool(hdr) and all(" HDRFILE -rw------- drwx------ " in r for r in hdr))
    check("no curl inherits VERIFY_HOMEPAGE_TOKEN, by name or by value",
          not any(" ENV-VAR" in r or " ENV-VALUE" in r for r in runs))

    base = f"http://localhost:{INT_PORT}"
    for label, argv, stdin, want in (
            ("sitemap-urls.py", [sys.executable, os.path.join(HERE, "sitemap-urls.py"),
                                 f"{base}/sitemap.xml"], None, f"{base}/page-a"),
            ("linkcheck.py", [sys.executable, os.path.join(HERE, "linkcheck.py"), "-"],
             f"{base}/page-a\n", "link check: PASS")):
        tmp = tempfile.mkdtemp(prefix="lc-selftest-tmp.")
        before = len(_shim_lines())
        r = subprocess.run(argv, input=stdin, capture_output=True, text=True, cwd=tmp,
                           env=dict(os.environ, TMPDIR=tmp))
        new = _shim_lines()[before:]
        check(f"{label} end to end: ran to its verdict", r.returncode == 0 and want in r.stdout)
        check(f"{label} end to end: the token never reached curl's argv",
              bool(new) and not any(TOKEN in n for n in new))
        check(f"{label} end to end: the header file sat under $TMPDIR",
              any(" HDRFILE " in n and (" " + tmp + os.sep) in n for n in new))
        check(f"{label} end to end: the private dir is gone after exit", os.listdir(tmp) == [])
        shutil.rmtree(tmp, True)


FAILS = []


def check(name, cond):
    print(f"  {'✅' if cond else '❌'} {name}")
    if not cond:
        FAILS.append(name)


def extraction_checks(linkcheck):
    """A templating DIRECTIVE is not a link.

    `\\bhref=` / `\\bsrc=` also match INSIDE a longer attribute name, because `-`
    satisfies `\\b`. Every client-side dialect then donates its expressions to the
    crawl. Live instance: lux-airport.lu emits

        <img data-wp-bind--src="state.selectedImage.currentSrc">

    from WordPress core's block lightbox. Crawled as a relative path it 404s with
    total confidence — the worst kind of red, because it looks like a real broken
    link on a real page. Six consecutive weekly runs went red on it, and the
    documented remedy suppresses it per state-variable NAME, so renaming the
    variable (`currentImage` -> `selectedImage`) re-broke the gate and earned a
    SECOND suppression line for the same one bug.

    Both directions are asserted, and the positive half is the one that matters:
    a regex that extracted nothing at all would satisfy every "must not extract"
    case below.
    """
    print("linkcheck.py — attribute extraction: directives are not URLs")
    LIVE = ('<img data-wp-bind--src="state.selectedImage.currentSrc" '
            'src="/wp-content/uploads/real.jpg" alt="">')
    a_of = linkcheck.A_RE.findall
    i_of = linkcheck.IMG_RE.findall
    check("img: the real src is still extracted", i_of(LIVE) == ["/wp-content/uploads/real.jpg"])
    check("img: WP Interactivity data-wp-bind--src is NOT extracted",
          "state.selectedImage.currentSrc" not in i_of(LIVE))
    check("img: a directive-only tag yields nothing",
          i_of('<img data-wp-bind--src="state.x">') == [])
    check("a: a plain href is still extracted",
          a_of('<a href="/plain/">x</a>') == ["/plain/"])
    check("a: a data- attribute BEFORE href does not shadow it",
          a_of('<a data-astro-prefetch href="/ok/">x</a>') == ["/ok/"])
    check("a: Alpine/Vue x-bind:href is NOT extracted",
          a_of('<a x-bind:href="u">x</a>') == [])
    check("a: the :href shorthand is NOT extracted", a_of('<a :href="u">x</a>') == [])
    check("img: htmx hx-src is NOT extracted", i_of('<img hx-src="u">') == [])
    check("img: srcset does not shadow the real src",
          i_of('<img srcset="a.png 1x" src="/b.png">') == ["/b.png"])
    check("img: a directive alongside a real src yields ONLY the real one",
          i_of('<img :src="u" src="/z.png">') == ["/z.png"])

    # --- THE ACCEPTED COST, pinned so it stays a decision ---------------------
    # The lookbehind rejects a preceding `:`, which is what kills `x-bind:href`
    # and the `:href` shorthand above. It also rejects SVG 1.1's
    # `<a xlink:href="…">`, which IS a real link. Naming it here rather than
    # leaving it to be rediscovered as a hole: an exemption nothing pins decays
    # into "we never checked those".
    #
    # MEASURED before accepting, 2026-09-06 — every `xlink:href` across nine
    # caller repos plus two live rendered pages is a FRAGMENT reference
    # (`#SVGID_1_`, `#icon-badResponse`, `#_Image1`) on `<use>`/`<image>`/
    # `<linearGradient>`. Not one is a URL and not one is on an `<a>`. Fragment
    # refs are dropped by the `#` filter in extract() regardless, so the live
    # exposure is zero.
    #
    # And the mitigation is in the markup itself: SVG2 deprecated `xlink:href`
    # for plain `href`, which has no preceding colon and IS extracted — asserted
    # below, because a limitation without its escape route reads worse than it is.
    check("a: SVG1.1 xlink:href is NOT extracted — the accepted cost of the "
          "colon in the lookbehind (fleet exposure measured at zero)",
          a_of('<a xlink:href="https://example.com/svg-link">x</a>') == [])
    check("a: …but SVG2's plain href inside an <svg> IS extracted, which is the "
          "escape route for anything that actually needs crawling",
          a_of('<svg><a href="https://example.com/svg2-link">x</a></svg>')
          == ["https://example.com/svg2-link"])
    check("use: a fragment xlink:href was never crawlable anyway (the `#` filter), "
          "which is why the measured exposure is zero",
          a_of('<use xlink:href="#icon-badResponse"/>') == [])


def page_outcome_checks(linkcheck):
    """A sitemap page's OWN response is a verdict (v1.29.1).

    main() fetched each sitemap page with fetch_html(), which returned the body of
    ANY response, a 404 or 500 page included, and graded only the links extracted
    from that body. The page itself was never graded: a sitemap page that 404s or
    500s failed the run only if some other crawled page happened to link to it,
    and a theme's 404 template has working nav, so the dead page came back clean.

    It is graded the way status() grades a link to it, so one URL gets one answer
    whichever way the crawl reached it: one re-check for a transient edge 5xx, a
    WAF fingerprint routed to REVIEW, an EXCLUDE path not graded, and a page that
    is also a link target fetched and counted once.
    """
    print("linkcheck.py — a sitemap page's own response is graded like a link to it")
    base = f"http://a.localhost:{INT_PORT}"

    # --- fetch_html() returns the page's own outcome --------------------------
    REC.clear()
    code, blocked, html = _page(linkcheck, base + "/sm/404")
    check("fetch_html 404 page: the page's own code comes back (404), not blocked",
          code == 404 and blocked is False)
    check("…and so does its body, so a 404 template's links are still crawled",
          "int-landing" in html)
    code, _, _ = _page(linkcheck, base + "/sm/500")
    check("fetch_html 500 page: the page's own code comes back (500)", code == 500)
    check("…after exactly one re-check, as status() gives a link (2 GETs)",
          _hits("/sm/500", "GET") == 2)
    code, _, _ = _page(linkcheck, base + "/sm/flaky-unit")
    check("fetch_html: a transient edge 502 is re-checked, and the re-check's 200 stands",
          code == 200)
    _, blocked, _ = _page(linkcheck, base + "/sm/waf")
    check("fetch_html: a WAF fingerprint on a page marks its status untrusted", blocked is True)
    for path in ("/sm/404", "/sm/500", "/sm/waf"):
        url = base + path
        code, blocked, _ = _page(linkcheck, url)
        check(f"{path}: the page's verdict is the one a link to it gets",
              code is not None
              and linkcheck.verdict(url, code, blocked) == linkcheck.verdict(url, *linkcheck.status(url)))

    # --- end to end, through main() --------------------------------------------
    def crawl(paths):
        tmp = tempfile.mkdtemp(prefix="lc-selftest-tmp.")
        REC.clear()
        r = subprocess.run([sys.executable, os.path.join(HERE, "linkcheck.py"), "-"],
                           input="".join(base + p + "\n" for p in paths), capture_output=True,
                           text=True, cwd=tmp, env=dict(os.environ, TMPDIR=tmp))
        rq = os.path.join(tmp, "linkcheck-review.txt")
        review = open(rq, encoding="utf-8").read() if os.path.exists(rq) else ""
        shutil.rmtree(tmp, True)
        summary = next((ln for ln in r.stdout.splitlines() if ln.startswith("=== link check:")), "")
        fatal = r.stdout.split("FATAL (broken)")[1] if "FATAL (broken)" in r.stdout else ""
        return r, summary, fatal, review

    def listed(section, code, path, on):
        return re.search(rf"^  \[{code}\] {re.escape(base + path)}\n +on: {re.escape(on)}$",
                         section, re.M) is not None

    # THE BUG: two dead pages nothing links to, beside a healthy one. Before
    # v1.29.1 this run PASSED, because no link on any of the bodies is broken.
    r, summary, fatal, _ = crawl(["/sm/home", "/sm/404", "/sm/500", "/sm/cart/"])
    check("THE BUG: a crawl whose only defect is two dead sitemap pages FAILS (exit 1)",
          r.returncode == 1 and "link check: FAIL" in r.stdout)
    check("…the page that 404s is FATAL, named `on: sitemap`", listed(fatal, 404, "/sm/404", "sitemap"))
    check("…the page that 500s is FATAL, named `on: sitemap`", listed(fatal, 500, "/sm/500", "sitemap"))
    check("…both are counted: 4 checked (3 graded pages + 1 link), 2 fatal",
          "link check: 4 checked " in summary and "| 2 fatal |" in summary)
    check("…a page on an EXCLUDE path (/cart/) is fetched for its links but never graded, "
          "as a link to it would not be", _hits("/sm/cart/", "GET") >= 1 and "/sm/cart/" not in r.stdout)

    # ONE URL, ONE ANSWER: a dead page that is also linked to, a page that 502s
    # once, and a page behind a WAF challenge.
    r, summary, fatal, review = crawl(["/sm/links-to-404", "/sm/linked-404", "/sm/flaky-e2e", "/sm/waf"])
    check("a dead page that is ALSO a link target is listed once, naming the sitemap and the "
          "page linking to it", r.stdout.count(f"] {base}/sm/linked-404\n") == 1
          and listed(fatal, 404, "/sm/linked-404", f"sitemap, {base}/sm/links-to-404"))
    check("…and fetched once, as a page: no second request as a link (HEAD)",
          _hits("/sm/linked-404", "HEAD") == 0)
    check("a page that 502s once is re-checked (2 GETs) and is not FATAL",
          _hits("/sm/flaky-e2e", "GET") == 2 and f"{base}/sm/flaky-e2e" not in fatal)
    check("a WAF-challenged page goes to REVIEW (linkcheck-review.txt), not FATAL",
          f"{base}/sm/waf" in review.split() and f"{base}/sm/waf" not in fatal)
    check("…each counted once: 5 checked (4 graded pages + 1 link), 1 fatal, 1 review",
          "link check: 5 checked " in summary and "| 1 fatal |" in summary
          and "| 1 review ===" in summary)
    check("…and the one dead page still fails the run (exit 1)", r.returncode == 1)


SM_NS = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'


def _refusal(sitemap, data):
    """parse()'s own refusal message for `data`, or '' — an error from expat does
    not count, since that is expat's limit (or a syntax error), not the guard."""
    try:
        sitemap.parse(data)
    except sitemap.Refused as e:
        return str(e)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _parsed(sitemap, data):
    """parse()'s root for `data`, or None however it failed."""
    try:
        return sitemap.parse(data)
    except Exception:  # noqa: BLE001
        return None


def hostile_sitemap_checks(sitemap):
    """A hostile sitemap cannot exhaust the machine that parses it (v1.16.1).

    The security-baseline self-scan (run 36124011254) flagged the stdlib XML
    parse as use-defused-xml. ElementTree leaves entity expansion to the libexpat
    Python links, and only expat >= 2.4.1 bounds it: on macOS's system Python 3.9
    (expat 2.2.8) 487 bytes expanded to 30 MB in half a second. parse() now
    refuses any DOCTYPE inside expat before ElementTree runs, and fetch() caps
    the body at the protocol's 50 MB as read and again as gunzipped.

    The positive controls come first, because a guard that refused everything
    would pass every refusal below. The HARMLESS-entity case is the one a missing
    guard fails on every expat. The bomb alone proves nothing on a Linux runner,
    whose expat refuses it by its own limit, and on the Mac it would expand ~3 GB
    before failing at all — so it runs only once the guard is proven present.
    """
    print("sitemap-urls.py — a DOCTYPE is refused before any entity expands; bodies are capped")
    print(f"  (this Python links {sitemap.expat.EXPAT_VERSION}; expansion is bounded by expat "
          "itself only from 2.4.1)")

    # --- still parses what real generators emit --------------------------------
    wp = _parsed(sitemap, (
        '﻿<?xml version="1.0" encoding="UTF-8"?>'
        '<?xml-stylesheet type="text/xsl" href="//example.com/main-sitemap.xsl"?>'
        f'<urlset {SM_NS}><url><loc>https://example.com/a/</loc></url></urlset>').encode())
    check("a WordPress-shaped urlset (BOM, XML declaration, xml-stylesheet PI) still parses",
          wp is not None and [e.text for e in wp.findall(".//sm:url/sm:loc", sitemap.NS)]
          == ["https://example.com/a/"])
    idx = _parsed(sitemap, (f'<sitemapindex {SM_NS}><sitemap><loc>https://example.com/s.xml'
                            '</loc></sitemap></sitemapindex>').encode())
    check("a sitemapindex still parses", idx is not None and idx.tag.endswith("sitemapindex"))
    u16 = _parsed(sitemap, (
        '<?xml version="1.0" encoding="UTF-16"?>'
        f'<urlset {SM_NS}><url><loc>https://example.com/b/</loc></url></urlset>').encode("utf-16"))
    check("a UTF-16 sitemap still parses", u16 is not None
          and [e.text for e in u16.findall(".//sm:url/sm:loc", sitemap.NS)] == ["https://example.com/b/"])

    # --- the refusals ------------------------------------------------------------
    benign = ('<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY x "https://example.com/c/">]>'
              f'<urlset {SM_NS}><url><loc>&x;</loc></url></urlset>').encode()
    guarded = "<!DOCTYPE urlset>" in _refusal(sitemap, benign)
    check("a DOCTYPE is refused even when its entity is harmless (so it is the guard, "
          "not an expat limit, that refuses)", guarded)
    if guarded:
        ents = ['<!ENTITY l0 "lol">'] + [f'<!ENTITY l{i} "{("&l%d;" % (i - 1)) * 10}">'
                                         for i in range(1, 10)]
        bomb = (f'<?xml version="1.0"?><!DOCTYPE urlset [{"".join(ents)}]>'
                f'<urlset {SM_NS}><url><loc>&l9;</loc></url></urlset>').encode()
        check("the billion-laughs payload (~3 GB once expanded) is refused, by the guard",
              "<!DOCTYPE urlset>" in _refusal(sitemap, bomb))
    else:
        check("the billion-laughs payload — NOT run: with no guard it expands ~3 GB on "
              "expat < 2.4.1", False)
    check("…in UTF-16 too, where a byte search for '<!DOCTYPE' finds nothing",
          "<!DOCTYPE urlset>" in _refusal(sitemap, benign.decode().replace(
              '<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>').encode("utf-16")))
    check("an external-DTD DOCTYPE is refused too — the policy is 'no DTD', not 'no entity'",
          "<!DOCTYPE urlset>" in _refusal(sitemap, (
              '<?xml version="1.0"?><!DOCTYPE urlset SYSTEM "file:///etc/passwd">'
              f'<urlset {SM_NS}/>').encode()))
    check("an HTML page (a WAF challenge, an error page) is refused BY NAME, so the WARN "
          "says what came back", "<!DOCTYPE html>" in _refusal(
              sitemap, b'<!DOCTYPE html><html><body>Just a moment...</body></html>'))

    # --- the size cap, as read and as inflated -----------------------------------
    check("the cap is the protocol's own: 50 MB = 52,428,800 bytes (sitemaps.org)",
          sitemap.MAX_SITEMAP_BYTES == 52_428_800)
    base = f"http://localhost:{INT_PORT}"

    def fetched(path):
        try:
            return len(sitemap.fetch(base + path))
        except sitemap.Refused:
            return "refused"
        except Exception as exc:  # noqa: BLE001
            return f"raised {exc!r}"

    real_cap, sitemap.MAX_SITEMAP_BYTES = sitemap.MAX_SITEMAP_BYTES, 4096
    try:
        check("a body AT the cap is fetched", fetched("/bytes-4096") == 4096)
        check("a body one byte over it is refused", fetched("/bytes-4097") == "refused")
        check("a gzip body inflating to the cap is fetched", fetched("/gz-4096") == 4096)
        check("a small gzip inflating one byte past it is refused (a gzip bomb)",
              fetched("/gz-4097") == "refused")
    finally:
        sitemap.MAX_SITEMAP_BYTES = real_cap

    # --- end to end: main() keeps the real child and drops the DOCTYPE one -------
    tmp = tempfile.mkdtemp(prefix="lc-selftest-tmp.")
    r = subprocess.run([sys.executable, os.path.join(HERE, "sitemap-urls.py"),
                        f"{base}/dtd-index.xml"], capture_output=True, text=True, cwd=tmp,
                       env=dict(os.environ, TMPDIR=tmp))
    shutil.rmtree(tmp, True)
    check("end to end: the real child's page is still listed, and the run exits 0",
          r.returncode == 0 and f"{base}/page-a" in r.stdout.split())
    check("end to end: nothing from the DOCTYPE child reaches the page list",
          "from-a-dtd" not in r.stdout)
    check("end to end: the refused child is WARNed by URL, with the reason",
          f"WARN: failed to fetch/parse {base}/dtd-child.xml: refused: it declares "
          "<!DOCTYPE urlset>" in r.stderr)


def main():
    global INT_PORT, EXT_PORT
    int_srv, INT_PORT = _start("INT")
    ext_srv, EXT_PORT = _start("EXT")

    _install_curl_shim()   # before any curl runs, so runner_checks sees every call

    # Env must be set BEFORE importing the scripts — they read it at module load.
    os.environ["LINKCHECK_HOST"] = "localhost"
    os.environ["VERIFY_HOMEPAGE_TOKEN"] = TOKEN
    os.environ["LINKCHECK_WORKERS"] = "2"
    linkcheck = _load("linkcheck", "linkcheck.py")
    sitemap = _load("sitemap_urls", "sitemap-urls.py")

    extraction_checks(linkcheck)

    print("linkcheck.py — status() / fetch_html() per-hop token scoping")

    # 1) internal → external redirect (HEAD path): token on internal hop, NOT external.
    REC.clear()
    code, _ = linkcheck.status(f"http://localhost:{INT_PORT}/to-external")
    check("status int→ext: final code is 200", code == 200)
    check("status int→ext: internal hop carried the token", TOKEN in _tokens("INT"))
    check("status int→ext: external host was reached", bool(_tokens("EXT")))
    check("status int→ext: external host did NOT get the token", TOKEN not in _tokens("EXT"))

    # 2) external → internal redirect: external start hop has NO token; the internal
    #    hop RE-attaches it (per-hop re-scoping, not gate-by-start-host).
    REC.clear()
    code, _ = linkcheck.status(f"http://127.0.0.1:{EXT_PORT}/to-internal")
    check("status ext→int: final code is 200", code == 200)
    check("status ext→int: external hop did NOT get the token", TOKEN not in _tokens("EXT"))
    check("status ext→int: internal hop re-attached the token", TOKEN in _tokens("INT"))

    # 3) fetch_html follows the chain, returns the FINAL (external) body, no leak.
    REC.clear()
    code, _, html = _page(linkcheck, f"http://localhost:{INT_PORT}/to-external")
    check("fetch_html int→ext: returned the final external body", "EXTERNAL-LANDING" in html)
    check("fetch_html int→ext: …and the final hop's code (200)", code == 200)
    check("fetch_html int→ext: external host did NOT get the token", TOKEN not in _tokens("EXT"))
    check("fetch_html int→ext: internal hop carried the token", TOKEN in _tokens("INT"))

    # 4) direct external fetch never carries the token.
    REC.clear()
    linkcheck.status(f"http://127.0.0.1:{EXT_PORT}/int-landing")
    check("status direct-external: token never sent", TOKEN not in _tokens("EXT"))

    # 4b) fetch_html transparently decompresses a Content-Encoding: gzip body
    #     (guards the --compressed flag) so extract() still sees the links.
    _, _, html_gz = _page(linkcheck, f"http://localhost:{INT_PORT}/gz-html")
    check("fetch_html gzip: body was decompressed", "sub.localhost/gz-link" in html_gz)
    check("fetch_html gzip: extract() recovered the link",
          any("sub.localhost/gz-link" in u for u in
              linkcheck.extract(f"http://localhost:{INT_PORT}/gz-html", html_gz)))

    # 4c) a redirect loop is no-final-answer (code 0), not a 3xx scored "ok" —
    #     matches the old `-L --max-redirs` behavior, so a looping internal page
    #     is still caught as broken.
    REC.clear()
    loop_code, _ = linkcheck.status(f"http://localhost:{INT_PORT}/loop")
    check("status redirect-loop: returns 0 (no final answer)", loop_code == 0)
    loop_page = _page(linkcheck, f"http://localhost:{INT_PORT}/loop")
    check("fetch_html redirect-loop: code 0 (no final answer) and no body",
          loop_page[0] == 0 and loop_page[2] == "")

    # 5) host predicate: subdomains internal, look-alikes external.
    check("is_internal(localhost)", linkcheck.is_internal("http://localhost/x"))
    check("is_internal(sub.localhost)", linkcheck.is_internal("http://a.localhost/x"))
    check("is_internal(127.0.0.1) is False", not linkcheck.is_internal("http://127.0.0.1/x"))
    check("is_internal(localhost.evil.com) is False",
          not linkcheck.is_internal("http://localhost.evil.com/x"))

    page_outcome_checks(linkcheck)

    print("sitemap-urls.py — fetch() host-gated, per-hop token scoping")
    sitemap._seed_allowed("localhost")

    # 6) sitemap fetch across an internal→external redirect: external gets no token.
    REC.clear()
    data = sitemap.fetch(f"http://localhost:{INT_PORT}/to-external")
    check("sitemap int→ext: returned the final external body", b"EXTERNAL-LANDING" in data)
    check("sitemap int→ext: external host did NOT get the token", TOKEN not in _tokens("EXT"))
    check("sitemap int→ext: internal hop carried the token", TOKEN in _tokens("INT"))

    # 7) sitemap fetch of an off-host child never carries the token (the old bug:
    #    it sent X-Verify-Source unconditionally to every URL).
    REC.clear()
    sitemap.fetch(f"http://127.0.0.1:{EXT_PORT}/int-landing")
    check("sitemap direct-external: token never sent", TOKEN not in _tokens("EXT"))

    check("is_allowed(localhost)", sitemap.is_allowed("http://localhost/"))
    check("is_allowed(a.localhost)", sitemap.is_allowed("http://a.localhost/"))
    check("is_allowed(127.0.0.1) is False", not sitemap.is_allowed("http://127.0.0.1/"))
    check("is_allowed(localhost.evil.com) is False",
          not sitemap.is_allowed("http://localhost.evil.com/"))

    hostile_sitemap_checks(sitemap)
    runner_checks()

    int_srv.shutdown()
    ext_srv.shutdown()

    crash_guard_checks()
    crawl_floor_checks()
    issue_body_checks(linkcheck)
    step_summary_checks(linkcheck)

    print()
    if FAILS:
        print(f"FAIL — {len(FAILS)} check(s) failed: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("PASS — token scoping, sitemap pages graded on their own response, the "
          "hostile-sitemap refusals, crash-guard attribution, the crawl-size floor, the "
          "issue-body cap and the step-summary cap hold.")


def crash_guard_checks():
    """Crash guard — asserted BEHAVIOURALLY, by crashing the real crawler.

    Never by grepping linkcheck.py for `except`: a textual assertion cannot tell a
    live handler from a dead one, and goes vacuous the moment the file is
    restructured. So we mutate a COPY of the real entrypoint, run it, and read the
    exit code and the output an operator would actually see.

    linkcheck has no report mode — it is structurally always-enforcing — so unlike
    the JS siblings there is no exit code to soften. What is pinned here is
    ATTRIBUTION, the half that bit: exit 1 means "I checked, links are broken",
    exit 2 means "I could not check". That distinction is what lets action.yml
    stop filing a false broken-links issue when it was our own scanner that died.
    """
    import subprocess
    import sys
    import tempfile

    print("\n# crash guard (real linkcheck.py, injected fault)")
    src = open(os.path.join(HERE, "linkcheck.py"), encoding="utf-8").read()
    anchor = "def main():"

    # Fail CLOSED: a missing anchor makes the mutation a silent no-op, and every
    # assertion below would then pass against a crawler that never crashed.
    check(f"fault-injection anchor {anchor!r} still present", anchor in src)
    if anchor not in src:
        return

    def run(source, env_extra=None, stdin=""):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "lc.py")
            with open(p, "w", encoding="utf-8") as f:
                f.write(source)
            env = {"PATH": os.environ.get("PATH", ""), "LINKCHECK_HOST": "localhost"}
            env.update(env_extra or {})
            r = subprocess.run([sys.executable, p, "-"], input=stdin,
                               capture_output=True, text=True, env=env)
            return r

    crashed = run(src.replace(anchor, anchor + "\n    raise RuntimeError('injected crawler fault')"))

    # (1) exit 2 = "no verdict", distinct from 1 = "real broken links". This is the
    #     single assertion the action.yml issue gating depends on.
    check("a crawler fault exits 2 (tool fault), NOT 1 (a link verdict)", crashed.returncode == 2)

    # (2) the crash must reach STDOUT, because action.yml pipes stdout through
    #     `tee linkcheck-report.txt` and appends that file to the step summary —
    #     stdout is the only path to an operator reading the run summary. A guard
    #     that reported to stderr alone would be invisible where it matters.
    check("the crash is reported on stdout (the path to the step summary)",
          "linkcheck CRASHED" in crashed.stdout)
    check("the crash names itself a TOOL fault, not a link verdict",
          "NOT a link verdict" in crashed.stdout)
    check("the injected reason is carried through", "injected crawler fault" in crashed.stdout)
    check("the full traceback reaches stderr for the raw job log",
          "injected crawler fault" in crashed.stderr and "Traceback" in crashed.stderr)

    # (3) a crash must NEVER be mistaken for a clean run — the failure mode that
    #     would silently close the tracking issue and declare a broken site healthy.
    check("a crash never prints the PASS verdict", "link check: PASS" not in crashed.stdout)

    # (4) SystemExit passes through untouched: `except Exception` does not catch it
    #     (it derives from BaseException), so every deliberate verdict exit keeps its
    #     own code and is never relabelled a crash. Asserted on the real config-error
    #     path — no LINKCHECK_HOST — which already exits 2 for a genuine reason.
    cfg = run(src, env_extra={"LINKCHECK_HOST": ""})
    check("a deliberate config-error exit is not relabelled as a crash",
          cfg.returncode == 2 and "CRASHED" not in cfg.stdout)

    # (5) the clean path is untouched by the guard: zero pages in, PASS out, exit 0.
    ok = run(src)
    check("an empty clean run still exits 0 with PASS",
          ok.returncode == 0 and "link check: PASS" in ok.stdout)

    # (6) action.yml wiring. The exit-code split above is only worth anything if the
    #     issue steps actually key on it. There is no runtime to exercise a GitHub
    #     `if:` expression, so this is textual by necessity — but it is pinned to the
    #     SEMANTIC claim (rc-keyed, and specifically NOT failure()-keyed), which is
    #     the thing that regressed, rather than to formatting.
    ay = open(os.path.join(HERE, "..", "action.yml"), encoding="utf-8").read()
    open_step = ay.split("- name: Open / update the broken-links issue")[1].split("- name:")[0]
    close_step = ay.split("- name: Close the broken-links issue when clean")[1].split("- name:")[0]
    check("the crawl step publishes a verdict as a step output",
          'echo "verdict=$verdict"' in ay)
    check("open-issue keys on verdict == 'broken' (a real link verdict)",
          "steps.crawl.outputs.verdict == 'broken'" in open_step)
    check("open-issue no longer keys on failure() — the false-issue bug",
          "failure()" not in open_step)
    check("close-issue keys on verdict == 'clean', not success()",
          "steps.crawl.outputs.verdict == 'clean'" in close_step and "success()" not in close_step)

    # (6b) THE CLASS, not the instance (2026-09-04). An UNSET step output is not inert
    #      in a GitHub `if:`: comparing null against a numeric-looking string coerces
    #      both to numbers, so `outputs.rc == '0'` is TRUE when rc was never written.
    #      That is how this action closed its own broken-links issue on every run that
    #      FOUND broken links — "we got no verdict" read as "verified clean".
    #      No issue-lifecycle condition may compare an output to a numeric literal
    #      again, whatever it is named.
    numeric_cmp = re.compile(r"steps\.\w+\.outputs\.\w+\s*==\s*'\d+'")
    check("no issue-lifecycle `if:` compares a step output to a NUMERIC literal",
          not numeric_cmp.search(open_step) and not numeric_cmp.search(close_step))

    # (7) THE BEHAVIOURAL ANCHOR the textual checks above structurally cannot give,
    #     and the reason this bug shipped: assertions (6) pinned that the wiring
    #     EXISTED, never that the crawl step could reach it. `shell: bash` runs
    #     `bash -eo pipefail`, so a crawler exiting non-zero aborted the step BEFORE
    #     the output was written. Extract the real `run:` body out of action.yml and
    #     execute it under the same flags GitHub uses, with a stub crawler.
    crawl_body = ay.split("      run: |\n        set -o pipefail\n")[1].split("\n    - name:")[0]
    crawl_body = textwrap.dedent("        set -o pipefail\n" + crawl_body)
    check("the crawl step's run: body was extracted for execution",
          "verdict=" in crawl_body and "PIPESTATUS" in crawl_body)

    for rc_want, verdict_want in ((0, "clean"), (1, "broken"), (2, "fault")):
        with tempfile.TemporaryDirectory() as td:
            stub = os.path.join(td, "linkcheck.py")
            with open(stub, "w", encoding="utf-8") as f:
                f.write(f"import sys\nprint('stub crawler')\nsys.exit({rc_want})\n")
            body = crawl_body.replace(
                '"${{ github.action_path }}/scripts/linkcheck.py"', f'"{stub}"')
            out_file = os.path.join(td, "gh_out")
            sum_file = os.path.join(td, "gh_sum")
            open(os.path.join(td, "pages.txt"), "w").close()
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", body],
                               cwd=td, capture_output=True, text=True,
                               env={"PATH": os.environ.get("PATH", ""),
                                    "GITHUB_OUTPUT": out_file,
                                    "GITHUB_STEP_SUMMARY": sum_file})
            written = open(out_file, encoding="utf-8").read() if os.path.exists(out_file) else ""
            check(f"crawler rc={rc_want}: the step still PUBLISHES its verdict "
                  f"(this is what -e used to prevent)",
                  f"verdict={verdict_want}" in written and f"rc={rc_want}" in written)
            check(f"crawler rc={rc_want}: the step's own exit code is preserved ({rc_want})",
                  r.returncode == rc_want)


def crawl_floor_checks(ay=None):
    """The collapsed-crawl floor — the 2026-09-06 lampakia-astro class.

    Scheduled run 33382684973 reported `48 checked | 10 fatal` -> FAIL and named
    ten `/katigoria/…` URLs as broken. Every one returns 200; the next full run
    crawled 1824 pages / 5113 links with 0 fatal. The tell was one line above the
    verdict: `Collected 18 page URLs across the sitemap` against 1824. The page
    set had collapsed ~100x, `[ "$N" -gt 0 ]` was satisfied, and the action
    published a verdict about a site it had seen 1% of.

    Two layers are graded here, and the second is the one that matters:
      * the DECISION is pure and unit-testable (below);
      * the OVERRIDE is executed, by running the real crawl `run:` body out of
        action.yml under the same bash flags GitHub uses. A static check proves a
        condition exists, never that it fires — which is exactly how the
        2026-09-04 numeric-coercion bug shipped past a selftest that had pinned
        the buggy condition verbatim.
    """
    import json
    import subprocess
    import sys
    import tempfile

    print("\n# crawl-size floor (collapsed page set => fault, not a verdict)")
    floor_py = os.path.join(HERE, "crawl-floor.py")
    check("crawl-floor.py ships next to the crawler", os.path.exists(floor_py))
    if not os.path.exists(floor_py):
        return

    def decide(pages, baseline_content, extra=None):
        with tempfile.TemporaryDirectory() as td:
            bp = os.path.join(td, "b.json")
            if baseline_content is not None:
                with open(bp, "w", encoding="utf-8") as f:
                    f.write(baseline_content)
            r = subprocess.run(
                [sys.executable, floor_py, "decide", "--pages", str(pages),
                 "--baseline", bp] + (extra or []),
                capture_output=True, text=True)
            return r.stdout.strip(), r.stderr, r.returncode

    # --- the incident, reproduced exactly -----------------------------------
    good = json.dumps([1824, 1820, 1830])
    d, err, rc = decide(18, good)
    check("THE INCIDENT: 18 pages against a 1824 median is `collapsed`", d == "collapsed")
    check("…and the explanation names both numbers, not just a verdict",
          "18" in err and "1824" in err)
    check("…and deciding never fails the run itself (exit 0)", rc == 0)

    # --- and the healthy run right next to it, or the above proves nothing ---
    check("a full crawl against the same baseline is `ok`", decide(1800, good)[0] == "ok")

    # --- boundary, both sides ------------------------------------------------
    check("exactly at the floor is NOT collapsed (0.5 x 1824 = 912)",
          decide(912, good)[0] == "ok")
    check("one page below the floor IS collapsed", decide(911, good)[0] == "collapsed")

    # --- COULD-NOT-LOOK is its own state, three ways -------------------------
    #     Each must be distinguishable in the report; none may fault the run. A
    #     floor that red-lights every new caller is a floor that gets switched off.
    d, err, _ = decide(18, None)
    check("no baseline at all => `no-baseline`, never `collapsed`", d == "no-baseline")
    check("…and it says the size was NOT judged", "NOT judged" in err)
    d, err, _ = decide(18, "{not json at all")
    check("a corrupt baseline => `unreadable`, never `collapsed`", d == "unreadable")
    check("…and `unreadable` is distinguishable from `no-baseline` in the report",
          "not a list of positive integers" in err)
    check("a list with a non-int member is `unreadable`, not silently filtered",
          decide(18, json.dumps([1824, "1820", 1830]))[0] == "unreadable")
    check("too little history => `no-baseline` (the floor is not armed yet)",
          decide(18, json.dumps([1824, 1820]))[0] == "no-baseline")
    check("…and the third good run arms it", decide(18, json.dumps([1824, 1820, 1830]))[0] == "collapsed")

    # --- the knobs actually move the answer ----------------------------------
    check("--fraction 0.9 makes a 20% drop collapsed",
          decide(1400, good, ["--fraction", "0.9"])[0] == "collapsed")
    check("--fraction 0.001 makes even 18 pages ok (0 disables at the action level)",
          decide(18, good, ["--fraction", "0.001"])[0] == "ok")
    check("--min-history 5 disarms a 3-run baseline",
          decide(18, good, ["--min-history", "5"])[0] == "no-baseline")

    # --- a crash degrades to `unreadable`, never to `ok` ---------------------
    #     Asserted by mutating a COPY of the real file, not by grepping for
    #     `except`: a textual check cannot tell a live handler from a dead one.
    src = open(floor_py, encoding="utf-8").read()
    anchor = "def main():"
    check("floor fault-injection anchor still present", anchor in src)
    if anchor in src:
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "cf.py")
            with open(p, "w", encoding="utf-8") as f:
                f.write(src.replace(anchor, anchor + "\n    raise RuntimeError('injected floor fault')"))
            bp = os.path.join(td, "b.json")
            with open(bp, "w", encoding="utf-8") as f:
                f.write(good)
            r = subprocess.run([sys.executable, p, "decide", "--pages", "18", "--baseline", bp],
                               capture_output=True, text=True)
            check("a crashed floor script prints `unreadable`, never `ok`",
                  r.stdout.strip() == "unreadable")
            check("…exits 0, so a broken GUARD cannot take a working gate down",
                  r.returncode == 0)
            check("…and the traceback still reaches stderr", "injected floor fault" in r.stderr)

    # --- record: only trustworthy runs extend the history --------------------
    with tempfile.TemporaryDirectory() as td:
        bp = os.path.join(td, "b.json")
        for n in (100, 200, 300):
            subprocess.run([sys.executable, floor_py, "record", "--pages", str(n),
                            "--baseline", bp], capture_output=True, text=True)
        check("record appends in order", json.load(open(bp)) == [100, 200, 300])
        subprocess.run([sys.executable, floor_py, "record", "--pages", "400",
                        "--baseline", bp, "--keep", "2"], capture_output=True, text=True)
        check("record keeps only the last --keep samples", json.load(open(bp)) == [300, 400])
        with open(bp, "w", encoding="utf-8") as f:
            f.write("garbage")
        subprocess.run([sys.executable, floor_py, "record", "--pages", "500",
                        "--baseline", bp], capture_output=True, text=True)
        check("record recovers from a corrupt baseline instead of wedging it forever",
              json.load(open(bp)) == [500])

    # ===== THE FLOOR STEP, EXECUTED (v1.29.3) ================================
    # Its summary line was `_crawl-floor: $d_`. Bash reads `$d_` as the unset
    # variable d_, so from v1.13.0 the summary never named the decision; only a
    # run of the real `run:` body could see it. Run on the real crawl-floor.py,
    # and on a stub that prints no token at all.
    if ay is None:
        ay = open(os.path.join(HERE, "..", "action.yml"), encoding="utf-8").read()
    floor_body = textwrap.dedent(ay.split(
        "- name: Judge the crawl size against this site's own history\n")[1]
        .split("\n    - name:")[0].split("      run: |\n", 1)[1])

    def run_floor(pages, baseline_content, floor_src=src):
        """Run the floor step. Returns its exit code, outputs, summary, and the
        ${{ }} expressions in it this leg has no value for."""
        with tempfile.TemporaryDirectory() as td:
            ws, scripts = os.path.join(td, "workspace"), os.path.join(td, "action", "scripts")
            os.makedirs(ws)
            os.makedirs(scripts)
            with open(os.path.join(scripts, "crawl-floor.py"), "w", encoding="utf-8") as f:
                f.write(floor_src)
            if baseline_content is not None:
                with open(os.path.join(ws, ".linkcheck-baseline.json"), "w", encoding="utf-8") as f:
                    f.write(baseline_content)
            run, unknown = _evaluate(floor_body, {     # the inputs at their action.yml defaults
                "github.action_path": os.path.join(td, "action"), "github.workspace": ws,
                "steps.sitemap.outputs.pages": str(pages), "inputs.crawl-floor-fraction": "0.5",
                "inputs.crawl-floor-min-history": "3"})
            out_file, sum_file = os.path.join(td, "gh_out"), os.path.join(td, "gh_sum")
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", run],
                               cwd=ws, capture_output=True, text=True,
                               env={"PATH": os.environ.get("PATH", ""),
                                    "GITHUB_OUTPUT": out_file, "GITHUB_STEP_SUMMARY": sum_file})
            return (r.returncode,) + tuple(open(p, encoding="utf-8").read() if os.path.exists(p)
                                           else "" for p in (out_file, sum_file)) + (unknown,)

    check("the floor step's run: body was extracted, and every ${{ }} in it is one this leg "
          "stands in for", "crawl-floor.py" in floor_body and not run_floor(1800, good)[3])
    for d, pages, baseline, said in (("collapsed", 18, good, "1824"), ("ok", 1800, good, "1824"),
                                     ("no-baseline", 18, None, "NOT judged"),
                                     ("unreadable", 18, "{not json", "not a list")):
        rc, outputs, summary, _ = run_floor(pages, baseline)
        check(f"floor step, {d}: the summary opens `_crawl-floor: {d}_`, the reason under it "
              "(v1.29.3)", rc == 0 and f"decision={d}\n" in outputs
              and summary.startswith(f"_crawl-floor: {d}_\n") and said in summary)
    rc, outputs, summary, _ = run_floor(18, good, floor_src="import sys\nsys.exit(0)\n")
    check("floor step, no token printed: the summary says `_crawl-floor: unreadable_`, never `ok`",
          rc == 0 and "decision=unreadable\n" in outputs and summary == "_crawl-floor: unreadable_\n")

    # ===== THE OVERRIDE, EXECUTED ===========================================
    # Everything above grades a pure function. This grades action.yml: extract the
    # real crawl `run:` body and run it under `bash --noprofile --norc -eo
    # pipefail` with a stub crawler, exactly as GitHub would.
    body = ay.split("      run: |\n        set -o pipefail\n")[1].split("\n    - name:")[0]
    body = textwrap.dedent("        set -o pipefail\n" + body)
    check("the crawl body was extracted and carries the floor override",
          "LINKCHECK_FLOOR_DECISION" in body)

    def run_body(rc, decision):
        with tempfile.TemporaryDirectory() as td:
            stub = os.path.join(td, "linkcheck.py")
            with open(stub, "w", encoding="utf-8") as f:
                f.write(f"import sys\nprint('stub crawler')\nsys.exit({rc})\n")
            b = body.replace('"${{ github.action_path }}/scripts/linkcheck.py"', f'"{stub}"')
            out_file, sum_file = os.path.join(td, "gh_out"), os.path.join(td, "gh_sum")
            open(os.path.join(td, "pages.txt"), "w").close()
            env = {"PATH": os.environ.get("PATH", ""),
                   "GITHUB_OUTPUT": out_file, "GITHUB_STEP_SUMMARY": sum_file}
            if decision is not None:
                env["LINKCHECK_FLOOR_DECISION"] = decision
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", b],
                               cwd=td, capture_output=True, text=True, env=env)
            written = open(out_file, encoding="utf-8").read() if os.path.exists(out_file) else ""
            vfile = os.path.join(td, "linkcheck-verdict.txt")
            verdict_file = open(vfile, encoding="utf-8").read().strip() if os.path.exists(vfile) else ""
            summary = open(sum_file, encoding="utf-8").read() if os.path.exists(sum_file) else ""
            return r, written, verdict_file, summary

    # (1) THE DANGEROUS DIRECTION. A collapsed crawl that happened to find no
    #     broken links would report `clean` — which CLOSES the tracking issue,
    #     declaring a site verified when 99% of it was never fetched. Harder to
    #     notice than the red one and strictly worse.
    r, written, vfile, summary = run_body(0, "collapsed")
    check("collapsed + rc=0: the CLEAN verdict is downgraded to `fault`",
          "verdict=fault" in written and vfile == "fault")
    check("collapsed + rc=0: `clean` is nowhere in the published output "
          "(it would close the issue)", "verdict=clean" not in written)
    check("collapsed + rc=0: the step goes RED — a green gate would report a run "
          "that verified nothing", r.returncode != 0)
    check("collapsed + rc=0: rc is republished as 2, matching the fault verdict",
          "rc=2" in written)
    check("collapsed + rc=0: the step summary explains the collapse, not the links",
          "CRAWL SIZE COLLAPSED" in summary and "NOT a link verdict" in summary)

    # (2) …and the red direction, which is the shape actually observed.
    r, written, vfile, _ = run_body(1, "collapsed")
    check("collapsed + rc=1: the BROKEN verdict is downgraded to `fault`",
          "verdict=fault" in written and vfile == "fault")
    check("collapsed + rc=1: `broken` is nowhere in the published output "
          "(it would file a false report)", "verdict=broken" not in written)

    # (3) THE ASYMMETRY. Without these, (1) and (2) pass just as well against a
    #     step that faults unconditionally — a gate that can never say anything.
    for decision in ("ok", "no-baseline", "unreadable", None):
        label = decision if decision is not None else "unset (floor step skipped)"
        _, written, _, _ = run_body(1, decision)
        check(f"decision={label}: a real BROKEN verdict still reports broken",
              "verdict=broken" in written)
        _, written, _, _ = run_body(0, decision)
        check(f"decision={label}: a real CLEAN verdict still reports clean",
              "verdict=clean" in written)

    # (4) a genuine crawler FAULT is not relabelled by the floor either way.
    _, written, _, _ = run_body(2, "ok")
    check("decision=ok + rc=2: a crawler fault is still `fault`", "verdict=fault" in written)

    # --- action.yml wiring: the pieces the executed body cannot reach --------
    check("the floor step publishes a decision the crawl step consumes",
          'echo "decision=$d" >> "$GITHUB_OUTPUT"' in ay
          and "LINKCHECK_FLOOR_DECISION: ${{ steps.floor.outputs.decision }}" in ay)
    check("an empty decision token defaults to `unreadable`, never `ok` "
          "(a guard that never ran must not read as healthy)",
          "*) d=unreadable" in ay)
    record_step = ay.split("- name: Record this crawl's size in the baseline")[1].split("- name:")[0]
    check("a COLLAPSED run never extends the baseline it is judged against "
          "(the guard would train itself to accept the collapse)",
          "steps.floor.outputs.decision != 'collapsed'" in record_step)
    check("only a real verdict extends the baseline",
          "outputs.verdict == 'clean'" in record_step and "outputs.verdict == 'broken'" in record_step)


# ---- the report cut: the issue body's (v1.29.2) and the step summary's (v1.29.3) ----
# Both legs execute a step out of action.yml on reports from the REAL linkcheck.main(),
# and grade the cut with the same checks: both steps run scripts/fit-report.py.

# Bytes and characters part ways on a Greek URL, which is the point of using one.
_page_url = "http://www.localhost/κατηγορία/ηλεκτρολογικό-υλικό/προϊόν-{:04d}/".format
_ext_url = "https://ext-{0:03d}.example.org/σελίδα-{0:04d}/".format


def _html(links):
    return "<html>" + "".join(f'<a href="{u}">x</a>' for u in links) + "</html>"


def _report_of(linkcheck, pages, page_of, link_of=lambda url: (200, False)):
    """The REAL linkcheck.main()'s report for `pages`, its fetches replaced:
    page_of(url) -> (code, blocked, html), link_of(url) -> (code, blocked)."""
    saved = linkcheck.fetch_html, linkcheck.status, sys.argv, os.getcwd()
    tmp, out = tempfile.mkdtemp(prefix="lc-selftest-tmp."), io.StringIO()
    try:
        linkcheck.fetch_html, linkcheck.status = page_of, link_of
        sys.argv = ["linkcheck.py", *pages]
        os.chdir(tmp)                      # main() writes linkcheck-review.txt here
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            try:
                linkcheck.main()
            except SystemExit:
                pass
    finally:
        linkcheck.fetch_html, linkcheck.status, sys.argv = saved[:3]
        os.chdir(saved[3])
        shutil.rmtree(tmp, True)
    return out.getvalue()


def _at_the_cap(linkcheck, wrap, cap):
    """(n, a report whose wrap() is exactly `cap` bytes, the same report one byte
    longer): n dead pages and one WARN row, the last dead page's URL padded to the
    byte. One byte over costs the last row in posting order, the WARN one."""
    hub = _page_url(9999)

    def sized(n, pad):
        pages = [_page_url(i) for i in range(n)] + [hub]
        pages[-2] += "x" * pad
        return _report_of(linkcheck, pages, lambda u: (200, False, _html([_ext_url(0)])) if u == hub
                          else (404, False, ""), lambda u: (500, False))

    n = (cap - len(wrap(sized(1, 0)))) // (len(wrap(sized(2, 0))) - len(wrap(sized(1, 0))))
    while n > 1 and len(wrap(sized(n, 0))) > cap:
        n -= 1
    short = len(wrap(sized(n, 0)))
    return n, sized(n, cap - short), sized(n, cap + 1 - short)


def _fenced(report):
    """What the issue step fences, and both steps cut: from the `=== link check` line
    on, as awk and $( ) cut it."""
    m = re.search(r"^=== link check", report or "", re.M)
    return report[m.start():].rstrip("\n") if m else "(report unavailable — open the run log)"


def _rows(text):
    """[(section title, row)] in order. A row is its `  [code] url` line and the
    `      on: …` line under it; a line of either kind without its partner
    comes back as (section, None)."""
    found, section, lines, i = [], None, text.split("\n"), 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("  [") and i + 1 < len(lines) and lines[i + 1].startswith("      on: "):
            found.append((section, ln + "\n" + lines[i + 1]))
            i += 2
            continue
        if ln.startswith(" "):
            found.append((section, None))
        elif ln:
            section = ln
        i += 1
    return found


def _rank(section):
    return {"FATAL": 0, "REVIEW": 1, "WARN": 2}.get((section or "").split(" ")[0], 3)


def _evaluate(text, ctx):
    """`text` with each ${{ expr }} in it read from `ctx`. Returns (that text, the
    expressions `ctx` has no value for)."""
    unknown = []

    def value(m):
        if m.group(1) not in ctx:
            unknown.append(m.group(1))
        return ctx.get(m.group(1), "")
    return re.sub(r"\$\{\{\s*([\w.-]+)\s*\}\}", value, text), unknown


def _step_env(ay, step, ctx):
    """The env the step named `step` hands its run: body, from its own `env:` block,
    each ${{ expr }} in it read from `ctx`: a mapping missing from action.yml is
    missing here too. Returns (env, the expressions `ctx` has no value for)."""
    block = ay.split(f"- name: {step}\n")[1].split("\n      run: |")[0]
    env, unknown = {}, []
    for name, raw in re.findall(r"^        ([A-Z][A-Z0-9_]*): (.*)$", block, re.M):
        env[name], missing = _evaluate(raw, ctx)
        unknown += missing
    return env, unknown


def _cut_checks(label, report, cut, left_out, size, cap):
    """What every cut owes, whatever it was cut for. `cut` is what the step fenced,
    `left_out` the count in the note under it, `size` the bytes of the whole post.
    Returns the rows it kept."""
    whole = _fenced(report)
    lines, want, got = cut.split("\n"), _rows(whole), _rows(cut)
    heads = {ln for ln in whole.split("\n") if ln and not ln.startswith(" ")}
    sections = {s for s, _ in want}
    check(f"{label}: …the fence opens with the report's summary line",
          lines[0] == whole.split("\n")[0])
    check(f"{label}: …only WHOLE rows, each one of the report's, none twice",
          all(r is not None for _, r in got) and set(got) <= set(want)
          and len(set(got)) == len(got))
    check(f"{label}: …no line the report does not have", all(
        not ln or ln.startswith(" ") or ln in heads for ln in lines))
    check(f"{label}: …no section title without its first row", all(
        i + 1 < len(lines) and lines[i + 1].startswith("  [")
        for i, ln in enumerate(lines) if ln in sections))
    check(f"{label}: …the rows kept are the report's first ones, FATAL then REVIEW then WARN",
          got == sorted(want, key=lambda sr: _rank(sr[0]))[:len(got)])
    check(f"{label}: …kept + left out = every row ({len(got)} + {left_out} = {len(want)})",
          len(got) + left_out == len(want))
    verdict = whole.find("\nlink check: ")
    check(f"{label}: …it ends as the report does, from the verdict line on (v1.29.3)",
          verdict > 0 and cut.endswith("\n" + whole[verdict:]))
    check(f"{label}: …and it fills the room: within 600 bytes of {cap:,} (a summary-only "
          "body would pass every check above)", cap - size < 600)
    return got


def issue_body_checks(linkcheck, ay=None, action_path=None):
    """The broken-links issue is still posted when the report is huge (v1.29.2).

    GitHub refuses an issue or comment body over 65,536 characters, and past
    128 KiB Linux will not even start `gh` with it (one argument is capped there).
    The step is continue-on-error, so a report that long opened and commented
    NOTHING. Since v1.29.1 every dead sitemap page is a row of its own, so a site
    that goes down mid-crawl lists one row per page: the issue went missing exactly
    when the breakage was largest.

    The REAL `run:` body is executed, out of action.yml (or `ay`, the text a
    mutation run feeds in), under GitHub's bash flags with `gh` and `date` stubbed,
    and with the env the step's own `env:` block declares. `action_path` stands in
    for ${{ github.action_path }}: a mutation run points it at a broken
    fit-report.py. Every report comes from the REAL linkcheck.main() with only its
    two fetches replaced, so a change to the report's format meets the trimmer here,
    not as a caller's missing issue.
    """
    print("\n# the issue body: under GitHub's limit, whole rows, FATAL first (v1.29.2)")
    action_path = action_path or os.path.dirname(HERE)
    if ay is None:
        ay = open(os.path.join(action_path, "action.yml"), encoding="utf-8").read()
    step = ay.split("- name: Open / update the broken-links issue\n")[1].split("\n    - name:")[0]
    src = textwrap.dedent(step.split("      run: |\n", 1)[1])
    check("the issue step's run: body was extracted, and runs as written (no ${{ }} in it)",
          "gh issue create" in src and "${{" not in src)

    repo, run_id, day = "example-org/example-site", "33911783576", "2026-10-12"
    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
    env, unknown = _step_env(ay, "Open / update the broken-links issue", {
        "github.token": "x", "github.repository": repo, "github.server_url": "https://github.com",
        "github.run_id": run_id, "github.action_path": action_path})
    check("the issue step's env: block evaluates: each ${{ }} in it is one this leg stands in for",
          bool(env) and not unknown)
    stubs = tempfile.mkdtemp(prefix="lc-selftest-gh.")
    atexit.register(shutil.rmtree, stubs, True)
    with open(os.path.join(stubs, "gh"), "w", encoding="utf-8") as f:
        f.write(textwrap.dedent("""\
            #!/usr/bin/env bash
            # The calls the step makes. `issue list` answers $STUB_OPEN_ISSUE; create
            # and comment record their verb and their exact --title and --body.
            case "$1 $2" in
              "issue list") [ -z "$STUB_OPEN_ISSUE" ] || printf '%s\\n' "$STUB_OPEN_ISSUE" ;;
              "issue create"|"issue comment")
                verb="$1 $2"; [ "$2" = comment ] && verb="$verb $3"
                printf '%s' "$verb" > "$STUB_OUT/verb"
                while [ $# -gt 0 ]; do
                  case "$1" in
                    --title) printf '%s' "$2" > "$STUB_OUT/title"; shift ;;
                    --body) printf '%s' "$2" > "$STUB_OUT/body"; shift ;;
                  esac
                  shift
                done ;;
              *) echo "gh stub: unexpected call: $*" >&2; exit 1 ;;
            esac
            """))
    with open(os.path.join(stubs, "date"), "w", encoding="utf-8") as f:
        f.write(f"#!/bin/sh\necho {day}\n")     # the step's one `date -u +%Y-%m-%d`
    for name in ("gh", "date"):
        os.chmod(os.path.join(stubs, name), 0o755)

    def post(report, open_issue=""):
        """Run the step on `report`. Returns the gh verb, --title and --body it
        posted, as bytes; None for a call never made."""
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "linkcheck-report.txt"), "w", encoding="utf-8") as f:
                f.write(report)
            out = os.path.join(td, "gh-calls")
            os.mkdir(out)
            subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", src],
                           cwd=td, capture_output=True,
                           env=dict(env, PATH=stubs + os.pathsep + os.environ.get("PATH", ""),
                                    # the runner's locale, where `wc -m` counts characters
                                    LANG="C.UTF-8",
                                    STUB_OUT=out, STUB_OPEN_ISSUE=open_issue))
            return tuple(open(os.path.join(out, n), "rb").read()
                         if os.path.exists(os.path.join(out, n)) else None
                         for n in ("verb", "title", "body"))

    head = (f"The weekly full-site check found broken links on **{day}**.\n\nRun: {run_url}\n\n"
            "This issue auto-closes when the next run is clean.\n\n```\n")

    def v1290(report):
        """v1.29.0's body for `report`: what any body under the cap must still be, to the byte."""
        return (head + _fenced(report) + "\n```").encode()

    shape = re.compile(re.escape(head) + r"(.*)\n```\n\n\(truncated — (\d+) more rows; the full "
                       r"report is in the run log: " + re.escape(run_url) + r"\)", re.S)

    def capped(label, report, body):
        """What every cut body owes, whatever the report. Returns the rows it kept."""
        text = body.decode("utf-8", "replace") if body is not None else ""
        check(f"{label}: an issue body was posted", body is not None)
        check(f"{label}: …at most 60,000 bytes, so under GitHub's 65,536 characters",
              body is not None and len(body) <= 60000 and len(text) <= 65536)
        m = shape.fullmatch(text)
        check(f"{label}: …the v1.29.0 wrapper and fence, then a note of how many rows it left "
              "out and the run URL", m is not None)
        if m is None:
            return []
        return _cut_checks(label, report, m.group(1), int(m.group(2)), len(body), 60000)

    # (1) THE BUG: the site goes down mid-crawl. One row per dead sitemap page,
    #     ~180 KB of report, which v1.29.1 posted whole and GitHub refused.
    pages = [_page_url(i) for i in range(1500)]
    live = {p: [_ext_url(2 * i), _ext_url(2 * i + 1)] for i, p in enumerate(pages[:12])}
    down = {p: (404, 502, 0)[i % 3] for i, p in enumerate(pages)}     # 0: no response
    report = _report_of(linkcheck, pages, lambda u: (200, False, _html(live[u])) if u in live
                        else (down[u], False, ""), lambda u: (502, False))
    check("site down mid-crawl, 1,488 dead pages: the whole report is over GitHub's 65,536 "
          "characters (v1.29.1 posted no issue at all)", len(v1290(report).decode()) > 65536)
    verb, title, body = post(report)
    check("site down: it OPENS the issue, titled as before",
          verb == b"issue create" and title == b"Weekly link check: broken links found")
    got = capped("site down", report, body)
    check("site down: the dead pages come first; the 24 WARN rows printed above them wait",
          bool(got) and all(s.startswith("FATAL") for s, _ in got))
    verb, _, comment = post(report, open_issue="17")
    check("site down, an issue already open: it COMMENTS, with the same capped body",
          verb == b"issue comment 17" and comment == body)

    # (2) The report prints WARN first. A flood of flaky externals must not crowd
    #     out the broken links the issue is about.
    dead = [_page_url(i) for i in range(100)]
    hubs = {_page_url(100 + k): [_ext_url(j) for j in range(k, 630, 10)] for k in range(10)}
    waf = {_ext_url(j) for j in range(30)}
    report = _report_of(linkcheck, dead + list(hubs),
                        lambda u: (200, False, _html(hubs[u])) if u in hubs else (404, False, ""),
                        lambda u: (403, True) if u in waf else (500, False))
    want = _rows(_fenced(report))
    warn = [r for s, r in want if s.startswith("WARN")]
    check("WARN flood: 100 FATAL, 30 REVIEW and 600 WARN rows, the WARN ones printed first "
          "and over 60,000 bytes on their own",
          [len([r for s, r in want if _rank(s) == k]) for k in range(3)] == [100, 30, 600]
          and _rank(want[0][0]) == 2 and len("\n".join(warn).encode()) > 60000)
    got = capped("WARN flood", report, post(report)[2])
    kept = [len([r for s, r in got if _rank(s) == k]) for k in range(3)]
    check(f"WARN flood: every FATAL and REVIEW row is kept, the cut falls inside WARN "
          f"(kept {kept})", kept[:2] == [100, 30] and 0 < kept[2] < 600)

    # (3) The cap counts BYTES, as the trimmer does: a Greek report GitHub would
    #     count as under 60,000 characters is cut too, whatever the locale says.
    report = _report_of(linkcheck, [_page_url(i) for i in range(560)], lambda u: (404, False, ""))
    size = v1290(report)
    check("Greek report: under 60,000 characters, over 60,000 bytes",
          len(size.decode()) < 60000 < len(size))
    capped("Greek report", report, post(report)[2])

    # (4) A report that fits is posted exactly as v1.29.0 posted it, on both paths.
    report = _report_of(linkcheck, [_page_url(7), _page_url(8)],
                        lambda u: (404, False, "") if u == _page_url(7)
                        else (200, False, _html([_ext_url(1)])), lambda u: (500, False))
    check("small report: a FATAL row and a WARN row, Greek URLs",
          [_rank(s) for s, _ in _rows(_fenced(report))] == [2, 0])
    verb, _, body = post(report)
    check("small report: the new issue's body is v1.29.0's, byte for byte",
          verb == b"issue create" and body == v1290(report))
    verb, _, body = post(report, open_issue="17")
    check("small report, an issue already open: the comment is v1.29.0's, byte for byte",
          verb == b"issue comment 17" and body == v1290(report))
    verb, _, body = post("")
    check("a report with no summary line: v1.29.0's '(report unavailable — open the run "
          "log)' body", verb == b"issue create" and body == v1290(""))

    # (5) The boundary, both sides: n dead pages and one WARN row, a page's URL
    #     padded until the v1.29.0 body is exactly 60,000 bytes, then one byte more.
    #     One byte over costs the last row in posting order, the WARN one, and its
    #     section title must go with it.
    n, report, over = _at_the_cap(linkcheck, v1290, 60000)
    check("boundary: a real report built to a v1.29.0 body of exactly 60,000 bytes",
          len(v1290(report)) == 60000)
    check("boundary: exactly 60,000 bytes is posted whole, byte for byte",
          post(report)[2] == v1290(report))
    check("boundary: the same report one byte longer (60,001)", len(v1290(over)) == 60001)
    got = capped("60,001 bytes", over, post(over)[2])
    check(f"60,001 bytes: only the WARN row goes, its title with it; all {n} FATAL rows stay",
          len(got) == n and all(_rank(s) == 0 for s, _ in got))


def step_summary_checks(linkcheck, ay=None, action_path=None):
    """The crawl step's summary is still written when the report is huge (v1.29.3).

    GitHub refuses a step summary over 1 MiB: the upload is aborted with an error
    annotation, and the run shows no summary at all. Since v1.29.1 every dead
    sitemap page is a row of its own, so a site that went down mid-crawl lost its
    summary exactly when it had the most to say: v1.29.2's issue-body bug, one size
    up. Over 900,000 bytes the summary now gets the issue body's cut.

    The REAL crawl `run:` body is executed, out of action.yml (or `ay`), under
    GitHub's bash flags, with the env the step's own `env:` block declares and a
    stub crawler that prints a report the REAL linkcheck.main() wrote and exits as
    it would. `action_path` stands in for ${{ github.action_path }}: a mutation run
    points it at a broken fit-report.py.
    """
    print("\n# the step summary: under GitHub's 1 MiB, the issue body's cut (v1.29.3)")
    action_path = action_path or os.path.dirname(HERE)
    if ay is None:
        ay = open(os.path.join(action_path, "action.yml"), encoding="utf-8").read()
    fitter = os.path.join(action_path, "scripts", "fit-report.py")
    check("fit-report.py ships next to the crawler", os.path.exists(fitter))
    crawler = '"${{ github.action_path }}/scripts/linkcheck.py"'
    body = ay.split("      run: |\n        set -o pipefail\n")[1].split("\n    - name:")[0]
    body = textwrap.dedent("        set -o pipefail\n" + body)
    check("the crawl step's run: body was extracted, and runs as written once the crawler is "
          "stubbed (no other ${{ }} in it)", crawler in body and "${{" not in body.replace(crawler, ""))

    repo, run_id = "example-org/example-site", "33911783576"
    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"

    def step_env(decision, workspace):
        return _step_env(ay, "Crawl + check every link & image", {
            "inputs.host": "localhost", "inputs.workers": "2", "inputs.verify-token": "",
            "inputs.allow-file": "scripts/linkcheck-allow.txt", "github.workspace": workspace,
            "steps.floor.outputs.decision": decision, "github.action_path": action_path,
            "github.repository": repo, "github.server_url": "https://github.com",
            "github.run_id": run_id})

    declared, unknown = step_env("", HERE)
    check("the crawl step's env: block evaluates: each ${{ }} in it is one this leg stands in for",
          bool(declared) and not unknown)

    def crawl(report, decision="", fit=None):
        """Run the step on a stub crawler that prints `report` and exits as the real
        one does after printing it. Returns its exit code, then as bytes its stdout,
        its outputs, its summary (None if it wrote none) and linkcheck-report.txt."""
        with tempfile.TemporaryDirectory() as td:
            printed = os.path.join(td, "stub-report.txt")
            with open(printed, "w", encoding="utf-8") as f:
                f.write(report)
            rc = 1 if "\nlink check: FAIL" in report else 2 if "\nlink check: CRASH" in report else 0
            stub = os.path.join(td, "stub-linkcheck.py")
            with open(stub, "w", encoding="utf-8") as f:
                f.write(f"import sys\nsys.stdout.buffer.write(open({printed!r}, 'rb').read())\n"
                        f"sys.exit({rc})\n")
            open(os.path.join(td, "pages.txt"), "w").close()
            env = dict(step_env(decision, td)[0], PATH=os.environ.get("PATH", ""),
                       LANG="C.UTF-8",   # the runner's locale, where `wc -m` counts characters
                       GITHUB_OUTPUT=os.path.join(td, "gh_out"),
                       GITHUB_STEP_SUMMARY=os.path.join(td, "gh_sum"))
            if fit is not None:
                env["FIT_REPORT"] = fit
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                body.replace(crawler, f'"{stub}"')],
                               cwd=td, capture_output=True, env=env)

            def read(name):
                p = os.path.join(td, name)
                return open(p, "rb").read() if os.path.exists(p) else None
            return (r.returncode, r.stdout, read("gh_out") or b"", read("gh_sum"),
                    read("linkcheck-report.txt"))

    head = "## Weekly full-site link & image check\n\n```\n"

    def v1292(report):
        """v1.29.2's summary of `report`: what any summary under the cap must still be,
        to the byte."""
        return (head + report + "```\n").encode()

    shape = re.compile(re.escape(head) + r"(.*)\n```\n\n\(truncated — (\d+) more rows; the full "
                       r"report is in the run log: " + re.escape(run_url) + r"\)\n", re.S)

    def summarized(label, report, summary):
        """What every cut summary owes, whatever the report. Returns the rows it kept."""
        text = summary.decode("utf-8", "replace") if summary is not None else ""
        check(f"{label}: a step summary was written", bool(summary))
        check(f"{label}: …at most 900,000 bytes, so under GitHub's 1 MiB",
              summary is not None and len(summary) <= 900000)
        m = shape.fullmatch(text)
        check(f"{label}: …the v1.29.2 heading and fence, then a note of how many rows it left "
              "out and the run URL", m is not None)
        if m is None:
            return []
        return _cut_checks(label, report, m.group(1), int(m.group(2)), len(summary), 900000)

    # (1) THE BUG: the site goes down mid-crawl, one row per dead sitemap page, over
    #     1 MiB of summary, which v1.29.2 wrote whole and GitHub refused.
    pages = [_page_url(i) for i in range(9000)]
    live = {p: [_ext_url(2 * i), _ext_url(2 * i + 1)] for i, p in enumerate(pages[:12])}
    down = {p: (404, 502, 0)[i % 3] for i, p in enumerate(pages)}     # 0: no response
    down_report = _report_of(linkcheck, pages, lambda u: (200, False, _html(live[u])) if u in live
                             else (down[u], False, ""), lambda u: (502, False))
    check("site down mid-crawl, 8,988 dead pages: the v1.29.2 summary is over GitHub's 1 MiB "
          "(the run showed no summary at all)", len(v1292(down_report)) > 1048576)
    rc, _, outputs, summary, left = crawl(down_report)
    check("site down: the step still publishes `broken` and exits 1",
          rc == 1 and b"rc=1\nverdict=broken\n" in outputs)
    got = summarized("site down", down_report, summary)
    check("site down: the dead pages come first; the 24 WARN rows printed above them wait",
          bool(got) and all(s.startswith("FATAL") for s, _ in got))
    check("site down: linkcheck-report.txt is left whole, for the issue step",
          left == down_report.encode())

    # (2) The report prints WARN first. A flood of flaky externals must not crowd
    #     out the broken links.
    dead = [_page_url(i) for i in range(100)]
    hubs = {_page_url(100 + k): [_ext_url(j) for j in range(k, 6030, 10)] for k in range(10)}
    waf = {_ext_url(j) for j in range(30)}
    report = _report_of(linkcheck, dead + list(hubs),
                        lambda u: (200, False, _html(hubs[u])) if u in hubs else (404, False, ""),
                        lambda u: (403, True) if u in waf else (500, False))
    want = _rows(_fenced(report))
    warn = [r for s, r in want if s.startswith("WARN")]
    check("WARN flood: 100 FATAL, 30 REVIEW and 6,000 WARN rows, the WARN ones printed first "
          "and over 900,000 bytes on their own",
          [len([r for s, r in want if _rank(s) == k]) for k in range(3)] == [100, 30, 6000]
          and _rank(want[0][0]) == 2 and len("\n".join(warn).encode()) > 900000)
    got = summarized("WARN flood", report, crawl(report)[3])
    kept = [len([r for s, r in got if _rank(s) == k]) for k in range(3)]
    check(f"WARN flood: every FATAL and REVIEW row is kept, the cut falls inside WARN "
          f"(kept {kept})", kept[:2] == [100, 30] and 0 < kept[2] < 6000)

    # (3) A clean run can be over the cap too: nothing broken, 6,030 flaky externals.
    clean = _report_of(linkcheck, list(hubs), lambda u: (200, False, _html(hubs[u])),
                       lambda u: (500, False))
    check("clean but oversized: 6,030 WARN rows and no FATAL, so PASS, over 900,000 bytes",
          "\nlink check: PASS" in clean and len(v1292(clean)) > 900000)
    rc, _, outputs, summary, _ = crawl(clean)
    check("clean but oversized: the step publishes `clean` and exits 0",
          rc == 0 and b"rc=0\nverdict=clean\n" in outputs)
    summarized("clean but oversized", clean, summary)

    # (4) The cut is a formatter, not a gate: if it faults, the step keeps its own
    #     exit code. Asserted by crashing a COPY of the real fit-report.py.
    src = open(fitter, encoding="utf-8").read() if os.path.exists(fitter) else ""
    anchor = "def main():"
    check(f"fitter fault-injection anchor {anchor!r} still present", anchor in src)
    with tempfile.TemporaryDirectory() as td:
        broken = os.path.join(td, "fit-report.py")
        with open(broken, "w", encoding="utf-8") as f:
            f.write(src.replace(anchor, anchor + "\n    raise RuntimeError('injected fitter fault')"))
        rc, out, outputs, summary, _ = crawl(clean, fit=broken)
    check("the cut faults on a clean run: the step still exits 0 and publishes `clean` "
          "(a summary must never cost the step its exit code)",
          rc == 0 and b"rc=0\nverdict=clean\n" in outputs)
    check("…it says so in a ::warning::, and the run log above it holds every row",
          b"::warning::linkcheck: the report is over the step summary's limit" in out
          and clean.encode() in out)
    check("…and it writes no summary rather than one GitHub would refuse", not summary)

    # (5) A collapsed crawl's notice says the verdict above it is void. The report
    #     ends with it, so cut from the end it would be the first thing to go.
    rc, _, outputs, summary, left = crawl(down_report, decision="collapsed")
    check("collapsed and oversized: the step publishes `fault` and exits 2",
          rc == 2 and b"rc=2\nverdict=fault\n" in outputs)
    summarized("collapsed and oversized", (left or b"").decode(), summary)
    check("collapsed and oversized: the CRAWL SIZE COLLAPSED notice survives the cut, right "
          "under the verdict it voids", summary is not None and re.search(
              rb"\nlink check: FAIL\n\n=== CRAWL SIZE COLLAPSED", summary) is not None)

    # (6) The cap counts BYTES, as GitHub's limit does: a Greek report under 900,000
    #     characters is cut too, whatever the locale says.
    report = _report_of(linkcheck, [_page_url(i) for i in range(7500)], lambda u: (404, False, ""))
    check("Greek report: under 900,000 characters, over 900,000 bytes",
          len(v1292(report).decode()) < 900000 < len(v1292(report)))
    summarized("Greek report", report, crawl(report)[3])

    # (7) A summary that fits is written exactly as v1.29.2 wrote it, whatever it is.
    report = _report_of(linkcheck, [_page_url(7), _page_url(8)],
                        lambda u: (404, False, "") if u == _page_url(7)
                        else (200, False, _html([_ext_url(1)])), lambda u: (500, False))
    check("small report: a FATAL row and a WARN row, Greek URLs",
          [_rank(s) for s, _ in _rows(_fenced(report))] == [2, 0])
    rc, _, _, summary, _ = crawl(report)
    check("small report: the summary is v1.29.2's, byte for byte",
          rc == 1 and summary == v1292(report))
    rc, _, _, summary, left = crawl(report, decision="collapsed")
    check("small report, a collapsed crawl: v1.29.2's summary, the notice in it, byte for byte",
          rc == 2 and left is not None and summary == v1292(left.decode())
          and b"CRAWL SIZE COLLAPSED" in summary)
    with tempfile.TemporaryDirectory() as td:     # what the real crawler prints when it faults
        faulty = os.path.join(td, "linkcheck.py")
        with open(faulty, "w", encoding="utf-8") as f:
            f.write(open(os.path.join(HERE, "linkcheck.py"), encoding="utf-8").read().replace(
                "def main():", "def main():\n    raise RuntimeError('injected crawler fault')", 1))
        crashed = subprocess.run([sys.executable, faulty, "-"], input="", capture_output=True,
                                 text=True, env={"PATH": os.environ.get("PATH", ""),
                                                 "LINKCHECK_HOST": "localhost"}).stdout
    rc, _, _, summary, _ = crawl(crashed)
    check("a crashed crawler's output, no summary line in it: v1.29.2's summary, byte for byte",
          "linkcheck CRASHED" in crashed and rc == 2 and summary == v1292(crashed))

    # (8) The boundary, both sides: n dead pages and one WARN row, a page's URL
    #     padded until the v1.29.2 summary is exactly 900,000 bytes, then one byte
    #     more. One byte over costs the WARN row, and its section title with it.
    n, report, over = _at_the_cap(linkcheck, v1292, 900000)
    check("boundary: a real report built to a v1.29.2 summary of exactly 900,000 bytes",
          len(v1292(report)) == 900000)
    check("boundary: exactly 900,000 bytes is written whole, byte for byte",
          crawl(report)[3] == v1292(report))
    check("boundary: the same report one byte longer (900,001)", len(v1292(over)) == 900001)
    got = summarized("900,001 bytes", over, crawl(over)[3])
    check(f"900,001 bytes: only the WARN row goes, its title with it; all {n} FATAL rows stay",
          len(got) == n and all(_rank(s) == 0 for s, _ in got))


if __name__ == "__main__":
    main()
