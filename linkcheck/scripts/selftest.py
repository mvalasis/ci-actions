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

Run: `python3 linkcheck/scripts/selftest.py`  (exit 0 = pass, 1 = a leak/regression)
"""
import atexit
import http.server
import importlib.util
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
    html = linkcheck.fetch_html(f"http://localhost:{INT_PORT}/to-external")
    check("fetch_html int→ext: returned the final external body", "EXTERNAL-LANDING" in html)
    check("fetch_html int→ext: external host did NOT get the token", TOKEN not in _tokens("EXT"))
    check("fetch_html int→ext: internal hop carried the token", TOKEN in _tokens("INT"))

    # 4) direct external fetch never carries the token.
    REC.clear()
    linkcheck.status(f"http://127.0.0.1:{EXT_PORT}/int-landing")
    check("status direct-external: token never sent", TOKEN not in _tokens("EXT"))

    # 4b) fetch_html transparently decompresses a Content-Encoding: gzip body
    #     (guards the --compressed flag) so extract() still sees the links.
    html_gz = linkcheck.fetch_html(f"http://localhost:{INT_PORT}/gz-html")
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
    check("fetch_html redirect-loop: returns empty",
          linkcheck.fetch_html(f"http://localhost:{INT_PORT}/loop") == "")

    # 5) host predicate: subdomains internal, look-alikes external.
    check("is_internal(localhost)", linkcheck.is_internal("http://localhost/x"))
    check("is_internal(sub.localhost)", linkcheck.is_internal("http://a.localhost/x"))
    check("is_internal(127.0.0.1) is False", not linkcheck.is_internal("http://127.0.0.1/x"))
    check("is_internal(localhost.evil.com) is False",
          not linkcheck.is_internal("http://localhost.evil.com/x"))

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

    print()
    if FAILS:
        print(f"FAIL — {len(FAILS)} check(s) failed: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("PASS — token scoping, the hostile-sitemap refusals, crash-guard attribution "
          "and the crawl-size floor hold.")


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


def crawl_floor_checks():
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

    # ===== THE OVERRIDE, EXECUTED ===========================================
    # Everything above grades a pure function. This grades action.yml: extract the
    # real crawl `run:` body and run it under `bash --noprofile --norc -eo
    # pipefail` with a stub crawler, exactly as GitHub would.
    ay = open(os.path.join(HERE, "..", "action.yml"), encoding="utf-8").read()
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


if __name__ == "__main__":
    main()
