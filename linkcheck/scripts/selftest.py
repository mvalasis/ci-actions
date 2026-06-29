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

Run: `python3 linkcheck/scripts/selftest.py`  (exit 0 = pass, 1 = a leak/regression)
"""
import http.server
import importlib.util
import os
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


FAILS = []


def check(name, cond):
    print(f"  {'✅' if cond else '❌'} {name}")
    if not cond:
        FAILS.append(name)


def main():
    global INT_PORT, EXT_PORT
    int_srv, INT_PORT = _start("INT")
    ext_srv, EXT_PORT = _start("EXT")

    # Env must be set BEFORE importing the scripts — they read it at module load.
    os.environ["LINKCHECK_HOST"] = "localhost"
    os.environ["VERIFY_HOMEPAGE_TOKEN"] = TOKEN
    os.environ["LINKCHECK_WORKERS"] = "2"
    linkcheck = _load("linkcheck", "linkcheck.py")
    sitemap = _load("sitemap_urls", "sitemap-urls.py")

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

    int_srv.shutdown()
    ext_srv.shutdown()

    print()
    if FAILS:
        print(f"FAIL — {len(FAILS)} check(s) failed: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("PASS — token never reaches a cross-origin host.")


if __name__ == "__main__":
    main()
