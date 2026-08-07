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

    crash_guard_checks()

    print()
    if FAILS:
        print(f"FAIL — {len(FAILS)} check(s) failed: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("PASS — token scoping + crash-guard attribution hold.")


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
    check("the crawl step publishes its rc as a step output", 'echo "rc=$rc" >> "$GITHUB_OUTPUT"' in ay)
    check("open-issue keys on rc == '1' (a real link verdict)",
          "steps.crawl.outputs.rc == '1'" in open_step)
    check("open-issue no longer keys on failure() — the false-issue bug",
          "failure()" not in open_step)
    check("close-issue keys on rc == '0' (verified clean), not success()",
          "steps.crawl.outputs.rc == '0'" in close_step and "success()" not in close_step)


if __name__ == "__main__":
    main()
