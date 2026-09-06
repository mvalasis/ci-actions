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
import re
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

    int_srv.shutdown()
    ext_srv.shutdown()

    crash_guard_checks()
    crawl_floor_checks()

    print()
    if FAILS:
        print(f"FAIL — {len(FAILS)} check(s) failed: {', '.join(FAILS)}")
        raise SystemExit(1)
    print("PASS — token scoping, crash-guard attribution and the crawl-size floor hold.")


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
