#!/usr/bin/env node
// selftest-fixtures.mjs — two loopback origins for a11y-audit's real-install self-test (v1.22.0).
//
//   node selftest-fixtures.mjs serve <requests.log> <ports.json>
//   node selftest-fixtures.mjs check <requests.log> <canary> <path,path,...> [--chrome-major N]
//
// serve: origin A (the audited site) and origin B (a third party, and a redirect target) on
// 127.0.0.1, each on its own port, so A and B are different origins. Every request is appended to
// requests.log as one JSON line: the server, the path, the X-Verify-Source it carried and the
// User-Agent. ports.json is written once both listen: {"A": <port>, "B": <port>}.
//   A /sitemap.xml  lists A /page
//   A /page         a clean page that loads a stylesheet, an image and a script from A and from B,
//                   and fetch()es one URL on each
//   A /redirect     302 to B /landing, a clean page with an image of its own
//   A /violation    an <img> with no alt: two errors (axe image-alt, HTML_CodeSniffer H37)
//
// check: the verify-token went where a11y-audit says it goes and nowhere else. Every request that
// carried an X-Verify-Source is on A, at one of the listed paths, and carries exactly the canary;
// every listed path was requested with it; and, so that "nowhere else" was actually observed, the
// requests a listed page makes without the token did happen: /page's subresources and fetches on
// both origins, /redirect's landing on B. With --chrome-major, each tokened navigation (every
// listed path but /sitemap.xml, which audit.sh fetches with curl) came from HeadlessChrome/<N>.
// Prints one line per assertion; exits 1 when any fails.
import fs from 'node:fs';
import http from 'node:http';

const [mode, ...args] = process.argv.slice(2);

function serve(logFile, portsFile) {
  const log = fs.openSync(logFile, 'a');
  const ports = {};
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
  const page = (body, head = '') => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>a11y-audit fixture</title>${head}</head><body><main><h1>Fixture</h1>${body}</main></body></html>`;
  const routes = {
    A: (A, B) => ({
      '/sitemap.xml': ['application/xml', `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${A}/page</loc></url></urlset>`],
      '/page': ['text/html', page(
        `<p>A clean page.</p><img src="/same.png" alt="a pixel"><img src="${B}/cross.png" alt="another pixel">`
        + `<script src="/same.js"></script><script src="${B}/cross.js"></script>`
        + `<script>fetch('/same-fetch').catch(() => {}); fetch('${B}/cross-fetch').catch(() => {});</script>`,
        `<link rel="stylesheet" href="/same.css"><link rel="stylesheet" href="${B}/cross.css">`)],
      '/redirect': [302, `${B}/landing`],
      '/violation': ['text/html', page('<img src="/same.png">')],
      '/same.css': ['text/css', 'p { color: #000 }'],
      '/same.png': ['image/png', png],
      '/same.js': ['text/javascript', '/* first party */'],
      '/same-fetch': ['text/plain', 'ok'],
    }),
    B: () => ({
      '/landing': ['text/html', page('<p>The redirect landed.</p><img src="/cross-landing.png" alt="a pixel">')],
      '/cross.css': ['text/css', 'h1 { color: #000 }'],
      '/cross.png': ['image/png', png],
      '/cross-landing.png': ['image/png', png],
      '/cross.js': ['text/javascript', '/* third party */'],
      '/cross-fetch': ['text/plain', 'ok'],
    }),
  };
  const handler = (name) => (req, res) => {
    const h = req.headers;
    fs.writeSync(log, `${JSON.stringify({ server: name, method: req.method, path: req.url, token: h['x-verify-source'] ?? null, ua: h['user-agent'] ?? '' })}\n`);
    const A = `http://127.0.0.1:${ports.A}`, B = `http://127.0.0.1:${ports.B}`;
    const r = routes[name](A, B)[req.url];
    if (!r) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found'); return; }
    if (r[0] === 302) { res.writeHead(302, { location: r[1] }); res.end(); return; }
    res.writeHead(200, { 'content-type': r[0], 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
    res.end(r[1]);
  };
  let listening = 0;
  for (const name of ['A', 'B']) {
    const s = http.createServer(handler(name));
    s.listen(0, '127.0.0.1', () => {
      ports[name] = s.address().port;
      if (++listening === 2) fs.writeFileSync(portsFile, JSON.stringify(ports));
    });
  }
}

function check(logFile, canary, list, rest) {
  const expected = list.split(',').filter(Boolean);
  const major = rest[0] === '--chrome-major' ? rest[1] : '';
  const reqs = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  let failed = 0;
  const say = (s) => fs.writeSync(1, `${s}\n`);
  const assert = (desc, cond, detail = '') => {
    if (cond) say(`ok   ${desc}`);
    else { failed++; say(`::error title=a11y-audit token scope::${desc}${detail ? ` — ${detail}` : ''}`); }
  };
  const show = (r) => `${r.server} ${r.method} ${r.path} X-Verify-Source=${r.token === canary ? '<canary>' : JSON.stringify(r.token)}`;
  const tokened = reqs.filter((r) => r.token !== null);
  const stray = tokened.filter((r) => !(r.server === 'A' && expected.includes(r.path) && r.token === canary));
  assert(`the token went nowhere but the audited navigations and the sitemap (${reqs.length} requests, ${tokened.length} with it)`,
    stray.length === 0, stray.map(show).join('; '));
  for (const p of expected) {
    assert(`A ${p} was requested with exactly the canary`, reqs.some((r) => r.server === 'A' && r.path === p && r.token === canary));
  }
  const seen = (server, path) => reqs.some((r) => r.server === server && r.path === path);
  const need = [];
  if (expected.includes('/page')) {
    need.push(['A', '/same.css'], ['A', '/same.png'], ['A', '/same.js'], ['A', '/same-fetch'],
      ['B', '/cross.css'], ['B', '/cross.png'], ['B', '/cross.js'], ['B', '/cross-fetch']);
  }
  if (expected.includes('/redirect')) need.push(['B', '/landing'], ['B', '/cross-landing.png']);
  for (const [server, path] of need) {
    assert(`${server} ${path} was requested (so its missing token was observed, not assumed)`, seen(server, path));
  }
  if (major) {
    const navs = tokened.filter((r) => r.path !== '/sitemap.xml');
    assert(`each audited navigation came from HeadlessChrome/${major} (the pinned build)`,
      navs.length > 0 && navs.every((r) => r.ua.includes(`HeadlessChrome/${major}.`)),
      [...new Set(navs.map((r) => r.ua))].join(' | '));
  }
  process.exitCode = failed ? 1 : 0;
}

if (mode === 'serve' && args.length === 2) serve(...args);
else if (mode === 'check' && args.length >= 3) check(args[0], args[1], args[2], args.slice(3));
else {
  fs.writeSync(2, 'usage: selftest-fixtures.mjs serve <requests.log> <ports.json> | check <requests.log> <canary> <path,...> [--chrome-major N]\n');
  process.exitCode = 2;
}
