// Offline self-test for the seo-aeo check engine. No network — feeds fixture HTML /
// robots.txt / llms.txt to the pure analyzers and asserts the findings; then runs the real
// check.mjs against a LOCAL node:http server (127.0.0.1 only) to assert what reaches the job
// log. Run locally or in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SEV, T0_CHECKS, T1_CHECKS, analyzePage, analyzeRobots, analyzeLlms, analyzeSitemap, analyzeRedirects,
  collectLdNodes, typesOf, safe, escapeData, escapeProperty, annotation, annotations,
} from './checks.mjs';

let failed = 0;
const ids = (fs) => fs.map((x) => x.id);
const sevOf = (fs, id) => fs.filter((x) => x.id === id).map((x) => x.sev);
function check(name, cond, detail = '') { if (cond) { console.log(`  ✅ ${name}`); } else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

const HEAD = (extra = '') => `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Clean Page — Brand</title>
<meta name="description" content="A perfectly reasonable meta description that sits comfortably within the fifty to one hundred sixty character window for snippets.">
<link rel="canonical" href="https://example.com/page/">
<meta property="og:title" content="Clean Page"><meta property="og:type" content="website">
<meta property="og:url" content="https://example.com/page/"><meta property="og:image" content="https://example.com/i.png">
<meta name="twitter:card" content="summary_large_image">
${extra}
</head><body><main><h1>Clean visible heading</h1><h2>Sub</h2><img src="a.png" alt="a"></main></body></html>`;

const P = (html, opts = {}) => analyzePage({ requestUrl: opts.url || 'https://example.com/page/', finalUrl: opts.finalUrl || opts.url || 'https://example.com/page/', status: opts.status ?? 200, headers: opts.headers || {}, html });

console.log('\n# page analyzer');

// 1. clean homepage is pristine (low false-positive rate is the whole point)
{
  const fs = P(HEAD(`<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Brand","url":"https://example.com/","sameAs":["https://www.linkedin.com/company/brand"]},{"@type":"WebSite","url":"https://example.com/"}]}</script>`), { url: 'https://example.com/', finalUrl: 'https://example.com/' }).findings;
  const noisy = fs.filter((x) => x.sev !== SEV.OK);
  check('clean page → zero crit/warn/info', noisy.length === 0, `got: ${JSON.stringify(noisy.map((x) => x.id + ':' + x.sev))}`);
}

// 2. FALSE-POSITIVE fixes — title buried in a comment / real missing title → CRITICAL
{
  const fs = P('<!doctype html><html lang="en"><head><!-- <title>Old</title> --></head><body><h1>Hi</h1></body></html>').findings;
  check('commented-out title → http? title-present CRITICAL', sevOf(fs, 'title-present').includes(SEV.CRIT), JSON.stringify(ids(fs)));
}
// 3. title in <body> (not head) → CRITICAL
{
  const fs = P('<!doctype html><html lang="en"><head></head><body><title>Body Title</title><h1>Hi</h1></body></html>').findings;
  check('title only in <body> → title-present CRITICAL', sevOf(fs, 'title-present').includes(SEV.CRIT));
}
// 4. FALSE-NEGATIVE fixes — multiline <title> and <h1 \n attrs> must NOT report missing
{
  const fs = P(`<!doctype html><html lang="en"><head>\n<title>\n  Wrapped Title\n</title>\n<meta name="description" content="${'x'.repeat(80)}"><link rel=canonical href="https://example.com/page/"><meta property="og:title" content="a"><meta property="og:type" content="b"><meta property="og:url" content="c"><meta property="og:image" content="https://e/i.png"><meta name=viewport content="width=device-width"></head><body><h1\n  class="hero">\n  Multiline H1\n</h1></body></html>`).findings;
  check('multiline title → present (no false negative)', !sevOf(fs, 'title-present').includes(SEV.CRIT));
  check('multiline h1 → present (no false negative)', !sevOf(fs, 'h1-present').includes(SEV.CRIT));
}
// 5. empty/textless h1 → CRITICAL; h1 only inside <template> ignored
{
  const fs = P('<!doctype html><html lang="en"><head><title>T</title></head><body><template><h1>tmpl</h1></template><h1>   </h1></body></html>').findings;
  check('empty h1 + template h1 → h1-present CRITICAL', sevOf(fs, 'h1-present').includes(SEV.CRIT));
}
// 6. noindex via meta robots → WARN noindex (NOT critical by default)
{
  const fs = P(HEAD('<meta name="robots" content="noindex,follow">')).findings;
  check('meta noindex → WARN noindex', sevOf(fs, 'noindex').includes(SEV.WARN));
  check('noindex is NOT critical by default', !sevOf(fs, 'noindex').includes(SEV.CRIT));
}
// 7. noindex via X-Robots-Tag HEADER → WARN noindex (invisible to a body parser)
{
  const fs = P(HEAD(), { headers: { 'x-robots-tag': 'noindex' } }).findings;
  check('X-Robots-Tag header noindex → WARN noindex', sevOf(fs, 'noindex').includes(SEV.WARN));
}
// 8. non-200 status → CRITICAL http-200 and short-circuits (no double-grading the 404 body)
{
  const fs = P('<html><head><title>404</title></head><body><h1>Not found</h1></body></html>', { status: 404 }).findings;
  check('HTTP 404 → http-200 CRITICAL', sevOf(fs, 'http-200').includes(SEV.CRIT));
  check('404 short-circuits (no title/h1 findings)', !ids(fs).includes('title-present') && !ids(fs).includes('h1-present'));
}
// 9. invalid JSON-LD → WARN jsonld-valid (parsed, not grepped)
{
  const fs = P(HEAD('<script type="application/ld+json">{ broken, }</script>')).findings;
  check('invalid ld+json → WARN jsonld-valid', sevOf(fs, 'jsonld-valid').includes(SEV.WARN));
}
// 10. canonical: relative href → WARN canonical-valid; cross-host → WARN
{
  const fs = P('<!doctype html><html lang=en><head><title>T</title><link rel=canonical href="/"></head><body><h1>h</h1></body></html>').findings;
  check('relative canonical → WARN canonical-valid', sevOf(fs, 'canonical-valid').includes(SEV.WARN));
}
// 11. @graph Organization on homepage → no jsonld-type warn
{
  const fs = P(HEAD('<script type="application/ld+json">{"@graph":[{"@type":"Organization","name":"x"}]}</script>'), { url: 'https://example.com/', finalUrl: 'https://example.com/' }).findings;
  check('homepage @graph Organization → no jsonld-type warn', !ids(fs).includes('jsonld-type'), JSON.stringify(ids(fs)));
}
// 12. FAQPage present → INFO (retired rich result), never WARN
{
  const fs = P(HEAD('<script type="application/ld+json">{"@type":"FAQPage","mainEntity":[{"@type":"Question","name":"q","acceptedAnswer":{"@type":"Answer","text":"a"}}]}</script>')).findings;
  check('FAQPage → INFO jsonld-retired', sevOf(fs, 'jsonld-retired').includes(SEV.INFO));
}

console.log('\n# robots.txt analyzer');
// 13. blanket Disallow + AI bots
{
  const r = analyzeRobots({ status: 200, body: 'User-agent: *\nDisallow: /\n' });
  check('blanket Disallow:/ → WARN robots-txt', sevOf(r.findings, 'robots-txt').includes(SEV.WARN));
}
{
  const r = analyzeRobots({ status: 200, body: 'Sitemap: https://e/sitemap.xml\nUser-agent: *\nAllow: /\nUser-agent: PerplexityBot\nDisallow: /\nUser-agent: GPTBot\nDisallow: /\n' });
  check('answer bot (PerplexityBot) blocked → WARN ai-crawler-allowlist', sevOf(r.findings, 'ai-crawler-allowlist').includes(SEV.WARN));
  check('training bot (GPTBot) blocked → INFO ai-crawler-allowlist', sevOf(r.findings, 'ai-crawler-allowlist').includes(SEV.INFO));
  check('robots with Sitemap: directive → no robots-sitemap-directive warn', !ids(r.findings).includes('robots-sitemap-directive'));
}
{
  const r = analyzeRobots({ status: 200, body: 'User-agent: *\nAllow: /\n' });
  check('robots 200 WITHOUT Sitemap: directive → WARN robots-sitemap-directive (T1 promotable)', sevOf(r.findings, 'robots-sitemap-directive').includes(SEV.WARN));
}
{
  const r = analyzeRobots({ status: 404, body: '' });
  check('robots 404 → INFO robots-txt (valid per RFC, not the promotable WARN)', sevOf(r.findings, 'robots-txt').includes(SEV.INFO) && !sevOf(r.findings, 'robots-txt').includes(SEV.WARN));
}

console.log('\n# llms.txt analyzer');
check('llms.txt HTML soft-404 → WARN', sevOf(analyzeLlms({ status: 200, body: '<!doctype html><html>...' }), 'llms-txt').includes(SEV.WARN));
check('llms.txt missing → WARN', sevOf(analyzeLlms({ status: 404, body: '' }), 'llms-txt').includes(SEV.WARN));
{
  const good = analyzeLlms({ status: 200, body: '# Project\n\n> A short summary.\n\n## Docs\n- [Guide](https://e/g)\n' });
  check('well-formed llms.txt → OK, no structure warn', sevOf(good, 'llms-txt').includes(SEV.OK) && !good.some((x) => x.id === 'llms-structure' && x.sev === SEV.WARN));
}

console.log('\n# sitemap + redirect analyzers');
check('non-xml sitemap → WARN', analyzeSitemap({ status: 200, body: '<html>nope' }).sev === SEV.WARN);
check('xml sitemap → OK', analyzeSitemap({ status: 200, body: '<urlset><url><loc>https://e/</loc></url></urlset>' }).sev === SEV.OK);
{
  const loop = analyzeRedirects([{ label: 'host', host: 'e', variant: 'https://e/', chain: [{ url: 'https://e/', status: 301, location: 'https://e/x' }, { url: 'https://e/x', status: 301, location: 'https://e/' }, { url: 'https://e/', status: 301 }] }]);
  check('redirect loop → WARN redirect-consistency', sevOf(loop, 'redirect-consistency').includes(SEV.WARN));
  const httpNoUpgrade = analyzeRedirects([{ label: 'http', host: 'e', variant: 'http://e/', chain: [{ url: 'http://e/', status: 200 }] }]);
  check('http serves 200 (no https upgrade) → WARN', sevOf(httpNoUpgrade, 'redirect-consistency').includes(SEV.WARN));
}

console.log('\n# review-fix guards (regressions from the adversarial review)');
const Pin = (h, o) => P(h, o).findings; // inline-fixture page findings
// viewport: only zoom <2× is a smell — maximum-scale=10 must NOT fire
check('viewport maximum-scale=10 → NOT flagged', !ids(Pin('<html lang=en><head><title>T</title><meta name=viewport content="width=device-width, maximum-scale=10"></head><body><h1>h</h1></body></html>')).includes('viewport'));
check('viewport maximum-scale=1 → flagged', sevOf(Pin('<html lang=en><head><title>T</title><meta name=viewport content="width=device-width, maximum-scale=1"></head><body><h1>h</h1></body></html>'), 'viewport').includes(SEV.WARN));
// robots: exact product-token match — no substring collisions
{
  const r = analyzeRobots({ status: 200, body: 'User-agent: Bing\nDisallow: /\nUser-agent: Googlebot-News\nDisallow: /\nUser-agent: *\nAllow: /\n' });
  check('robots: "Bing" group does NOT block Bingbot', !r.findings.some((x) => /Bingbot/.test(x.msg)));
  check('robots: "Googlebot-News" group does NOT block Googlebot', !r.findings.some((x) => x.id === 'search-engine-blocked'));
}
check('classic search engine blocked → search-engine-blocked WARN (not ai-crawler)', sevOf(analyzeRobots({ status: 200, body: 'User-agent: Googlebot\nDisallow: /\n' }).findings, 'search-engine-blocked').includes(SEV.WARN));
// og-core no longer requires og:type
check('og-core without og:type → not flagged', !ids(Pin('<html lang=en><head><title>T</title><meta name=viewport content="width=device-width"><meta property="og:title" content=a><meta property="og:url" content=b><meta property="og:image" content="https://e/i.png"></head><body><h1>h</h1></body></html>')).includes('og-core'));
// placeholder/length: bare "Home"/"Contact" are valid; only true placeholders fire
check('title "Home" → not placeholder-flagged', !ids(Pin('<html lang=en><head><title>Home</title></head><body><h1>h</h1></body></html>')).includes('title-length'));
check('title "Contact" (7 chars) → not flagged (no <15 floor)', !ids(Pin('<html lang=en><head><title>Contact</title></head><body><h1>h</h1></body></html>')).includes('title-length'));
check('title "Untitled" → still placeholder-flagged', sevOf(Pin('<html lang=en><head><title>Untitled</title></head><body><h1>h</h1></body></html>'), 'title-length').includes(SEV.WARN));
// collectLdNodes retains a typed parent that itself carries @graph
{
  const types = new Set(collectLdNodes({ '@type': 'WebPage', '@graph': [{ '@type': 'Organization' }] }).flatMap(typesOf));
  check('collectLdNodes keeps parent WebPage + nested Organization', types.has('WebPage') && types.has('Organization'));
}
// meta-description: empty first tag must not mask a valid second
check('meta-description: empty first ignored, valid second wins', !ids(Pin('<html lang=en><head><title>T</title><meta name=description content=""><meta name=description content="A valid description long enough to be reasonable for a snippet here today."></head><body><h1>h</h1></body></html>')).includes('meta-description'));
// entity sameAs (AEO) — homepage-scoped
check('homepage Organization without sameAs → entity-sameas WARN', sevOf(Pin('<html lang=en><head><title>T</title><script type="application/ld+json">{"@type":"Organization","name":"x"}</script></head><body><h1>h</h1></body></html>', { url: 'https://e/', finalUrl: 'https://e/' }), 'entity-sameas').includes(SEV.WARN));
check('homepage Organization WITH sameAs → no entity-sameas', !ids(Pin('<html lang=en><head><title>T</title><script type="application/ld+json">{"@type":"Organization","name":"x","sameAs":["https://x.com/p"]}</script></head><body><h1>h</h1></body></html>', { url: 'https://e/', finalUrl: 'https://e/' })).includes('entity-sameas'));

console.log('\n# exhaustiveness gaps closed');
// charset
check('missing <meta charset> → WARN charset', sevOf(Pin('<html lang=en><head><title>T</title></head><body><h1>h</h1></body></html>'), 'charset').includes(SEV.WARN));
check('<meta charset> present → no charset warn', !ids(Pin('<html lang=en><head><meta charset="utf-8"><title>T</title></head><body><h1>h</h1></body></html>')).includes('charset'));
// mixed content
check('http img on https page → WARN mixed-content', sevOf(P('<html lang=en><head><title>T</title></head><body><h1>h</h1><img src="http://x/p.gif"></body></html>', { url: 'https://e/p', finalUrl: 'https://e/p' }).findings, 'mixed-content').includes(SEV.WARN));
check('http img on an HTTP page → no mixed-content (only flagged on https)', !ids(P('<html lang=en><head><title>T</title></head><body><h1>h</h1><img src="http://x/p.gif"></body></html>', { url: 'http://e/p', finalUrl: 'http://e/p' }).findings).includes('mixed-content'));
// microdata/RDFa awareness
check('no JSON-LD but Microdata → INFO not WARN', sevOf(Pin('<html lang=en><head><title>T</title></head><body itemscope itemtype="https://schema.org/WebPage"><h1>h</h1></body></html>'), 'jsonld-present').includes(SEV.INFO));
check('no structured data at all → WARN jsonld-present', sevOf(Pin('<html lang=en><head><title>T</title></head><body><h1>h</h1></body></html>'), 'jsonld-present').includes(SEV.WARN));
// search-engine verification (INFO, homepage-scoped, never warns on absence)
check('google-site-verification on home → INFO search-verification', sevOf(P('<html lang=en><head><title>T</title><meta name="google-site-verification" content="abc"></head><body><h1>h</h1></body></html>', { url: 'https://e/', finalUrl: 'https://e/' }).findings, 'search-verification').includes(SEV.INFO));
check('no verification meta → no warn (DNS/file verification is equally valid)', !ids(P('<html lang=en><head><title>T</title></head><body><h1>h</h1></body></html>', { url: 'https://e/', finalUrl: 'https://e/' }).findings).includes('search-verification'));

console.log('\n# severity-tier contract');
check('T0 core is exactly {http-200,title-present,h1-present}', [...T0_CHECKS].sort().join(',') === 'h1-present,http-200,title-present');
check('promotable T1 set excludes T0 ids', ![...T0_CHECKS].some((c) => T1_CHECKS.has(c)));
check('noindex is promotable (T1), title-length is not', T1_CHECKS.has('noindex') && !T1_CHECKS.has('title-length'));

console.log('\n# report + annotation encoding (pure)');
{
  check('safe() strips CR/LF and markdown-structural chars, caps length', safe('a\r\n`|<b>[c]', 5) === 'a bc' && safe('x'.repeat(300)).length === 220, JSON.stringify(safe('a\r\n`|<b>[c]', 5)));
  check('escapeData encodes % CR LF', escapeData('a%b\r\nc') === 'a%25b%0D%0Ac');
  check('escapeProperty also encodes : and ,', escapeProperty('a:b,c%') === 'a%3Ab%2Cc%25');
  const x = { id: 'h1-present', sev: SEV.CRIT, msg: 'no <h1> on the page', where: 'https://example.com/a/' };
  check('annotation = title + `<check> at <url>`, no file=/line= (a URL is not a repo file)', annotation(x) === '::error title=seo-aeo h1-present::h1-present at https://example.com/a/', annotation(x));
  check('annotation never carries msg (page text stays in the report)', !annotation(x).includes('no <h1>'));
  check("annotation level is the caller's", annotation(x, 'warning').startsWith('::warning title=seo-aeo h1-present::'));
  check('no location → just the check id', annotation({ id: 'no-urls-resolved', sev: SEV.CRIT, where: '' }) === '::error title=seo-aeo no-urls-resolved::no-urls-resolved');
  // A hostile location stays ONE command: a line break would start a second one (stop-commands),
  // a raw % would be unescaped by the runner, and [ ] would let the legacy `##[cmd]` form in.
  const evil = annotation({ ...x, where: 'https://e.test/p%0A\n::stop-commands::tok\r##[error]x' });
  check('a hostile location stays ONE line', !/[\r\n]/.test(evil), JSON.stringify(evil));
  check('a hostile location cannot add a property (title is the only one)', /^::error title=seo-aeo h1-present::/.test(evil) && evil.split('::').length === 5, JSON.stringify(evil));
  check('…its % is escaped and its brackets are gone', evil.includes('p%250A') && !evil.includes('##['), JSON.stringify(evil));
  const many = Array.from({ length: 12 }, (_, i) => ({ ...x, where: `https://example.com/${i}/` }));
  const warnOnly = { id: 'noindex', sev: SEV.WARN, msg: 'm', where: 'https://example.com/w/' };
  const out = annotations([...many, warnOnly]);
  check("annotations: 10 CRITICALs (GitHub's per-step cap) + one overflow line", out.length === 11 && out.slice(0, 10).every((l) => l.startsWith('::error ')) && /^seo-aeo: 2 more critical/.test(out[10]), `got ${out.length}`);
  check('annotations: a WARN finding is never annotated', !out.some((l) => l.includes('noindex')) && annotations([warnOnly]).length === 0);
}

console.log('\n# check.mjs end to end — the job log carries the report; CRITICALs annotate');
{
  // check.mjs runs a top-level IIFE, so it is exercised as a PROCESS against a local server. The
  // hostile page plants workflow commands where only check.mjs's safe() stands between them and the
  // start of a log line: html-lang and canonical-valid messages carry the raw attribute value.
  const HOSTILE = '<!doctype html><html lang="en&#10;::error title=forged::pwned-lang"><head><meta charset="utf-8">'
    + '<title>Hostile fixture page</title><link rel="canonical" href="rel&#10;::warning::pwned-canon"></head>'
    + '<body><main><p>no heading here</p></main></body></html>';
  const OK = (self) => '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    + `<title>A clean fixture page</title><link rel="canonical" href="${self}">`
    + '<meta name="description" content="A perfectly reasonable meta description, long enough for a snippet and short enough to fit.">'
    + '</head><body><main><h1>Clean heading</h1></main></body></html>';
  const server = createServer((req, res) => {
    const base = `http://${req.headers.host}`;
    if (req.url === '/ok/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(OK(`${base}/ok/`)); return; }
    if (req.url === '/hostile/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(HOSTILE); return; }
    if (req.url === '/empty-sitemap.xml') { res.writeHead(200, { 'content-type': 'application/xml' }); res.end('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>'); return; }
    res.writeHead(404, { 'content-type': 'text/html' }); res.end('<html><head><title>404</title></head><body><h1>Not found</h1></body></html>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const BASE = `http://127.0.0.1:${server.address().port}`;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'seo-e2e-'));
  const summaryPath = path.join(tmp, 'summary.md');
  // MUST be async (spawn, not spawnSync): the fixture server lives in THIS process. The env is built
  // from scratch so a CI runner's own GITHUB_ACTIONS / GITHUB_STEP_SUMMARY never leak into a case.
  const run = (extra) => new Promise((resolve) => {
    try { fs.rmSync(summaryPath, { force: true }); } catch { /* fresh file per run */ }
    const child = spawn(process.execPath, [fileURLToPath(new URL('./check.mjs', import.meta.url))], {
      env: { PATH: process.env.PATH, HOME: tmp, TMPDIR: tmp, ...extra }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (status) => {
      clearTimeout(killer);
      const summary = fs.existsSync(summaryPath) && fs.statSync(summaryPath).isFile() ? fs.readFileSync(summaryPath, 'utf8') : '';
      resolve({ status, stdout, stderr, summary });
    });
  });
  // A line the runner would read as a command: `::` after leading whitespace, or `##[` anywhere.
  const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l) || l.includes('##['));
  const why = (r) => `exit ${r.status}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
  const HEADER = '## 🔎 seo-aeo';
  const once = (r) => r.stdout.split(HEADER).length === 2 && !r.stdout.includes('crashed');
  const URLS = `${BASE}/gone/ ${BASE}/hostile/ ${BASE}/ok/`;
  const expected = (level, promoted) => [
    `::${level} title=seo-aeo http-200::http-200 at ${BASE}/gone/`,
    `::${level} title=seo-aeo h1-present::h1-present at ${BASE}/hostile/`,
    ...(promoted ? [`::${level} title=seo-aeo html-lang::html-lang at ${BASE}/hostile/`] : []),
  ];
  try {
    // (A) On Actions, enforcing, one T1 promoted: summary + job log + one ::error per CRITICAL.
    const a = await run({ URLS, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: 'html-lang' });
    check('Actions run: two T0 + one promoted T1 BLOCK (exit 1)', a.status === 1, why(a));
    check('the step summary is the report, verdict included', a.summary.startsWith(HEADER) && a.summary.includes('\nBLOCKED — 3 critical check(s) failed.'), JSON.stringify(a.summary.slice(-120)));
    check('the job log carries the WHOLE report, byte for byte', a.summary.length > 0 && a.stdout.includes(a.summary));
    check('the report reaches the log once, not twice', once(a), why(a));
    check('the fixtures reached the report (the hostile page, both planted values, defused)',
      a.stdout.includes(`${BASE}/hostile/`) && a.stdout.includes('pwned-lang') && a.stdout.includes('pwned-canon'));
    check('one ::error per CRITICAL (the promoted T1 included), none for a WARN, nothing else command-shaped',
      JSON.stringify(commands(a.stdout)) === JSON.stringify(expected('error', true)), JSON.stringify(commands(a.stdout)));
    check('annotations stay out of the step summary', commands(a.summary).length === 0);

    // (B) Off Actions: stdout is the only output — the report prints once, with no commands. spawn
    // hands the child a SOCKET as stdout: the case that crashes an `appendFileSync('/dev/stdout')`
    // fallback on Linux (ENXIO) with nothing printed and an exit code that still looks like a verdict.
    for (const [label, extra] of [['local run', {}], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', { GITHUB_STEP_SUMMARY: '/dev/stdout' }]]) {
      const b = await run({ URLS, FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: 'html-lang', ...extra });
      check(`${label}: the report prints exactly once, verdict included, no crash`, b.status === 1 && once(b) && b.stdout.includes('\nBLOCKED — 3 critical check(s) failed.'), why(b));
      check(`${label}: no workflow commands`, b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
    }

    // (C) report-only: the T0s annotate as ::warning, the (unpromoted) WARN not at all, exit 0.
    const c = await run({ URLS, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('report-only: exit 0', c.status === 0, why(c));
    check('report-only: the criticals annotate as ::warning, a WARN never', JSON.stringify(commands(c.stdout)) === JSON.stringify(expected('warning', false)), JSON.stringify(commands(c.stdout)));
    check('report-only: the log still carries the whole report', c.summary.length > 0 && c.stdout.includes(c.summary) && c.summary.includes('report-only — 2 critical check(s) would BLOCK'));

    // (D) The summary sink itself fails: the report is already in the log (it is echoed first), the
    // fault is named there, and the exit is the caller's setting — our fault never blocks report-only.
    const sinkDir = path.join(tmp, 'summary-is-a-dir');
    fs.mkdirSync(sinkDir);
    const d = await run({ URLS, GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('unwritable summary: the report still reaches the job log', d.stdout.includes(HEADER) && d.stdout.includes('report-only — 2 critical check(s) would BLOCK'), why(d));
    check('unwritable summary: the fault is named in the log', /seo-aeo crashed: .*EISDIR/.test(d.stdout), why(d));
    check('unwritable summary: the crash note is ONE line (no stack frame starts a log line)', !/^\s+at /m.test(d.stdout), why(d));
    check('unwritable summary: the crash re-flush echoes only the new line, not the report again', d.stdout.split(HEADER).length === 2);
    check('unwritable summary under report-only: exit 0, not an unhandled throw', d.status === 0, why(d));

    // (E) The early exits — two of them run before check.mjs's first await, i.e. while the module is
    // still evaluating, so anything they touch must already be initialized (no TDZ crash).
    const e = await run({});
    check('no input: skipped, exit 0, printed once, no crash', e.status === 0 && once(e) && e.stdout.includes('nothing to check (skipped)'), why(e));
    const f = await run({ URLS: ' ', GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true' });
    check('input resolving to no URL: BLOCKED (exit 1), printed once, no crash', f.status === 1 && once(f) && f.stdout.includes('BLOCKED — gate checked nothing.'), why(f));
    check('…annotated as the one CRITICAL it counts', JSON.stringify(commands(f.stdout)) === JSON.stringify(['::error title=seo-aeo no-urls-resolved::no-urls-resolved']), JSON.stringify(commands(f.stdout)));
    const g = await run({ SITEMAP_URL: `${BASE}/empty-sitemap.xml`, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('an empty sitemap: report-only exit 0, annotated at the sitemap as ::warning', g.status === 0
      && JSON.stringify(commands(g.stdout)) === JSON.stringify([`::warning title=seo-aeo no-urls-resolved::no-urls-resolved at ${BASE}/empty-sitemap.xml`]), JSON.stringify(commands(g.stdout)));
  } finally {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
