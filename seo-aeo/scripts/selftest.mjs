// Offline self-test for the seo-aeo check engine. No network — feeds fixture HTML /
// robots.txt / llms.txt to the pure analyzers and asserts the findings. Run locally or
// in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import {
  SEV, T0_CHECKS, T1_CHECKS, analyzePage, analyzeRobots, analyzeLlms, analyzeSitemap, analyzeRedirects,
  collectLdNodes, typesOf,
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

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
