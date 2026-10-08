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
import {
  parseLinkHeader, analyzeAgentHome, analyzeWebmcp, analyzeMarkdownNegotiation, analyzeMarkdown404, analyzeContentSignal,
  analyzeLlmsGuidance, parseSkillsIndex, gradeSkillArtifacts, sha256hex, analyzeArd, analyzeTrustPages, analyzeSitemapLastmod,
} from './agent.mjs';

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
  const fs = P(HEAD(`<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Brand","url":"https://example.com/","description":"What Brand does, in one sentence.","address":{"@type":"PostalAddress","addressCountry":"GR"},"contactPoint":{"@type":"ContactPoint","contactType":"customer service","email":"hi@example.com"},"sameAs":["https://www.linkedin.com/company/brand"]},{"@type":"WebSite","url":"https://example.com/"},{"@type":"ItemList","itemListElement":[]}]}</script>`), { url: 'https://example.com/', finalUrl: 'https://example.com/' }).findings;
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

console.log('\n# external-webfont (T1) — HEADLESS-ASTRO §7d: webfonts are self-hosted, never fonts.googleapis.com & co');
{
  const GF = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Playfair+Display&display=swap';
  const fw = (extra) => P(HEAD(extra)).findings.filter((x) => x.id === 'external-webfont');
  const one = (label, extra, re) => {
    const x = fw(extra);
    check(`${label} → one WARN external-webfont`, x.length === 1 && x[0].sev === SEV.WARN, JSON.stringify(x));
    if (re) check(`${label} → message names the host, the count, the self-host rule and the IP leak`, x.length === 1 && re.test(x[0].msg) && /self-host/.test(x[0].msg) && /woff2/.test(x[0].msg) && /§7d/.test(x[0].msg) && /visitor IPs/.test(x[0].msg), JSON.stringify(x));
  };
  // positives
  one('Google Fonts stylesheet <link>', `<link rel="stylesheet" href="${GF}">`, /1 reference\(s\) to fonts\.googleapis\.com/);
  one('preconnect only (no CSS link)', '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>', /1 reference\(s\) to fonts\.gstatic\.com/);
  one('dns-prefetch with a protocol-relative href', '<link rel="dns-prefetch" href="//fonts.googleapis.com">', /fonts\.googleapis\.com/);
  one('async media=print loader', `<link rel="stylesheet" href="${GF}" media="print" onload="this.media='all'">`, /fonts\.googleapis\.com/);
  one('preload as=style + onload loader', `<link rel="preload" as="style" href="${GF}" onload="this.rel='stylesheet'">`, /fonts\.googleapis\.com/);
  one('inline <style> @import url()', `<style>@import url('${GF}'); body{font-family:Inter}</style>`, /fonts\.googleapis\.com/);
  one('inline <style> @import "…" (string form)', `<style>@import "${GF}";</style>`, /fonts\.googleapis\.com/);
  one('inline <style> @font-face src: url(gstatic)', '<style>@font-face{font-family:Inter;src:url(https://fonts.gstatic.com/s/inter/v13/x.woff2) format("woff2")}</style>', /fonts\.gstatic\.com/);
  one('Typekit stylesheet', '<link rel="stylesheet" href="https://use.typekit.net/abc1def.css">', /use\.typekit\.net/);
  one('Typekit p.typekit.net preconnect, upper-cased host', '<link rel="preconnect" href="https://P.TYPEKIT.NET">', /p\.typekit\.net/);
  one('<noscript> fallback link (a JS-disabled visitor loads it)', `<noscript><link rel="stylesheet" href="${GF}"></noscript>`, /fonts\.googleapis\.com/);
  // the EPN shape: preconnect x2 + css link + noscript copy + @import → ONE finding, counted, URLs capped at 3 distinct
  {
    const x = fw(`<link rel="stylesheet" href="${GF}"><link rel="stylesheet" href="${GF}"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/cssA"><link rel="stylesheet" href="https://fonts.googleapis.com/cssB"><style>@import url(https://fonts.googleapis.com/cssC);</style><noscript><link rel="stylesheet" href="${GF}"></noscript>`);
    check('many references (one URL three times, incl. <noscript>) → still ONE finding, count = 8 (references, not distinct URLs), both hosts named', x.length === 1 && /8 reference\(s\) to fonts\.googleapis\.com, fonts\.gstatic\.com/.test(x[0].msg), JSON.stringify(x));
    const urls = x.length ? (x[0].msg.split('e.g. ')[1] || '').split(' , ') : [];
    check('…lists at most 3 distinct URLs', urls.length === 3 && urls.every((u, i) => urls.every((v, j) => i === j || !(u.startsWith(v) || v.startsWith(u)))), JSON.stringify(urls));
    check('…and the message fits the report\'s 300-char cap (the rule text is never cut)', x.length === 1 && x[0].msg.length <= 300, String(x[0] && x[0].msg.length));
    const y = fw(`<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="${GF}">`);
    const yu = y.length ? (y[0].msg.split('e.g. ')[1] || '').split(' , ') : [];
    check('…the stylesheet URL (with its family=) is listed before the bare preconnect hosts, though it comes last in the page', yu.length === 3 && /^fonts\.googleapis\.com\/css2\?family=Inter/.test(yu[0]) && yu[1] === 'fonts.googleapis.com' && yu[2] === 'fonts.gstatic.com', JSON.stringify(yu));
  }
  // URLs are sanitised like every page-controlled string: no line break, no markdown/bracket characters
  {
    const x = fw('<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=A&#10;::error::pwned|`[x]<b>">');
    check('hostile href → sanitised (no CR/LF, no ` | [ ] < >)', x.length === 1 && !/[\r\n`|[\]<>]/.test(x[0].msg), JSON.stringify(x));
  }
  // negatives
  check('self-hosted font preload + @font-face → no external-webfont', fw('<link rel="preload" as="font" type="font/woff2" href="/fonts/inter-latin.woff2" crossorigin><style>@font-face{font-family:Inter;src:url(/fonts/inter-latin.woff2) format("woff2");font-display:swap}</style>').length === 0);
  check('absolute same-origin /fonts/ URLs → no external-webfont', fw('<link rel="preload" as="font" href="https://example.com/fonts/inter.woff2" crossorigin><style>@font-face{font-family:I;src:url("https://example.com/fonts/inter.woff2")}</style>').length === 0);
  check('page with no fonts at all → no external-webfont (the clean page, again)', fw('').length === 0);
  // near-miss mutants: each is the real defect with ONE property changed, and must stay silent
  check('mutant: host only as a path segment (example.com/fonts.googleapis.com/x.css) → silent', fw('<link rel="stylesheet" href="https://example.com/fonts.googleapis.com/x.css">').length === 0);
  check('mutant: lookalike host (fonts.googleapis.com.example.org) → silent', fw('<link rel="stylesheet" href="https://fonts.googleapis.com.example.org/css">').length === 0);
  check('mutant: lookalike host (notfonts.gstatic.com) → silent', fw('<link rel="preconnect" href="https://notfonts.gstatic.com">').length === 0);
  check('mutant: an <a href> to the host is a hyperlink, not a font request → silent', P('<html lang=en><head><title>T</title></head><body><h1>h</h1><a href="https://fonts.googleapis.com/css2?family=Inter">fonts</a></body></html>').findings.every((x) => x.id !== 'external-webfont'));
  check('mutant: <link rel="canonical"> / rel="icon" at the host is not a webfont → silent', fw('<link rel="icon" href="https://fonts.gstatic.com/favicon.ico">').length === 0);
  check('mutant: @import commented out of the inline <style> → silent', fw(`<style>/* @import url('${GF}'); */ body{margin:0}</style>`).length === 0);
  check('mutant: the host named in plain text of a <style> comment/selector value → silent', fw('<style>.x::after{content:"fonts.googleapis.com"}</style>').length === 0);
  check('mutant: the link lives in a <template> (inert) → silent', fw(`<template><link rel="stylesheet" href="${GF}"></template>`).length === 0);
  check('mutant: a link in an HTML comment → silent', fw(`<!-- <link rel="stylesheet" href="${GF}"> -->`).length === 0);
  check('only a 2xx page is graded (a 404 short-circuits before this check)', !ids(P(`<html><head><link rel="stylesheet" href="${GF}"></head><body></body></html>`, { status: 404 }).findings).includes('external-webfont'));
}

console.log('\n# agent readiness (agent.mjs + the homepage entity) — absent → INFO, present but broken → WARN, adopted → OK');
const only = (fs, id) => [...new Set(sevOf(fs, id))].sort().join(',');   // the severities one id produced
{
  const links = parseLinkHeader('</sitemap-index.xml>; rel="sitemap", </llms.txt>; rel="describedby", </index.md>; rel="alternate"; type="text/markdown"');
  check('parseLinkHeader: three links, rel and type read', links.length === 3 && links[0].rel === 'sitemap' && links[2].type === 'text/markdown', JSON.stringify(links));
  const HOME = '<html><head><link rel="alternate" type="text/markdown" href="/index.md"><link rel="modulepreload" href="/_astro/entry.js"><script src="https://cdn.other.test/x.js"></script></head><body><script src="/_astro/a.js"></script><form toolname="search_products" tooldescription="Search the catalog"></form></body></html>';
  check('no Link header → INFO agent-link-headers', only(analyzeAgentHome({ finalUrl: 'https://e.test/', headers: {}, html: '<html></html>' }).findings, 'agent-link-headers') === SEV.INFO);
  const h = analyzeAgentHome({ finalUrl: 'https://e.test/', headers: { link: '</llms.txt>; rel="describedby"' }, html: HOME });
  check('a Link header → OK agent-link-headers', only(h.findings, 'agent-link-headers') === SEV.OK);
  const wpLink = analyzeAgentHome({ finalUrl: 'https://e.test/', headers: { link: '<https://e.test/wp-json/>; rel="https://api.w.org/", <https://e.test/?p=1>; rel=shortlink' }, html: HOME });
  check("WordPress's REST-discovery and shortlink Link headers alone → INFO, never adopted", only(wpLink.findings, 'agent-link-headers') === SEV.INFO && wpLink.findings.some((x) => x.id === 'agent-link-headers' && /carries only https:\/\/api\.w\.org\/, shortlink — none an agent follows/.test(x.msg)), JSON.stringify(wpLink.findings.filter((x) => x.id === 'agent-link-headers')));
  check('a language alternate alone → INFO', only(analyzeAgentHome({ finalUrl: 'https://e.test/', headers: { link: '</en/>; rel="alternate"; hreflang="en"' }, html: HOME }).findings, 'agent-link-headers') === SEV.INFO);
  const mdLink = analyzeAgentHome({ finalUrl: 'https://e.test/', headers: { link: '<https://e.test/wp-json/>; rel="https://api.w.org/", </index.md>; rel="alternate"; type="text/markdown", </x>; rel="preload describedby"' }, html: HOME });
  check('the Markdown alternate and a space-separated rel list count; the REST link beside them is not listed', only(mdLink.findings, 'agent-link-headers') === SEV.OK && mdLink.findings.some((x) => x.id === 'agent-link-headers' && x.msg === 'Link: header advertises alternate (text/markdown), describedby'), JSON.stringify(mdLink.findings.filter((x) => x.id === 'agent-link-headers')));
  check('the Markdown alternate is read from <link rel=alternate type=text/markdown>', h.mdAlternate === '/index.md', h.mdAlternate);
  check('bundles: same-origin <script src> + modulepreload, never another origin', JSON.stringify(h.scripts) === JSON.stringify(['https://e.test/_astro/a.js', 'https://e.test/_astro/entry.js']), JSON.stringify(h.scripts));
  check('no tools → INFO agent-webmcp', only(analyzeWebmcp({ bundles: [{ url: 'u', body: 'console.log(1)' }] }), 'agent-webmcp') === SEV.INFO);
  check('a toolname form → OK agent-webmcp', h.toolForms === 1 && only(analyzeWebmcp({ toolForms: h.toolForms }), 'agent-webmcp') === SEV.OK);
  check('registerTool in a same-origin bundle → OK agent-webmcp', only(analyzeWebmcp({ bundles: [{ url: 'u', body: 'document.modelContext.registerTool({name:"search_products"})' }] }), 'agent-webmcp') === SEV.OK);
  check('mutant: modelContext feature-tested but no tool registered → still INFO', only(analyzeWebmcp({ bundles: [{ url: 'u', body: 'if (navigator.modelContext) {}' }] }), 'agent-webmcp') === SEV.INFO);
}
{
  const MD = '# Fixture shop\n\nA lighting shop. Products, categories and shipping, in Markdown for agents.\n';
  const neg = (status, headers, body) => analyzeMarkdownNegotiation({ status, headers, body });
  check('HTML answer to Accept: text/markdown → INFO agent-markdown', only(neg(200, { 'content-type': 'text/html; charset=utf-8' }, '<!doctype html><html>'), 'agent-markdown') === SEV.INFO);
  check('a non-2xx answer → INFO agent-markdown, even one labelled text/markdown', only(neg(406, {}, ''), 'agent-markdown') === SEV.INFO && only(neg(404, { 'content-type': 'text/markdown', vary: 'Accept' }, MD), 'agent-markdown') === SEV.INFO);
  check('text/markdown + Vary: Accept + a Markdown body → OK', only(neg(200, { 'content-type': 'text/markdown; charset=utf-8', vary: 'Accept-Encoding, Accept' }, MD), 'agent-markdown') === SEV.OK);
  check('negotiated without Vary: Accept → WARN (a shared cache serves the Markdown to browsers)', only(neg(200, { 'content-type': 'text/markdown' }, MD), 'agent-markdown') === SEV.WARN);
  check('mutant: Vary: Accept-Encoding alone is not Vary: Accept → WARN', only(neg(200, { 'content-type': 'text/markdown', vary: 'Accept-Encoding' }, MD), 'agent-markdown') === SEV.WARN);
  // the HTML body is longer than the nearly-empty floor, so only the HTML test can turn it WARN
  check('text/markdown over an HTML body → WARN', only(neg(200, { 'content-type': 'text/markdown', vary: 'Accept' }, `<!doctype html><html><body><p>${'A real page body. '.repeat(5)}</p></body></html>`), 'agent-markdown') === SEV.WARN);
  check('text/markdown, nearly empty → WARN', only(neg(200, { 'content-type': 'text/markdown', vary: 'Accept' }, '# x'), 'agent-markdown') === SEV.WARN);
  const p404 = (status, headers, body, adopted) => analyzeMarkdown404({ status, headers, body }, { adopted });
  check('a nonexistent path answering 200 → WARN soft-404, adopted or not', only(p404(200, {}, '<html>', false), 'agent-markdown-404') === SEV.WARN && only(p404(200, {}, '<html>', true), 'agent-markdown-404') === SEV.WARN);
  check('not adopted + a real 404 → nothing graded', p404(404, { 'content-type': 'text/html' }, '<html>', false).length === 0);
  check('adopted + an HTML 404 → INFO', only(p404(404, { 'content-type': 'text/html' }, '<!doctype html><html>', true), 'agent-markdown-404') === SEV.INFO);
  check('adopted + a Markdown 404 → OK', only(p404(404, { 'content-type': 'text/markdown' }, '# Not found\n\nThe site map is at /llms.txt.', true), 'agent-markdown-404') === SEV.OK);
}
{
  check('no Content-Signal → INFO', only(analyzeContentSignal('User-agent: *\nAllow: /\n'), 'agent-content-signal') === SEV.INFO);
  check('Content-Signal: search=yes, ai-input=yes, ai-train=no → OK', only(analyzeContentSignal('User-agent: *\nContent-Signal: search=yes, ai-input=yes, ai-train=no\nAllow: /\n'), 'agent-content-signal') === SEV.OK);
  check('a value outside yes/no → WARN', only(analyzeContentSignal('Content-Signal: ai-train=maybe'), 'agent-content-signal') === SEV.WARN);
  check('an unknown key → WARN', only(analyzeContentSignal('Content-Signal: ai-foo=yes'), 'agent-content-signal') === SEV.WARN);
  check('mutant: a commented-out Content-Signal declares nothing → INFO', only(analyzeContentSignal('# Content-Signal: search=yes\nUser-agent: *\n'), 'agent-content-signal') === SEV.INFO);
  check('a trailing comment is not part of the signal → OK', only(analyzeContentSignal('Content-Signal: search=yes, ai-train=no # the owner\'s call\n'), 'agent-content-signal') === SEV.OK);
  check('llms.txt "## When to use (for AI agents)" → OK', only(analyzeLlmsGuidance({ status: 200, body: '# S\n\n> s\n\n## When to use (for AI agents)\n- buying lamps\n' }), 'agent-llms-guidance') === SEV.OK);
  check('llms.txt without it → INFO', only(analyzeLlmsGuidance({ status: 200, body: '# S\n\n## Docs\n- [a](https://e/a)\n' }), 'agent-llms-guidance') === SEV.INFO);
  check('mutant: the phrase in prose, not a ## heading → INFO', only(analyzeLlmsGuidance({ status: 200, body: '# S\n\nWhen to use this site: always.\n' }), 'agent-llms-guidance') === SEV.INFO);
  check('no llms.txt → nothing here (llms-txt already reports it)', analyzeLlmsGuidance({ status: 404, body: '' }).length === 0);
}
{
  const SKILL = Buffer.from('---\nname: product-finder\ndescription: Find a lamp by room, socket and price.\n---\n# Product finder\n');
  const entry = { name: 'product-finder', type: 'skill-md', description: 'Find a lamp.', url: '/.well-known/agent-skills/product-finder/SKILL.md', digest: `sha256:${sha256hex(SKILL)}` };
  const index = (skills) => ({ status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json', skills }) });
  const grade = (idx, art) => { const p = parseSkillsIndex(idx); return [...p.findings, ...gradeSkillArtifacts(p.entries.map((e) => ({ ...e, ...art })), p.findings)]; };
  const served = { status: 200, headers: { 'content-type': 'text/markdown; charset=utf-8' }, bytes: SKILL };
  check('no index (404) → INFO agent-skills-index', only(parseSkillsIndex({ status: 404 }).findings, 'agent-skills-index') === SEV.INFO);
  check('an index + a SKILL.md whose bytes match its digest → OK', only(grade(index([entry]), served), 'agent-skills-index') === SEV.OK);
  check('a digest that does not match the bytes served → WARN', only(grade(index([entry]), { ...served, bytes: Buffer.concat([SKILL, Buffer.from('\n')]) }), 'agent-skills-index') === SEV.WARN);
  check('index soft-404 (HTML with a 200) → WARN naming the soft-404', parseSkillsIndex({ status: 200, headers: { 'content-type': 'text/html' }, body: '<!doctype html><html>' }).findings.some((x) => x.sev === SEV.WARN && /soft-404/.test(x.msg)));
  check('an index that is not JSON → WARN', only(parseSkillsIndex({ status: 200, headers: { 'content-type': 'application/json' }, body: '{nope' }).findings, 'agent-skills-index') === SEV.WARN);
  check('an index served as text/plain → WARN', sevOf(grade({ ...index([entry]), headers: { 'content-type': 'text/plain' } }, served), 'agent-skills-index').includes(SEV.WARN));
  check('a skill name that is not lowercase-kebab → WARN', sevOf(grade(index([{ ...entry, name: 'Product_Finder' }]), served), 'agent-skills-index').includes(SEV.WARN));
  check('a SKILL.md served as text/html → WARN', sevOf(grade(index([entry]), { ...served, headers: { 'content-type': 'text/html' } }), 'agent-skills-index').includes(SEV.WARN));
  check('a listed SKILL.md that 404s → WARN', sevOf(grade(index([entry]), { ...served, status: 404 }), 'agent-skills-index').includes(SEV.WARN));
  check('a skill on another host → INFO only (never fetched, so never claimed verified)', only(grade(index([entry]), { offSite: true }), 'agent-skills-index') === SEV.INFO);
  check('an index that lists no skills → WARN', only(parseSkillsIndex(index([])).findings, 'agent-skills-index') === SEV.WARN);
}
{
  const CAT = (entries) => ({ status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ specVersion: '0.91', host: 'e.test', entries }) });
  const e = { identifier: 'urn:air:e.test:skill:product-finder', displayName: 'Product finder', type: 'application/ai-skill+md', url: 'https://e.test/.well-known/agent-skills/product-finder/SKILL.md' };
  const gone = { status: 404, headers: {}, body: '' };
  check('no catalog under either name → INFO agent-ard', only(analyzeArd(gone, gone, 'e.test'), 'agent-ard') === SEV.INFO);
  check('a catalog under both names → OK', only(analyzeArd(CAT([e]), CAT([e]), 'e.test'), 'agent-ard') === SEV.OK);
  check('ard.json only → OK + INFO for the missing alias', only(analyzeArd(CAT([e]), gone, 'e.test'), 'agent-ard') === 'info,ok');
  check('a www host against an apex identifier → the same site, OK', only(analyzeArd(CAT([e]), CAT([e]), 'www.e.test'), 'agent-ard') === SEV.OK);
  check('an identifier on another domain → WARN', sevOf(analyzeArd(CAT([{ ...e, identifier: 'urn:air:other.test:skill:x' }]), CAT([e]), 'e.test'), 'agent-ard').includes(SEV.WARN));
  check('an entry with both url and data → WARN', sevOf(analyzeArd(CAT([{ ...e, data: {} }]), CAT([e]), 'e.test'), 'agent-ard').includes(SEV.WARN));
  check('catalog soft-404 (HTML with a 200) → WARN', only(analyzeArd({ status: 200, headers: {}, body: '<!doctype html><html>' }, gone, 'e.test'), 'agent-ard') === SEV.WARN);
}
{
  const real = `<html><body><main><h1>About</h1><p>${'Real content about the business. '.repeat(20)}</p></main></body></html>`;
  const pages = (over = {}) => ['/about', '/contact', '/privacy'].map((p) => ({ path: p, status: 200, finalUrl: `https://e.test${p}`, html: real, offSite: false, ...(over[p] || {}) }));
  check('three real trust pages → OK', only(analyzeTrustPages(pages()), 'agent-trust-pages') === SEV.OK);
  check('one 404 → INFO naming it', only(analyzeTrustPages(pages({ '/privacy': { status: 404 } })), 'agent-trust-pages') === SEV.INFO && analyzeTrustPages(pages({ '/privacy': { status: 404 } }))[0].msg.includes('/privacy'));
  check('mutant: a page whose length is all nav/footer chrome is thin → INFO', only(analyzeTrustPages(pages({ '/about': { html: `<html><body><nav>${'menu '.repeat(200)}</nav><p>short</p><footer>${'footer '.repeat(200)}</footer></body></html>` } })), 'agent-trust-pages') === SEV.INFO);
  check('a redirect to another host does not count → INFO', only(analyzeTrustPages(pages({ '/contact': { offSite: true } })), 'agent-trust-pages') === SEV.INFO);
  check('a sitemap without lastmod → INFO sitemap-lastmod', only(analyzeSitemapLastmod('<urlset><url><loc>https://e/</loc></url></urlset>'), 'sitemap-lastmod') === SEV.INFO);
  check('a sitemap with lastmod → OK', only(analyzeSitemapLastmod('<urlset><url><loc>https://e/</loc><lastmod>2026-10-08</lastmod></url></urlset>'), 'sitemap-lastmod') === SEV.OK);
  check('a sitemap index (no <url>) → nothing graded here', analyzeSitemapLastmod('<sitemapindex><sitemap><loc>x</loc></sitemap></sitemapindex>').length === 0);
}
{
  const home = (graph) => P(HEAD(`<script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@graph': graph })}</script>`), { url: 'https://example.com/', finalUrl: 'https://example.com/' }).findings;
  const org = { '@type': 'Organization', name: 'B', sameAs: ['https://x.test/b'] };
  check('a homepage Organization without description → WARN entity-fields', sevOf(home([org]), 'entity-fields').includes(SEV.WARN));
  check('…without address and contactPoint → one INFO entity-fields naming both', home([org]).filter((x) => x.id === 'entity-fields' && x.sev === SEV.INFO && /address/.test(x.msg) && /contactPoint/.test(x.msg)).length === 1);
  check('a telephone counts as contact', !ids(home([{ ...org, description: 'd', telephone: '+30 210 000 0000', address: { '@type': 'PostalAddress' } }, { '@type': 'ItemList' }])).includes('entity-fields'));
  check('a Person site is never asked for an address or a contactPoint', !ids(home([{ '@type': 'Person', name: 'P', description: 'd', sameAs: ['https://x.test/p'] }])).includes('entity-fields'));
  check('a split graph: the address and phone on a LocalBusiness next to the Organization count', !ids(home([{ ...org, description: 'd' }, { '@type': 'LocalBusiness', name: 'B shop', telephone: '+30 210 000 0000', address: { '@type': 'PostalAddress' } }, { '@type': 'ItemList' }])).includes('entity-fields'));
  check('…but an Organization next to an author Person is still asked for them', home([{ ...org, description: 'd' }, { '@type': 'Person', name: 'A' }, { '@type': 'ItemList' }]).some((x) => x.id === 'entity-fields' && x.sev === SEV.INFO));
  check('entity + WebSite only → INFO homepage-type-breadth', only(home([{ ...org, description: 'd' }, { '@type': 'WebSite' }]), 'homepage-type-breadth') === SEV.INFO);
  check('…an ItemList on the homepage clears it', !ids(home([{ ...org, description: 'd' }, { '@type': 'WebSite' }, { '@type': 'ItemList' }])).includes('homepage-type-breadth'));
  check('inner pages are not graded for entity fields', !ids(P(HEAD('<script type="application/ld+json">{"@type":"Organization","name":"B"}</script>')).findings).includes('entity-fields'));
}

console.log('\n# severity-tier contract');
check('T0 core is exactly {http-200,title-present,h1-present}', [...T0_CHECKS].sort().join(',') === 'h1-present,http-200,title-present');
check('promotable T1 set excludes T0 ids', ![...T0_CHECKS].some((c) => T1_CHECKS.has(c)));
check('noindex is promotable (T1), title-length is not', T1_CHECKS.has('noindex') && !T1_CHECKS.has('title-length'));
check('external-webfont is promotable T1 and never a T0 (default WARN)', T1_CHECKS.has('external-webfont') && !T0_CHECKS.has('external-webfont'));
check('the four agent WARNs are promotable T1', ['agent-markdown', 'agent-skills-index', 'agent-ard', 'agent-content-signal'].every((c) => T1_CHECKS.has(c) && !T0_CHECKS.has(c)));
check('the other agent ids stay advisory (never promotable)', ['agent-link-headers', 'agent-webmcp', 'agent-llms-guidance', 'agent-trust-pages', 'agent-markdown-404', 'sitemap-lastmod', 'entity-fields', 'homepage-type-breadth'].every((c) => !T1_CHECKS.has(c)));
{
  // the promise behind promoting them: a site that adopted NONE of the four yields only INFO under their ids
  const absent = [
    ...analyzeMarkdownNegotiation({ status: 200, headers: { 'content-type': 'text/html' }, body: '<!doctype html><html>' }),
    ...analyzeContentSignal('User-agent: *\nAllow: /\n'),
    ...parseSkillsIndex({ status: 404 }).findings,
    ...analyzeArd({ status: 404 }, { status: 404 }, 'e.test'),
  ];
  check('a site that adopted none of the four: four INFOs, so promoting them blocks nothing', absent.length === 4 && absent.every((x) => x.sev === SEV.INFO), JSON.stringify(absent.map((x) => `${x.id}:${x.sev}`)));
}

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
    if (req.url === '/gfont/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(OK(`${base}/gfont/`).replace('</head>', '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&display=swap"></head>')); return; }
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

    // (F) external-webfont through the real action path: a clean page with one Google Fonts link is a
    // WARN by default (exit 0, no annotation) and BLOCKS only when this caller promotes the check.
    const hf = await run({ URLS: `${BASE}/gfont/`, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true' });
    check('external-webfont: default WARN does not block (exit 0), reported, never annotated', hf.status === 0 && hf.stdout.includes('`external-webfont`') && commands(hf.stdout).length === 0, why(hf));
    const hp = await run({ URLS: `${BASE}/gfont/`, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: 'external-webfont' });
    check('external-webfont: promoted via critical-checks BLOCKS with one ::error', hp.status === 1 && JSON.stringify(commands(hp.stdout)) === JSON.stringify([`::error title=seo-aeo external-webfont::external-webfont at ${BASE}/gfont/`]), why(hp) + JSON.stringify(commands(hp.stdout)));

    // (G) agent readiness through the real check.mjs. An adopting site is all ✅ even with the four agent
    // checks promoted; a broken one blocks on exactly the promoted ids (a 503 is could-not-look, which
    // blocks a promoted id too); a site that adopted nothing never blocks on them; and the verify token
    // never leaves the checked host (an off-site skill is never fetched, an off-site redirect hop gets none).
    const SKILL = Buffer.from('---\nname: product-finder\ndescription: Find a product by room and price.\n---\n# Product finder\n');
    const extHits = [], ownTokens = [];
    const external = createServer((req, res) => { extHits.push({ url: req.url, token: req.headers['x-verify-source'] || '' }); res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<html><body><main>${'x'.repeat(600)}</main></body></html>`); });
    await new Promise((r) => external.listen(0, 'localhost', r));
    const EXT = `http://localhost:${external.address().port}`;   // another HOST than 127.0.0.1, so headersFor withholds the token
    const agentSite = (good) => createServer((req, res) => {
      ownTokens.push(req.headers['x-verify-source'] || '');
      const base = `http://${req.headers.host}`, url = req.url.split('?')[0], md = /text\/markdown/.test(String(req.headers.accept || ''));
      const send = (status, type, body, extra = {}) => { res.writeHead(status, { 'content-type': type, ...extra }); res.end(body); };
      if (url === '/' && md) return send(200, 'text/markdown; charset=utf-8', '# Fixture shop\n\nA fixture site that negotiates Markdown for agents.\n', good ? { vary: 'Accept' } : {});
      if (url === '/') return send(200, 'text/html', `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Fixture shop</title><link rel="alternate" type="text/markdown" href="${base}/index.md"></head><body><main><h1>Fixture shop</h1><form toolname="search_products" tooldescription="Search the catalog" action="/search"><input name="q"></form></main></body></html>`, { link: `<${base}/llms.txt>; rel="describedby"` });
      if (url === '/robots.txt') return send(200, 'text/plain', `User-agent: *\nContent-Signal: search=yes, ai-input=yes, ai-train=${good ? 'yes' : 'maybe'}\nAllow: /\nSitemap: ${base}/sitemap.xml\n`);
      if (url === '/sitemap.xml') return send(200, 'application/xml', `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${base}/</loc><lastmod>2026-10-08</lastmod></url></urlset>`);
      if (url === '/llms.txt') return send(200, 'text/plain', '# Fixture shop\n\n> A fixture.\n\n## When to use (for AI agents)\n- finding a product\n');
      if (url === '/.well-known/agent-skills/index.json') {
        const skill = (name, href) => ({ name, type: 'skill-md', description: 'Find a product.', url: href, digest: `sha256:${sha256hex(SKILL)}` });
        return send(200, 'application/json', JSON.stringify({ $schema: 'https://schemas.agentskills.io/discovery/0.2.0/schema.json', skills: [skill('product-finder', '/.well-known/agent-skills/product-finder/SKILL.md'), ...(good ? [] : [skill('elsewhere', `${EXT}/SKILL.md`)])] }));
      }
      if (url === '/.well-known/agent-skills/product-finder/SKILL.md') return send(200, 'text/markdown', good ? SKILL : Buffer.concat([SKILL, Buffer.from('edited after the index was built\n')]));
      if (url === '/.well-known/ard.json' || url === '/.well-known/ai-catalog.json') {
        if (!good) return send(503, 'text/plain', 'busy');
        return send(200, 'application/json', JSON.stringify({ specVersion: '0.91', host: '127.0.0.1', entries: [{ identifier: 'urn:air:127.0.0.1:skill:product-finder', displayName: 'Product finder', type: 'application/ai-skill+md', url: `${base}/.well-known/agent-skills/product-finder/SKILL.md` }] }));
      }
      if (!good && url === '/privacy') { res.writeHead(301, { location: `${EXT}/privacy` }); return res.end(); }
      if (['/about', '/contact', '/privacy'].includes(url)) return send(200, 'text/html', `<!doctype html><html><body><main><h1>${url}</h1><p>${'Real content about the business. '.repeat(20)}</p></main></body></html>`);
      if (md) return send(404, 'text/markdown', '# Not found\n\nThe site map is at /llms.txt.\n');
      return send(404, 'text/html', '<html><head><title>404</title></head><body><h1>Not found</h1></body></html>');
    });
    const goodSite = agentSite(true), brokenSite = agentSite(false);
    await Promise.all([goodSite, brokenSite].map((sv) => new Promise((r) => sv.listen(0, '127.0.0.1', r))));
    const GOOD = `http://127.0.0.1:${goodSite.address().port}`, BROKEN = `http://127.0.0.1:${brokenSite.address().port}`;
    const PROMOTE = 'agent-markdown,agent-skills-index,agent-ard,agent-content-signal';
    const agentSection = (r) => (r.stdout.split('### Agent readiness')[1] || '').split('\n**critical:')[0];
    try {
      const ga = await run({ URLS: `${GOOD}/`, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: PROMOTE });
      const inPlace = (agentSection(ga).match(/✅ in place: (.*)/) || [])[1] || '';
      const all = ['agent-link-headers', 'agent-webmcp', 'agent-markdown', 'agent-markdown-404', 'agent-content-signal', 'agent-llms-guidance', 'agent-skills-index', 'agent-ard', 'agent-trust-pages', 'sitemap-lastmod'];
      check('agent e2e, adopting site: exit 0 with all four promoted, nothing annotated', ga.status === 0 && commands(ga.stdout).length === 0, why(ga) + JSON.stringify(commands(ga.stdout)));
      check('…all ten agent checks in place, no ℹ️/⚠️ in the agent section', all.every((id) => inPlace.includes(`\`${id}\``)) && !/^\s+- (ℹ️|⚠️)/m.test(agentSection(ga)), JSON.stringify(agentSection(ga)));

      ownTokens.length = 0;
      const gb = await run({ URLS: `${BROKEN}/`, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: PROMOTE, VERIFY_TOKEN: 'e2e-agent-token' });
      check('agent e2e, broken site: BLOCKED (exit 1) with one ::error per promoted defect, at the origin', gb.status === 1 && JSON.stringify(commands(gb.stdout)) === JSON.stringify(['agent-markdown', 'agent-content-signal', 'agent-skills-index', 'agent-ard'].map((id) => `::error title=seo-aeo ${id}::${id} at ${BROKEN}`)), why(gb) + JSON.stringify(commands(gb.stdout)));
      check('…the 503 catalog is reported as could-not-look, never as a verdict', /`agent-ard` — could not look at .*HTTP 503/.test(gb.stdout), JSON.stringify(agentSection(gb)));
      check('…/privacy redirecting to another host is a missing trust page', /ℹ️ `agent-trust-pages` — .*\/privacy/.test(agentSection(gb)), JSON.stringify(agentSection(gb)));
      check('…the token reached the checked host (the test is not vacuous)', ownTokens.includes('e2e-agent-token'));
      check('…an off-site skill is never fetched, and the off-site redirect hop got no token', !extHits.some((h) => h.url === '/SKILL.md') && extHits.some((h) => h.url === '/privacy') && extHits.every((h) => h.token === ''), JSON.stringify(extHits));
      const gr = await run({ URLS: `${BROKEN}/`, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false', CRITICAL_CHECKS: PROMOTE });
      check('agent e2e, broken site report-only: exit 0, the same four annotate as ::warning', gr.status === 0 && commands(gr.stdout).length === 4 && commands(gr.stdout).every((l) => l.startsWith('::warning ')), why(gr));
      const gn = await run({ URLS: `${BASE}/ok/`, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: PROMOTE });
      check('agent e2e, a site that adopted nothing: the four promoted ids never block (exit 0)', gn.status === 0 && commands(gn.stdout).length === 0 && /ℹ️ `agent-markdown`/.test(gn.stdout), why(gn));
    } finally {
      for (const sv of [external, goodSite, brokenSite]) sv.close();
    }
  } finally {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
