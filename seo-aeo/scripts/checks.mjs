// seo-aeo check engine — PURE functions, no network, no process exit.
// Parses the raw (JS-disabled) served HTML with a real DOM parser (cheerio) and
// evaluates the SEO/AEO matrix. The CLI (check.mjs) does the fetching + I/O and
// calls these; selftest.mjs unit-tests them offline against fixtures.
//
// Severity tiers (see README): T0 = always CRITICAL; T1 = WARN, opt-in promotable
// to CRITICAL per-caller via `critical-checks`; everything else = advisory WARN/INFO.
import { load } from 'cheerio';

export const SEV = { CRIT: 'critical', WARN: 'warn', INFO: 'info', OK: 'ok' };

// T0 — the only checks born CRITICAL. Each is binary, config-free, locale-independent,
// always-a-real-defect, and verified-passing on the two enforcing callers (epn, lampakia).
export const T0_CHECKS = new Set(['http-200', 'title-present', 'h1-present']);

// T1 — clean today, real defects, but not safe to assert fleet-wide without per-site
// verification. A caller may ELEVATE any of these to CRITICAL via the `critical-checks`
// input once it has eyeballed a clean run. Default severity stays WARN.
export const T1_CHECKS = new Set([
  'noindex', 'single-h1', 'canonical-present', 'canonical-valid', 'meta-description',
  'html-lang', 'viewport', 'jsonld-valid', 'og-core', 'robots-txt', 'sitemap',
  'redirect-consistency',
]);
// Everything else is T2 (advisory; ignored if a caller tries to promote it).

const CLASSIC_SEARCH_BOTS = ['Googlebot', 'Bingbot'];                        // blocking → de-indexed from Google/Bing (classic-SEO catastrophe)
const AI_ANSWER_BOTS = ['OAI-SearchBot', 'Claude-SearchBot', 'PerplexityBot']; // blocking → invisible to AI answer engines (AEO cost)
const AI_TRAINING_BOTS = ['GPTBot', 'ClaudeBot', 'anthropic-ai', 'Google-Extended', 'Applebot-Extended', 'CCBot', 'Amazonbot', 'Bytespider', 'Meta-ExternalAgent', 'Perplexity-User', 'ChatGPT-User', 'Claude-User']; // blocking is editorial policy, not a defect
export const AI_BOTS = [...CLASSIC_SEARCH_BOTS, ...AI_ANSWER_BOTS, ...AI_TRAINING_BOTS];

const RETIRED_RICH_RESULT = new Set(['FAQPage', 'HowTo']); // valid schema, no rich result since 2026-05-07

// ---------- small helpers ----------

const f = (id, sev, msg) => ({ id, sev, msg });
const norm = (u) => { try { const x = new URL(u); return (x.origin + x.pathname).replace(/\/+$/, '') || x.origin; } catch { return null; } };
const isAbsHttp = (u) => /^https?:\/\//i.test(u || '');
const validLangTag = (t) => /^[a-z]{2,3}(-[A-Za-z0-9]{1,8})*$/i.test(t || '');
const validHreflang = (t) => t === 'x-default' || validLangTag(t);

// JSON-LD: flatten single object / array / @graph into a flat node list.
export function collectLdNodes(value) {
  if (Array.isArray(value)) return value.flatMap(collectLdNodes);
  if (value && typeof value === 'object') {
    if (Array.isArray(value['@graph'])) {
      // keep the parent node too if it is itself typed (don't lose a top-level @type that
      // also wraps a @graph) — the common Yoast wrapper is just {@context,@graph} → no parent.
      const { '@graph': graph, ...rest } = value;
      const parent = rest['@type'] ? [rest] : [];
      return [...parent, ...graph.flatMap(collectLdNodes)];
    }
    return [value];
  }
  return [];
}
export function typesOf(node) {
  const t = node && node['@type'];
  if (!t) return [];
  return (Array.isArray(t) ? t : [t]).map(String);
}
const has = (n, p) => {
  const v = n && n[p];
  return v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0);
};

// Parse all <script type="application/ld+json"> blocks. Returns { nodes, types, parseErrors }.
export function extractJsonLd($) {
  const nodes = [], parseErrors = [];
  $('script[type="application/ld+json"]').each((i, el) => {
    let raw = $(el).contents().text()
      .replace(/^﻿/, '')
      .replace(/^\s*\/\/\s*<!\[CDATA\[/, '').replace(/\/\/\s*\]\]>\s*$/, '')
      .replace(/^\s*<!\[CDATA\[/, '').replace(/\]\]>\s*$/, '')
      .trim();
    if (!raw) return; // empty tag — not an error
    try { nodes.push(...collectLdNodes(JSON.parse(raw))); }
    catch (e) { parseErrors.push({ index: i, message: String(e.message).slice(0, 80) }); }
  });
  const types = new Set(nodes.flatMap(typesOf));
  return { nodes, types, parseErrors };
}

// ---------- page-type inference (signal-first, then URL, homepage by elimination) ----------

const LOCALES = new Set(['en', 'fr', 'de', 'el']); // ISO-639-1 langs in this fleet (gr/lu are TLDs, not languages)
export function inferPageType(url, $, types) {
  let path = '/';
  try { path = new URL(url).pathname.replace(/\/+$/, '') || '/'; } catch { /* keep / */ }
  let seg = path.split('/').filter(Boolean);
  if (seg.length === 0) return 'home';
  if (seg.length === 1 && LOCALES.has(seg[0].toLowerCase())) return 'home';     // /en, /fr, /de root
  if (seg.length > 1 && LOCALES.has(seg[0].toLowerCase())) seg = seg.slice(1);  // strip a /en//fr/ prefix before matching
  // strongest signal: an explicit @type wins over URL guessing
  if (types.has('Product')) return 'product';
  if (types.has('Article') || types.has('BlogPosting') || types.has('NewsArticle')) return 'article';
  if (types.has('ItemList') || types.has('CollectionPage')) return 'listing';
  if (types.has('LocalBusiness') || types.has('Store') || types.has('ContactPage')) return 'contact';
  const p = '/' + seg.join('/').toLowerCase();
  if (/(^|\/)(product|products|produkt|produit|προϊόν)\//.test(p)) return 'product';
  if (/(^|\/)(shop|category|product-category|categoria|categorie|κατηγορία|katigoria|collections?)(\/|$)/.test(p)) return 'listing';
  if (/(^|\/)(blog|news|article|post|actualites|nea|νέα)\//.test(p)) return 'article';
  if (/(^|\/)(contact|contact-us|epikoinwnia|epikoinonia|επικοινωνία|impressum|kontakt)(\/|$)/.test(p)) return 'contact';
  return 'generic';
}
function expectedTypesFor(pt) {
  switch (pt) {
    // homepage should identify the entity behind the site — Organization (or a
    // LocalBusiness/Store subtype), a Person (academic/portfolio sites), or a WebSite node.
    case 'home': return [['Organization', 'Person', 'LocalBusiness', 'Store', 'WebSite']];
    case 'listing': return [['ItemList', 'CollectionPage']];
    case 'product': return [['Product']];
    case 'article': return [['Article', 'BlogPosting', 'NewsArticle']];
    case 'contact': return [['LocalBusiness', 'Store', 'Organization']];
    default: return [];
  }
}

// ---------- the per-page analyzer ----------

// input: { requestUrl, finalUrl, status, headers (lowercased plain obj), html }
export function analyzePage(input) {
  const { requestUrl, finalUrl = input.requestUrl, status, headers = {}, html = '' } = input;
  const findings = [];
  const add = (...x) => findings.push(...x);
  const out = { url: requestUrl, finalUrl, status, findings };

  // T0.1 — reachability. A non-2xx CONTENT response is a real defect; skip the rest
  // (a 404/500 body has its own title/h1 we must not also grade).
  if (!(status >= 200 && status < 300)) {
    add(f('http-200', SEV.CRIT, `returned HTTP ${status} (expected 2xx)`));
    return out;
  }
  add(f('http-200', SEV.OK, `HTTP ${status}`));

  const $ = load(html);
  // <template> content is inert (a detached fragment) — never the page's real title/h1.
  // Removing it also clears it from $('h1')/$('title') (cheerio keeps it in a fragment
  // that .parents() can't reach). Comments are already non-elements; <noscript> stays
  // (its content IS rendered to a JS-disabled crawler).
  $('template').remove();
  const lower = (s) => String(s || '').toLowerCase();

  // ---- title (T0) + length (T2) + misplacement ----
  const headTitle = $('head title').first().text().trim();
  const anyTitle = $('title').first().text().trim();
  out.title = headTitle || null;
  if (!headTitle) {
    add(f('title-present', SEV.CRIT, anyTitle ? '<title> present but not in <head> (crawlers ignore body titles)' : 'missing or empty <title>'));
  } else {
    add(f('title-present', SEV.OK, `title (${headTitle.length} chars)`));
    out.titleLen = headTitle.length;
    // No lower-length floor: "About"/"Contact"/"FAQ" are idiomatic, valid titles, and Google
    // has no title-length ranking factor — the only real consequence is SERP truncation (a
    // LONG-title issue). Keep the >65-char truncation hint + placeholder/template-leak detection.
    if (headTitle.length > 65) add(f('title-length', SEV.WARN, `title is long (${headTitle.length} chars) — may be truncated in SERPs (~600px)`));
    if (/^(untitled|document|new page|test|no title)$/i.test(headTitle) || /%%|\{\{|\}\}/.test(headTitle)) add(f('title-length', SEV.WARN, `title looks like a placeholder/template token: "${headTitle.slice(0, 40)}"`));
  }

  // ---- h1 (T0) + single-h1 (T1) + hierarchy (T2) ----
  const h1s = $('h1');
  const realH1s = h1s.filter((i, el) => $(el).text().trim().length > 0 || $(el).find('img[alt]').filter((j, im) => ($(im).attr('alt') || '').trim()).length > 0);
  out.h1Count = realH1s.length;
  if (realH1s.length === 0) {
    add(f('h1-present', SEV.CRIT, h1s.length ? `${h1s.length} <h1> present but all empty/textless` : 'no <h1> on the page'));
  } else {
    add(f('h1-present', SEV.OK, `${realH1s.length} <h1>`));
    if (realH1s.length > 1) add(f('single-h1', SEV.WARN, `${realH1s.length} <h1> elements — one primary h1 is preferred`));
  }
  // heading hierarchy: no downward skip (h1 -> h3 with no h2)
  let prevMax = 0, skip = null;
  $('h1,h2,h3,h4,h5,h6').each((i, el) => {
    const lvl = Number(el.tagName[1]);
    if (prevMax && lvl > prevMax + 1 && !skip) skip = `h${prevMax}→h${lvl}`;
    prevMax = Math.max(prevMax, lvl);
  });
  if (skip) add(f('heading-hierarchy', SEV.WARN, `heading level skipped (${skip}) — keep the outline sequential`));

  // ---- indexability: noindex / nofollow via meta robots + X-Robots-Tag header (T1/T2) ----
  const robotsMeta = lower($('meta[name="robots"]').attr('content')) + ' ' + lower($('meta[name="googlebot"]').attr('content'));
  const xRobots = lower(headers['x-robots-tag']);
  const robotsAll = robotsMeta + ' ' + xRobots;
  out.noindex = /\bnoindex\b|\bnone\b/.test(robotsAll);
  if (out.noindex) add(f('noindex', SEV.WARN, `page is NOINDEX (${/\bnone\b/.test(robotsAll) ? 'none' : 'noindex'}${xRobots.includes('noindex') ? ', via X-Robots-Tag header' : ', via meta robots'}) — it will be dropped from search; intentional?`));
  if (/\bnofollow\b/.test(robotsAll)) add(f('nofollow', SEV.WARN, 'page-level nofollow on robots directive — all links on this page are not followed'));

  // ---- canonical (T1) ----
  const canons = $('link[rel="canonical"]').map((i, el) => $(el).attr('href')).get().filter(Boolean);
  out.canonical = canons[0] || null;
  if (canons.length === 0) {
    add(f('canonical-present', SEV.WARN, 'no <link rel="canonical"> — relying on Google to pick the canonical'));
  } else {
    if (canons.length > 1 && new Set(canons.map(norm)).size > 1) add(f('canonical-valid', SEV.WARN, `${canons.length} conflicting canonicals: ${[...new Set(canons)].slice(0, 3).join(' , ')}`));
    const c = canons[0];
    if (!isAbsHttp(c)) add(f('canonical-valid', SEV.WARN, `canonical is not an absolute https URL: "${c}"`));
    else {
      try {
        const cu = new URL(c), fu = new URL(finalUrl);
        if (cu.host !== fu.host) add(f('canonical-valid', SEV.WARN, `canonical points off-host (${cu.host} ≠ ${fu.host}) — verify this is an intentional cross-host canonical`));
      } catch { add(f('canonical-valid', SEV.WARN, `canonical does not parse as a URL: "${c}"`)); }
    }
    if (out.noindex && norm(c) && norm(c) !== norm(finalUrl)) add(f('canonical-conflict', SEV.WARN, 'page is noindex AND canonicalises to a different URL — conflicting signals (Google docs flag this)'));
  }

  // ---- meta description (T1 present / T2 length) ----
  // pick the first NON-EMPTY description (an empty first tag must not mask a valid second one)
  const descCandidates = $('meta').filter((i, el) => lower($(el).attr('name')) === 'description').map((i, el) => ($(el).attr('content') || '').trim()).get();
  const desc = descCandidates.find(Boolean) || '';
  out.descLen = desc.length;
  out.desc = desc || null;
  if (!desc) add(f('meta-description', SEV.WARN, 'no meta description — Google will auto-generate the snippet'));
  else if (desc.length < 50) add(f('meta-description-length', SEV.WARN, `meta description is short (${desc.length} chars; aim 50–160)`));
  else if (desc.length > 160) add(f('meta-description-length', SEV.WARN, `meta description is long (${desc.length} chars) — may be truncated`));

  // ---- Open Graph + Twitter (T1 og-core / T2 twitter) ----
  const og = (k) => ($(`meta[property="og:${k}"]`).attr('content') || '').trim();
  // require the card-bearing trio (title/url/image); og:type is lowest-value and consumers
  // default it to "website", so omitting it isn't a defect — left out of the core to avoid FPs.
  const missingOg = ['title', 'url', 'image'].filter((k) => !og(k));
  if (missingOg.length) add(f('og-core', SEV.WARN, `missing Open Graph tags: ${missingOg.map((k) => 'og:' + k).join(', ')}`));
  if (og('image') && !isAbsHttp(og('image'))) add(f('og-core', SEV.WARN, 'og:image is not an absolute URL — social scrapers need an absolute URL'));
  const twCard = ($('meta[name="twitter:card"]').attr('content') || '').trim();
  const anyTw = $('meta[name^="twitter:"]').length > 0;
  if (anyTw && !['summary', 'summary_large_image', 'app', 'player'].includes(twCard)) add(f('twitter-card', SEV.WARN, `twitter:* tags present but twitter:card is "${twCard || 'missing'}" (expected summary/summary_large_image/app/player)`));

  // ---- <html lang> (T1) + viewport (T1) ----
  const lang = ($('html').attr('lang') || '').trim();
  out.lang = lang || null;
  if (!lang) add(f('html-lang', SEV.WARN, 'missing <html lang> — declares no page language for crawlers/AT'));
  else if (!validLangTag(lang)) add(f('html-lang', SEV.WARN, `<html lang="${lang}"> is not a valid BCP-47 tag`));
  const vp = ($('meta[name="viewport"]').attr('content') || '').toLowerCase();
  if (!vp) add(f('viewport', SEV.WARN, 'missing <meta name="viewport"> — mobile-first indexing signal'));
  else if (!vp.includes('width=device-width')) add(f('viewport', SEV.WARN, 'viewport lacks width=device-width'));
  // flag zoom capped BELOW 2× only (WCAG 1.4.4) — anchored so maximum-scale=10 etc. don't match.
  else if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*(0|1)(\.0+)?(\D|$)/.test(vp)) add(f('viewport', SEV.WARN, 'viewport caps zoom below 2× (user-scalable=no / maximum-scale<2) — a11y/SEO smell'));

  // ---- charset (T2) — rendering correctness, esp. for non-ASCII (Greek/French) content ----
  const charset = $('meta[charset]').attr('charset') || (($('meta[http-equiv="Content-Type"]').attr('content') || '').match(/charset=([\w-]+)/i) || [])[1];
  if (!charset) add(f('charset', SEV.WARN, 'no <meta charset> declared — risks mojibake on non-ASCII content'));

  // ---- hreflang (T2, conditional — only meaningful when present) ----
  const hreflang = $('link[rel="alternate"][hreflang]').map((i, el) => ({ lang: $(el).attr('hreflang'), href: $(el).attr('href') })).get();
  out.hreflang = hreflang;
  if (hreflang.length) {
    const bad = hreflang.filter((h) => !validHreflang(h.lang)).map((h) => h.lang);
    if (bad.length) add(f('hreflang', SEV.WARN, `invalid hreflang code(s): ${[...new Set(bad)].join(', ')}`));
    if (!hreflang.some((h) => h.lang === 'x-default')) add(f('hreflang', SEV.WARN, 'hreflang cluster has no x-default entry'));
    if (lang && !hreflang.some((h) => (h.lang || '').toLowerCase().split('-')[0] === lang.toLowerCase().split('-')[0])) add(f('hreflang', SEV.WARN, `hreflang cluster has no self-referencing entry for the page language (${lang})`));
    if (hreflang.some((h) => h.href && !isAbsHttp(h.href))) add(f('hreflang', SEV.WARN, 'hreflang entries must use absolute URLs'));
  }

  // ---- img alt coverage (T2) ----
  // count CONTENT images only: skip aria-hidden/presentation, 1×1 tracking pixels, and
  // lazy-load placeholders with no src/srcset (the JS-disabled view legitimately lacks those).
  const imgs = $('img').filter((i, el) => {
    const $e = $(el);
    if ($e.attr('aria-hidden') === 'true' || $e.attr('role') === 'presentation') return false;
    if ($e.attr('width') === '1' || $e.attr('height') === '1') return false;
    if (!$e.attr('src') && !$e.attr('srcset')) return false;
    return true;
  });
  const noAlt = imgs.filter((i, el) => $(el).attr('alt') === undefined).length;
  if (noAlt > 0) add(f('img-alt', SEV.WARN, `${noAlt}/${imgs.length} content <img> missing an alt attribute (use alt="" for decorative)`));

  // ---- mixed content (T2) — http:// subresources on an https page (browsers block/warn; SEO + trust) ----
  let pageHttps = false;
  try { pageHttps = new URL(finalUrl).protocol === 'https:'; } catch { /* */ }
  if (pageHttps) {
    const insecure = $('img[src^="http://"], script[src^="http://"], link[rel="stylesheet"][href^="http://"], iframe[src^="http://"], video[src^="http://"], audio[src^="http://"], source[src^="http://"]').length;
    if (insecure) add(f('mixed-content', SEV.WARN, `${insecure} subresource(s) loaded over http:// on an https page — mixed content`));
  }

  // ---- semantic landmarks (T2) ----
  if ($('main, [role="main"], article').length === 0) add(f('semantic-landmark', SEV.WARN, 'no <main>/<article>/role=main landmark — weaker structure for AI extraction'));

  // ---- soft-404 (T2, conservative) ----
  const pt = inferPageType(finalUrl, $, new Set());
  if (pt !== 'home' && /\b(404|not found|page not found|σελίδα δεν βρέθηκε|seite nicht gefunden|page introuvable)\b/i.test(headTitle + ' ' + realH1s.first().text())) {
    add(f('soft-404', SEV.WARN, 'title/h1 looks like an error page served with HTTP 200 (possible soft-404)'));
  }

  // search-engine ownership verification (INFO only — absence is NOT a defect: DNS-TXT and
  // HTML-file verification are equally valid, so the gate REPORTS what's present, never warns).
  if (pt === 'home') {
    const verif = ['google-site-verification', 'msvalidate.01', 'yandex-verification', 'p:domain_verify', 'facebook-domain-verification'].filter((n) => $(`meta[name="${n}"]`).attr('content'));
    if (verif.length) add(f('search-verification', SEV.INFO, `search-engine ownership verification meta present: ${verif.join(', ')}`));
  }

  // ---- JSON-LD (T1 valid / T2 type+fields / INFO retired) ----
  const { nodes, types, parseErrors } = extractJsonLd($);
  out.jsonldTypes = [...types];
  for (const pe of parseErrors) add(f('jsonld-valid', SEV.WARN, `invalid JSON in ld+json block #${pe.index}: ${pe.message}`));
  if (nodes.length === 0 && parseErrors.length === 0) {
    // not a false "no structured data" if the page uses Microdata/RDFa instead of JSON-LD
    const micro = $('[itemscope][itemtype], [typeof], [vocab]').length;
    if (micro) add(f('jsonld-present', SEV.INFO, 'structured data uses Microdata/RDFa, not JSON-LD (valid; JSON-LD is Google-preferred)'));
    else add(f('jsonld-present', SEV.WARN, 'no structured data (JSON-LD / Microdata / RDFa) found'));
  }
  else {
    const pageType = inferPageType(finalUrl, $, types);
    out.pageType = pageType;
    for (const orGroup of expectedTypesFor(pageType)) {
      if (!orGroup.some((t) => types.has(t))) add(f('jsonld-type', SEV.WARN, `inferred ${pageType} page has no ${orGroup.join('/')} structured data`));
    }
    if (nodes.length && !types.has('BreadcrumbList') && pageType !== 'home') add(f('jsonld-type', SEV.WARN, 'no BreadcrumbList structured data (recommended on inner pages)'));
    add(...validateLdFields(nodes, pageType));
    for (const t of types) if (RETIRED_RICH_RESULT.has(t)) add(f('jsonld-retired', SEV.INFO, `${t} present — valid schema (AI/parse value), but no rich result since 2026-05-07`));
    // entity signal (AEO/GEO): the homepage's Organization/Person should carry a sameAs chain
    if (pageType === 'home') {
      const entity = nodes.find((n) => typesOf(n).some((t) => /Organization|LocalBusiness|Store|Person|Business/i.test(t)));
      if (entity && !has(entity, 'sameAs')) add(f('entity-sameas', SEV.WARN, 'homepage entity (Organization/Person) has no sameAs links — weakens entity disambiguation for AI/search answer engines'));
    }
    // freshness on article-shaped pages (T2)
    if (['article'].includes(pageType)) {
      const artModified = $('meta[property="article:modified_time"]').attr('content') || $('meta[property="article:published_time"]').attr('content');
      const dated = nodes.some((n) => has(n, 'dateModified') || has(n, 'datePublished')) || artModified;
      if (!dated) add(f('freshness', SEV.WARN, 'article page exposes no dateModified/datePublished — weakens freshness for answer engines'));
    }
  }

  return out;
}

// Required/recommended fields per @type — WARN only, scoped to types actually present.
function validateLdFields(nodes, pageType = 'generic') {
  const out = [];
  for (const n of nodes) {
    for (const t of typesOf(n)) {
      if (t === 'Product') {
        const miss = ['name', 'image', 'offers'].filter((p) => !has(n, p));
        if (miss.length) out.push(f('jsonld-fields', SEV.WARN, `Product JSON-LD missing ${miss.join(', ')}`));
        const offers = [].concat(n.offers || []);
        for (const o of offers) {
          if (!(has(o, 'price') || has(o, 'priceSpecification') || has(o, 'lowPrice'))) out.push(f('jsonld-fields', SEV.WARN, 'Product offer missing price/priceSpecification'));
          if (!has(o, 'priceCurrency') && !has(o.priceSpecification || {}, 'priceCurrency')) out.push(f('jsonld-fields', SEV.WARN, 'Product offer missing priceCurrency'));
        }
      } else if (t === 'Article' || t === 'BlogPosting' || t === 'NewsArticle') {
        const miss = ['headline', 'datePublished'].filter((p) => !has(n, p));
        if (miss.length) out.push(f('jsonld-fields', SEV.WARN, `${t} JSON-LD missing ${miss.join(', ')}`));
        if (!has(n, 'author')) out.push(f('jsonld-fields', SEV.WARN, `${t} JSON-LD missing author`));
      } else if (t === 'BreadcrumbList') {
        const items = [].concat(n.itemListElement || []);
        // a 1-item breadcrumb is normal on a homepage — only flag thin breadcrumbs on inner pages
        if (items.length < 2 && pageType !== 'home') out.push(f('jsonld-fields', SEV.WARN, 'BreadcrumbList has <2 itemListElement entries (no rich result)'));
        items.forEach((li, idx, arr) => {
          if (!has(li, 'name') && !has(li.item || {}, 'name')) out.push(f('jsonld-fields', SEV.WARN, `breadcrumb item ${idx + 1} missing name`));
          if (idx < arr.length - 1 && !has(li, 'item')) out.push(f('jsonld-fields', SEV.WARN, `breadcrumb item ${idx + 1} missing item URL`));
        });
      } else if (t === 'FAQPage') {
        const qs = [].concat(n.mainEntity || []);
        if (!qs.length || !qs.some((q) => has(q, 'acceptedAnswer'))) out.push(f('jsonld-fields', SEV.WARN, 'FAQPage has no Question with acceptedAnswer'));
      }
    }
  }
  // de-dup identical messages (graphs repeat nodes across pages of the same template)
  const seen = new Set();
  return out.filter((x) => !seen.has(x.msg) && seen.add(x.msg));
}

// ---------- site-level analyzers (pure; CLI feeds them fetched text) ----------

// RFC-9309-ish group resolver: most-specific UA group wins (NOT additive); a group whose
// root '/' verdict is Disallow blocks that bot. Returns { groups, blocked:{bot->true} }.
export function parseRobotsTxt(txt) {
  const groups = {}; let cur = null;
  const sitemaps = [];
  for (const rawLine of String(txt).split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, '').trim(); if (!line) continue;
    const m = line.match(/^([a-z-]+)\s*:\s*(.*)$/i); if (!m) continue;
    const key = m[1].toLowerCase(), val = m[2].trim();
    if (key === 'user-agent') { const k = val.toLowerCase(); cur = groups[k] = groups[k] || []; }
    else if (key === 'sitemap') sitemaps.push(val);
    else if ((key === 'allow' || key === 'disallow') && cur) cur.push({ type: key, path: val });
  }
  // Is path '/' disallowed for this UA token? RFC-9309: pick the ONE most-specific
  // matching group (groups are not additive); only rules whose path prefixes '/'
  // (i.e. '' or '/') affect the root; longest path wins, Allow beats Disallow on a tie.
  const rootBlocked = (uaToken) => {
    const tok = uaToken.toLowerCase();
    // RFC 9309 §2.2.1: match the product token case-insensitively. We pass canonical
    // tokens (Googlebot, Bingbot, GPTBot, …), so require EXACT group equality — never a
    // substring. This fixes the collisions a loose match caused ('Bing' group capturing
    // Bingbot, 'Googlebot-News' group capturing Googlebot) and removes file-order ambiguity
    // (an exact match is unique). No specific group → fall back to the '*' group.
    let key = Object.keys(groups).find((g) => g === tok);
    if (!key && groups['*']) key = '*';
    if (!key) return false; // no matching group → allowed
    const candidates = groups[key].filter((r) => r.path === '' || r.path === '/');
    if (!candidates.length) return false;
    let best = candidates[0];
    for (const r of candidates.slice(1)) {
      if (r.path.length > best.path.length) best = r;
      else if (r.path.length === best.path.length && r.type === 'allow') best = r;
    }
    return best.type === 'disallow' && best.path === '/'; // "Disallow:" (empty) = allow-all
  };
  return { groups, sitemaps, rootBlocked };
}

export function analyzeRobots({ status, body }) {
  const findings = [];
  // A 404 robots.txt is VALID per RFC 9309 (everything is crawlable) — advisory only, and
  // NOT the promotable `robots-txt` WARN (so a caller promoting robots-txt can't be blocked
  // by a legitimately-absent file). elevate() only touches WARN, so INFO here stays INFO.
  if (status === 404) { findings.push(f('robots-txt', SEV.INFO, 'no robots.txt (404) — valid per RFC 9309 (all crawling allowed); a Sitemap directive + explicit rules are still recommended')); return { findings, robots: null }; }
  if (!(status >= 200 && status < 300) || /<html|<!doctype/i.test(String(body).slice(0, 200))) {
    findings.push(f('robots-txt', SEV.WARN, `robots.txt not served as plain text (status ${status || 'fetch error'})`));
    return { findings, robots: null };
  }
  const robots = parseRobotsTxt(body);
  // blanket block of all crawlers
  const star = robots.groups['*'] || [];
  if (star.some((r) => r.type === 'disallow' && r.path === '/') && !star.some((r) => r.type === 'allow' && r.path === '/')) {
    findings.push(f('robots-txt', SEV.WARN, 'robots.txt has "User-agent: * / Disallow: /" — blocks ALL crawlers site-wide (intentional only for staging)'));
  }
  if (robots.sitemaps.length === 0) findings.push(f('robots-sitemap-directive', SEV.WARN, 'robots.txt has no Sitemap: directive'));
  // Classic search engines vs AI answer engines vs AI training crawlers — three different stakes.
  const blockedClassic = CLASSIC_SEARCH_BOTS.filter((b) => robots.rootBlocked(b));
  const blockedAnswer = AI_ANSWER_BOTS.filter((b) => robots.rootBlocked(b));
  const blockedTrain = AI_TRAINING_BOTS.filter((b) => robots.rootBlocked(b));
  if (blockedClassic.length) findings.push(f('search-engine-blocked', SEV.WARN, `classic search engine(s) blocked at root: ${blockedClassic.join(', ')} — this DE-INDEXES the site from Google/Bing (almost always a mistake outside staging)`));
  if (blockedAnswer.length) findings.push(f('ai-crawler-allowlist', SEV.WARN, `AI answer engines blocked in robots.txt: ${blockedAnswer.join(', ')} — costs AEO visibility (verify this is intentional)`));
  if (blockedTrain.length) findings.push(f('ai-crawler-allowlist', SEV.INFO, `AI training crawlers blocked (policy choice, not a defect): ${blockedTrain.join(', ')}`));
  return { findings, robots };
}

export function analyzeSitemap({ status, body }) {
  if (!(status >= 200 && status < 300)) return f('sitemap', SEV.WARN, 'no sitemap discoverable (checked robots.txt Sitemap + common paths)');
  if (!/<(sitemapindex|urlset)\b/i.test(String(body))) return f('sitemap', SEV.WARN, 'sitemap does not parse as XML (<urlset>/<sitemapindex> root not found)');
  return f('sitemap', SEV.OK, 'sitemap present and parses');
}

// llms.txt structural validation against the llmstxt.org grammar (not just HTTP 200).
export function analyzeLlms({ status, body }) {
  if (!(status >= 200 && status < 300)) return [f('llms-txt', SEV.WARN, 'no /llms.txt (AEO artifact: a markdown index that helps LLMs navigate the site)')];
  if (/<html|<!doctype/i.test(String(body).slice(0, 200))) return [f('llms-txt', SEV.WARN, '/llms.txt returns HTML, not markdown (likely a soft-404 / SPA fallback)')];
  const lines = String(body).replace(/^﻿/, '').split(/\r?\n/);
  const firstReal = lines.find((l) => l.trim().length);
  const out = [f('llms-txt', SEV.OK, '/llms.txt present')];
  if (!/^#\s+\S/.test(firstReal || '')) out.push(f('llms-structure', SEV.WARN, 'llms.txt should open with an H1 ("# Project Name") per the llmstxt.org spec'));
  if (!/^\s*>/m.test(body)) out.push(f('llms-structure', SEV.INFO, 'llms.txt has no blockquote summary (recommended after the H1)'));
  if (!/^##\s+\S/m.test(body) && !/\]\(/.test(body)) out.push(f('llms-structure', SEV.WARN, 'llms.txt has no "## " sections or markdown links — looks empty/unstructured'));
  return out;
}

// Redirect hygiene from a manual-redirect probe chain. probes: { http, www/apex, slash }
// each = { variant, chain: [{url,status,location}], finalStatus }.
export function analyzeRedirects(probes) {
  const out = [];
  for (const p of probes) {
    if (!p || p.error) continue;
    if (p.label === 'http' && p.chain.length && p.chain[0].status === 200) out.push(f('redirect-consistency', SEV.WARN, `http://${p.host} serves 200 without redirecting to https`));
    if (p.chain.length > 2) out.push(f('redirect-consistency', SEV.WARN, `${p.variant} takes ${p.chain.length} hops to resolve (redirect chain) — collapse to one hop`));
    const urls = p.chain.map((c) => c.url);
    if (new Set(urls).size !== urls.length) out.push(f('redirect-consistency', SEV.WARN, `${p.variant} has a redirect loop`));
  }
  return out;
}
