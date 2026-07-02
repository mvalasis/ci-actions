// form-protection CLI — fetches live URLs JS-disabled, finds bot-widget forms
// (checks.mjs), then live-probes each resolved submit endpoint with a tokenless
// and a junk-token POST. Renders a per-page + per-endpoint report to
// GITHUB_STEP_SUMMARY and exits non-zero only when a CRITICAL check fails AND
// fail-on-critical is set. Air-gapped: only touches the target site.
//
// Read-safe by design: probes send a MINIMAL body (no real-looking fields), so
// even a skip-verifying endpoint falls through to its own field validation
// instead of creating a record — see buildProbeBody in checks.mjs.
import fs from 'node:fs';
import {
  SEV, analyzeForms, parseEndpointMap, buildProbeBody, judgeProbe,
} from './checks.mjs';

const env = process.env;
const FAIL_ON_CRITICAL = env.FAIL_ON_CRITICAL === 'true';
const MAX_URLS = Math.max(1, parseInt(env.MAX_URLS || '15', 10) || 15);
const VERIFY_TOKEN = env.VERIFY_TOKEN || '';
const SUBMIT_PROBE = env.SUBMIT_PROBE !== 'false';
const ENDPOINT_MAP = parseEndpointMap(env.FORM_ENDPOINTS || '');
const EXTRA_TEST_KEYS = (env.TEST_SITEKEYS || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const lines = [];
const note = (s = '') => lines.push(s);
const ICON = { critical: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };

// Neutralize page-controlled strings before they reach the markdown summary
// (report-spoofing guard — same contract as seo-aeo).
const safe = (s, max = 300) => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/[`|<>[\]]/g, '').slice(0, max);

const baseHeaders = { 'user-agent': 'Mozilla/5.0 (compatible; ci-actions-form-protection/1.0; +https://github.com/mvalasis/ci-actions)' };
// WAF-bypass token + LiteSpeed cookie go ONLY to the configured host(s) and
// their www/apex variants — never to an off-host redirect target (undici keeps
// custom headers across cross-origin redirects, so we scope by host ourselves
// and follow page redirects manually).
const TOKEN_HEADERS = VERIFY_TOKEN ? { 'x-verify-source': VERIFY_TOKEN, cookie: '_lscache_vary=1' } : {};
const ALLOWED_HOSTS = new Set();
for (const u of [...(env.URLS || '').split(/\s+/), env.SITEMAP_URL || ''].filter(Boolean)) {
  try { const h = new URL(u).host, apex = h.replace(/^www\./, ''); [h, apex, 'www.' + apex].forEach((x) => ALLOWED_HOSTS.add(x)); } catch { /* ignore */ }
}
function headersFor(url, extra = {}) {
  let host = ''; try { host = new URL(url).host; } catch { /* none */ }
  return ALLOWED_HOSTS.has(host) ? { ...baseHeaders, ...TOKEN_HEADERS, ...extra } : { ...baseHeaders, ...extra };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const extractLocs = (xml) => [...String(xml).matchAll(/<loc>\s*(?:<!\[CDATA\[)?\s*([^<\s\]]+)\s*(?:\]\]>)?\s*<\/loc>/gi)].map((m) => m[1]);

// GET fetches follow redirects MANUALLY (re-evaluating headersFor each hop) so
// the token is never carried to an off-host target.
async function followFetch(url, maxHops = 6) {
  let current = url, redirected = false;
  for (let i = 0; i < maxHops; i++) {
    const r = await fetch(current, { headers: headersFor(current), redirect: 'manual', signal: AbortSignal.timeout(25000) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { current = new URL(loc, current).href; redirected = true; continue; }
    return { status: r.status, finalUrl: current, redirected, body: await r.text() };
  }
  throw new Error('too many redirects');
}
// Retry once on a NETWORK/timeout error (transient) — never on a real HTTP status.
async function fetchPage(url) {
  try { return await followFetch(url); }
  catch (e1) { await sleep(1500); try { return await followFetch(url); } catch (e2) { return { error: e2.message || String(e2) }; } }
}

// POST probes never follow redirects (a 3xx answer is itself a verdict input).
async function postProbe(url, { body, contentType }) {
  const doPost = async () => {
    const r = await fetch(url, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(25000),
      headers: headersFor(url, { 'content-type': contentType }),
      body,
    });
    return { status: r.status, body: await r.text() };
  };
  try { return await doPost(); }
  catch (e1) { await sleep(1500); try { return await doPost(); } catch (e2) { return { error: e2.message || String(e2) }; } }
}

async function expandSitemap(sm) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = await fetchPage(sm);
    if (!r.error && r.status >= 200 && r.status < 300) {
      const locs = extractLocs(r.body);
      if (/<sitemapindex\b/i.test(r.body) && locs.length) {
        const kids = [];
        for (const child of locs.slice(0, 5)) {
          const cr = await fetchPage(child);
          if (!cr.error) kids.push(...extractLocs(cr.body));
        }
        return kids;
      }
      return locs;
    }
    await sleep(1500);
  }
  return [];
}

(async () => {
  let urls = [];
  let sitemapTotal = 0;
  const inputGiven = !!(env.URLS || env.SITEMAP_URL);
  if (env.SITEMAP_URL) { const all = await expandSitemap(env.SITEMAP_URL); sitemapTotal = all.length; urls.push(...all); }
  if (env.URLS) urls.push(...env.URLS.split(/[\s]+/));
  urls = [...new Set(urls.map((u) => u.trim()).filter(Boolean))];
  const truncated = urls.length > MAX_URLS;
  urls = urls.slice(0, MAX_URLS);

  note('## 🛡️ form-protection — bot-gate enforced end-to-end');
  note('');

  if (!inputGiven) { note('- no `urls`/`sitemap-url` configured — nothing to check (skipped)'); flush(); process.exit(0); }
  if (urls.length === 0) {
    note('- ❌ **no URLs resolved** — `sitemap-url`/`urls` was set but expanded to nothing (the gate checked zero pages).');
    note('');
    note('**critical: 1 · warnings: 0**');
    note(FAIL_ON_CRITICAL ? 'BLOCKED — gate checked nothing.' : 'report-only — would BLOCK under fail-on-critical.');
    flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0);
  }

  note(`- mode: ${FAIL_ON_CRITICAL ? '**BLOCK on critical**' : 'report-only (never blocks)'}`);
  note(`- pages checked: ${urls.length}${truncated ? ` (capped at max-urls=${MAX_URLS} of ${sitemapTotal} in sitemap — partial coverage)` : ''}`);
  note(`- submit probe: ${SUBMIT_PROBE ? 'on (tokenless + junk-token POST per endpoint)' : '**off** — sitekey checks only, server-side verification NOT asserted'}`);
  const badEntries = ENDPOINT_MAP.filter((e) => e.error);
  for (const b of badEntries) note(`- ⚠️ unparseable \`form-endpoints\` line (want \`selector => endpoint [mode=json] [token=…] [expect=…]\`): \`${safe(b.error, 120)}\``);
  note('');

  let crit = 0, warn = 0, info = 0;
  const tally = (findings) => findings.forEach((x) => { if (x.sev === SEV.CRIT) crit++; else if (x.sev === SEV.WARN) warn++; else if (x.sev === SEV.INFO) info++; });
  warn += badEntries.length;
  const sevRank = (s) => ({ critical: 0, warn: 1, info: 2, ok: 3 }[s] ?? 9);
  const renderFindings = (findings, indent = '  ') => {
    for (const x of findings.filter((y) => y.sev !== SEV.OK).sort((a, b) => sevRank(a.sev) - sevRank(b.sev))) {
      note(`${indent}- ${ICON[x.sev]} \`${x.id}\` — ${safe(x.msg, 400)}`);
    }
  };

  // ---- per-page: widget + sitekey checks, collect probe surfaces ----
  note('### Pages');
  const surfaces = [];
  for (const url of urls) {
    const r = await fetchPage(url);
    if (r.error) { note(`- ⚠️ ${safe(url)} — fetch failed (${safe(r.error, 120)}) — infra issue, not a content defect (not counted as critical)`); warn++; continue; }
    // WAF/auth challenge or transient origin error: infra-WARN, never a content verdict.
    if ([401, 403, 408, 425, 429].includes(r.status) || (r.status >= 500 && r.status < 600)) {
      note(`- ⚠️ ${safe(url)} — origin returned HTTP ${r.status} (WAF/bot-challenge or transient origin error) — set \`verify-token\` if WAF-fronted; infra-WARN, not critical`);
      warn++; continue;
    }
    if (!(r.status >= 200 && r.status < 300)) {
      note(`- ⚠️ ${safe(url)} — HTTP ${r.status} (page missing?) — nothing to check here; fix the wired URL`);
      warn++; continue;
    }
    const { findings, surfaces: pageSurfaces } = analyzeForms({ requestUrl: url, html: r.body, endpointMap: ENDPOINT_MAP, extraTestKeys: EXTRA_TEST_KEYS });
    tally(findings);
    surfaces.push(...pageSurfaces);
    const icon = findings.some((x) => x.sev === SEV.CRIT) ? ICON.critical : findings.some((x) => x.sev === SEV.WARN) ? ICON.warn : ICON.ok;
    note(`- ${icon} [${safe(url)}](${safe(url)})  \`HTTP ${r.status}\` · ${pageSurfaces.length} gated form(s)`);
    if (findings.filter((x) => x.sev !== SEV.OK).length) renderFindings(findings, '  ');
    else if (pageSurfaces.length) note(`  - ✅ ${pageSurfaces.map((s) => `${safe(s.form, 60)} → ${safe(s.endpoint, 100)}`).join(' · ')}`);
  }

  // ---- submit probes: dedupe endpoints across pages, POST twice each ----
  if (SUBMIT_PROBE) {
    note('');
    note('### Submit probes (tokenless + junk-token POST must hard-reject)');
    const byEndpoint = new Map();
    for (const s of surfaces) {
      // fields is part of the key: two forms can share an endpoint but carry
      // different routing discriminators (epn contact vs employer formType).
      const key = `${s.endpoint} ${s.mode} ${s.tokenField} ${s.expect} ${JSON.stringify(s.fields || {})}`;
      if (!byEndpoint.has(key)) byEndpoint.set(key, { ...s, forms: [] });
      byEndpoint.get(key).forms.push(`${s.form} @ ${s.page}`);
    }
    if (!byEndpoint.size) { note('- no probe-able endpoints resolved (no gated forms found, or all lacked an endpoint)'); }
    for (const surface of byEndpoint.values()) {
      note(`- **${safe(surface.endpoint, 160)}** (${surface.mode}${surface.expect ? `, expect="${safe(surface.expect, 40)}"` : ''}) ← ${safe([...new Set(surface.forms)].join(' · '), 220)}`);
      for (const kind of ['tokenless', 'junk-token']) {
        const r = await postProbe(surface.endpoint, buildProbeBody(surface, kind));
        if (r.error) { note(`  - ⚠️ ${kind} POST — network error (${safe(r.error, 120)}); probe inconclusive`); warn++; continue; }
        const verdict = judgeProbe({ kind, status: r.status, body: r.body, expect: surface.expect, endpoint: surface.endpoint });
        tally([verdict]);
        note(`  - ${ICON[verdict.sev]} ${verdict.sev === SEV.OK ? safe(verdict.msg, 300) : `\`${verdict.id}\` — ${safe(verdict.msg, 400)}`}`);
        await sleep(700);
      }
    }
  }

  // ---- verdict ----
  note('');
  note(`**critical: ${crit} · warnings: ${warn} · info: ${info}**`);
  if (crit > 0 && FAIL_ON_CRITICAL) { note(`BLOCKED — ${crit} critical check(s) failed. Fix the ❌ items above.`); flush(); process.exit(1); }
  if (crit > 0) note(`report-only — ${crit} critical check(s) would BLOCK under \`fail-on-critical: true\`.`);
  else note('PASS — no critical issues.');
  flush(); process.exit(0);
})().catch((e) => { note(`- ❌ form-protection crashed: ${e.stack || e.message}`); flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0); });

function flush() { fs.appendFileSync(summaryFile, lines.join('\n') + '\n'); }
