// seo-aeo CLI — fetches live URLs JS-disabled (the crawler's-eye view), runs the
// check engine (checks.mjs), renders a per-page report to GITHUB_STEP_SUMMARY, and
// exits non-zero only when a CRITICAL check fails AND fail-on-critical is set.
// Air-gapped: only touches the target site (no SaaS, no telemetry).
import fs from 'node:fs';
import {
  SEV, T1_CHECKS, analyzePage, analyzeRobots, analyzeSitemap, analyzeLlms, analyzeRedirects,
} from './checks.mjs';

const env = process.env;
const FAIL_ON_CRITICAL = env.FAIL_ON_CRITICAL === 'true';
const MAX_URLS = Math.max(1, parseInt(env.MAX_URLS || '15', 10) || 15);
const VERIFY_TOKEN = env.VERIFY_TOKEN || '';
const CRITICAL_CHECKS = (env.CRITICAL_CHECKS || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const lines = [];
const note = (s = '') => lines.push(s);
const ICON = { critical: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };

// Neutralize page-controlled strings before they reach the markdown summary: strip CR/LF and
// markdown-structural chars + cap length so a hostile <title>/<loc>/canonical can't forge
// verdict lines or inject an image beacon into the job summary (report-spoofing guard).
const safe = (s, max = 220) => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/[`|<>[\]]/g, '').slice(0, max);
const norm2 = (u) => { try { const x = new URL(u); return (x.origin + x.pathname).replace(/\/+$/, '') || x.origin; } catch { return null; } };
const extractLocs = (xml) => [...String(xml).matchAll(/<loc>\s*(?:<!\[CDATA\[)?\s*([^<\s\]]+)\s*(?:\]\]>)?\s*<\/loc>/gi)].map((m) => m[1]);

const baseHeaders = { 'user-agent': 'Mozilla/5.0 (compatible; ci-actions-seo/1.0; +https://github.com/mvalasis/ci-actions)' };
// The WAF-bypass token + LiteSpeed cookie go ONLY to the configured host(s) and their www/apex
// variants — never to a redirect/sitemap target on another origin. undici forwards custom
// headers across cross-origin redirects (it only strips Cookie/Authorization), so we gate the
// token by host ourselves and follow page redirects manually to re-scope it per hop.
const TOKEN_HEADERS = VERIFY_TOKEN ? { 'x-verify-source': VERIFY_TOKEN, cookie: '_lscache_vary=1' } : {};
const ALLOWED_HOSTS = new Set();
for (const u of [...(env.URLS || '').split(/\s+/), env.SITEMAP_URL || ''].filter(Boolean)) {
  try { const h = new URL(u).host, apex = h.replace(/^www\./, ''); [h, apex, 'www.' + apex].forEach((x) => ALLOWED_HOSTS.add(x)); } catch { /* ignore */ }
}
function headersFor(url) {
  let host = ''; try { host = new URL(url).host; } catch { /* none */ }
  return ALLOWED_HOSTS.has(host) ? { ...baseHeaders, ...TOKEN_HEADERS } : { ...baseHeaders };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchOnce(url, opts = {}) {
  const r = await fetch(url, { headers: headersFor(url), redirect: opts.redirect || 'follow', signal: AbortSignal.timeout(opts.timeout || 25000) });
  const body = opts.headOnly ? '' : await r.text();
  return { status: r.status, finalUrl: r.url, redirected: r.redirected, headers: Object.fromEntries(r.headers), body, location: r.headers.get('location') };
}
// Page fetches follow redirects MANUALLY (re-evaluating headersFor each hop) so the token is
// never carried to an off-host redirect target.
async function followFetch(url, maxHops = 6) {
  let current = url, redirected = false;
  for (let i = 0; i < maxHops; i++) {
    const r = await fetch(current, { headers: headersFor(current), redirect: 'manual', signal: AbortSignal.timeout(25000) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { current = new URL(loc, current).href; redirected = true; continue; }
    return { status: r.status, finalUrl: current, redirected, headers: Object.fromEntries(r.headers), body: await r.text() };
  }
  throw new Error('too many redirects');
}
// Retry once on a NETWORK/timeout error (transient) — never on a real HTTP status.
async function fetchPage(url) {
  try { return await followFetch(url); }
  catch (e1) { await sleep(1500); try { return await followFetch(url); } catch (e2) { return { error: e2.message || String(e2) }; } }
}

// Manual redirect chain (≤5 hops) for one host variant.
async function probeRedirect(label, host, startUrl) {
  const chain = [];
  let url = startUrl;
  try {
    for (let i = 0; i < 5; i++) {
      const r = await fetchOnce(url, { redirect: 'manual', headOnly: true, timeout: 12000 });
      chain.push({ url, status: r.status, location: r.location });
      if (r.status >= 300 && r.status < 400 && r.location) { url = new URL(r.location, url).href; continue; }
      break;
    }
    return { label, host, variant: startUrl, chain };
  } catch (e) { return { label, host, variant: startUrl, error: e.message }; }
}

// ---- build the URL list ----
async function expandSitemap(sm) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = await fetchPage(sm);
    if (!r.error && r.status >= 200 && r.status < 300) {
      const locs = extractLocs(r.body);
      // a sitemap index points to child sitemaps — expand one level
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

  note('## 🔎 seo-aeo — SEO + AEO/GEO gate (JS-disabled crawler view)');
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
  if (CRITICAL_CHECKS.length) {
    const ok = CRITICAL_CHECKS.filter((c) => T1_CHECKS.has(c));
    const bad = CRITICAL_CHECKS.filter((c) => !T1_CHECKS.has(c));
    if (ok.length) note(`- promoted to critical (this caller): \`${ok.join('`, `')}\``);
    if (bad.length) note(`- ⚠️ ignored \`critical-checks\` (not promotable T1 checks): \`${bad.join('`, `')}\``);
  }
  note('');

  const promote = new Set(CRITICAL_CHECKS.filter((c) => T1_CHECKS.has(c)));
  const elevate = (finding) => (finding.sev === SEV.WARN && promote.has(finding.id)) ? { ...finding, sev: SEV.CRIT } : finding;

  let crit = 0, warn = 0, info = 0;
  const tally = (findings) => findings.forEach((x) => { if (x.sev === SEV.CRIT) crit++; else if (x.sev === SEV.WARN) warn++; else if (x.sev === SEV.INFO) info++; });
  const renderFindings = (findings, indent = '  ') => {
    for (const x of findings.filter((y) => y.sev !== SEV.OK).sort((a, b) => sevRank(a.sev) - sevRank(b.sev))) {
      note(`${indent}- ${ICON[x.sev]} \`${x.id}\` — ${safe(x.msg, 300)}`);
    }
  };

  // ---- per-page ----
  note('### Pages');
  const pages = [];
  for (const url of urls) {
    const r = await fetchPage(url);
    if (r.error) { note(`- ⚠️ ${safe(url)} — fetch failed (${safe(r.error, 120)}) — infra issue, not a content defect (not counted as critical)`); warn++; continue; }
    // WAF/auth challenge OR a transient server-side error: never a CONTENT defect — downgrade
    // to infra-WARN so a 5xx/timeout blip can't newly-block an enforcing caller (the old
    // `curl -fsSL` gate swallowed every non-2xx as a soft WARN; match that). Genuine content
    // 404/410 still falls through to analyzePage → http-200 CRITICAL.
    if ([401, 403, 408, 425, 429].includes(r.status) || (r.status >= 500 && r.status < 600)) {
      note(`- ⚠️ ${safe(url)} — origin returned HTTP ${r.status} (WAF/bot-challenge or transient origin error) — set \`verify-token\` if WAF-fronted; infra-WARN, not critical`);
      warn++; continue;
    }
    const res = analyzePage({ requestUrl: url, finalUrl: r.finalUrl, status: r.status, headers: r.headers, html: r.body });
    res.findings = res.findings.map(elevate);
    pages.push(res);
    tally(res.findings);
    const fails = res.findings.filter((x) => x.sev !== SEV.OK);
    const head = `${pageIcon(res.findings)} [${safe(res.url)}](${safe(res.url)})  \`HTTP ${res.status}\`${res.pageType ? ` · ${res.pageType}` : ''}${r.redirected ? ` · ↪ ${safe(res.finalUrl)}` : ''}`;
    note(`- ${head}`);
    if (fails.length) renderFindings(res.findings, '  ');
    else note(`  - ✅ title (${res.titleLen}) · ${res.h1Count} h1 · canonical · indexable`);
  }

  // ---- site-level (per distinct origin) ----
  const origins = [...new Set(pages.map((p) => { try { return new URL(p.finalUrl).origin; } catch { return null; } }).filter(Boolean))];
  note('');
  note('### Site files & hygiene');
  for (const origin of origins) {
    note(`**${safe(origin)}**`);
    const hostFindings = [];

    const robotsResp = await fetchPage(origin + '/robots.txt');
    const robotsRes = analyzeRobots(robotsResp.error ? { status: 0, body: '' } : robotsResp);
    hostFindings.push(...robotsRes.findings);

    // sitemap: prefer a Sitemap: directive, else probe common paths
    let smResp = { status: 0, body: '' };
    const smCandidates = [...(robotsRes.robots?.sitemaps || []), origin + '/sitemap_index.xml', origin + '/sitemap.xml', origin + '/sitemap-index.xml'];
    for (const sm of smCandidates) { const rr = await fetchPage(sm); if (!rr.error && rr.status >= 200 && rr.status < 300 && /<(sitemapindex|urlset)\b/i.test(rr.body)) { smResp = rr; break; } }
    hostFindings.push(analyzeSitemap(smResp));

    const llmsResp = await fetchPage(origin + '/llms.txt');
    hostFindings.push(...analyzeLlms(llmsResp.error ? { status: 0, body: '' } : llmsResp));

    // redirect hygiene
    let host = ''; try { host = new URL(origin).host; } catch { /* skip */ }
    if (host) {
      const apex = host.replace(/^www\./, ''); const www = host.startsWith('www.') ? host : 'www.' + host;
      const probes = await Promise.all([
        probeRedirect('http', host, `http://${host}/`),
        probeRedirect('host', host, `https://${host === www ? apex : www}/`),
      ]);
      hostFindings.push(...analyzeRedirects(probes));

      // trailing-slash consistency: toggle the slash on a sampled inner page; if BOTH forms
      // serve 200 (neither redirects to the other), the canonical form is ambiguous → advisory.
      const sample = pages.find((p) => { try { const u = new URL(p.finalUrl); return u.origin === origin && u.pathname.replace(/\/+$/, '') !== ''; } catch { return false; } });
      if (sample) {
        const u = new URL(sample.finalUrl);
        const toggled = u.pathname.endsWith('/') ? u.href.replace(/\/$/, '') : u.href + '/';
        const tp = await probeRedirect('slash', host, toggled);
        if (tp && !tp.error && tp.chain.length && tp.chain[0].status >= 200 && tp.chain[0].status < 300) {
          hostFindings.push({ id: 'trailing-slash', sev: SEV.INFO, msg: `both ${safe(sample.finalUrl)} and its ${u.pathname.endsWith('/') ? 'no-slash' : 'trailing-slash'} variant return 200 — pick one canonical form` });
        }
      }
    }

    const elevated = hostFindings.map(elevate);
    tally(elevated);
    const nonOk = elevated.filter((x) => x.sev !== SEV.OK);
    if (nonOk.length) renderFindings(elevated);
    else note('  - ✅ robots.txt · sitemap · llms.txt · redirects — all clean');
  }

  // ---- cross-page duplicate detection (group by canonical to exclude hreflang alternates) ----
  const dupNote = [];
  for (const [field, label] of [['title', 'title'], ['desc', 'meta description']]) {
    const byVal = new Map();
    for (const p of pages) {
      const v = (p[field] || '').trim(); if (!v) continue;
      const key = (p.canonical || p.finalUrl);
      if (!byVal.has(v)) byVal.set(v, new Set());
      byVal.get(v).add(key);
    }
    for (const [v, keys] of byVal) if (keys.size > 1) dupNote.push(`- ⚠️ \`duplicate-${field === 'title' ? 'title' : 'meta'}\` — ${keys.size} pages share the same ${label}: "${safe(v, 60)}"`);
  }
  // hreflang reciprocity within the sampled set: if A lists B as an alternate but B (also in
  // the sample) doesn't link back, the cluster is non-reciprocal (Google ignores one-way pairs).
  const byUrl = new Map(pages.map((p) => [norm2(p.finalUrl), new Set((p.hreflang || []).map((h) => norm2(h.href)).filter(Boolean))]));
  for (const p of pages) {
    const a = norm2(p.finalUrl);
    for (const h of (p.hreflang || [])) {
      const b = norm2(h.href);
      if (b && b !== a && byUrl.has(b) && !byUrl.get(b).has(a)) dupNote.push(`- ⚠️ \`hreflang-reciprocity\` — ${safe(p.finalUrl)} lists ${safe(h.href)} as an alternate, but that page doesn't link back`);
    }
  }
  // canonical-target resolution: a canonical pointing to a same-host URL that doesn't 200 is a
  // real, silent defect (and not covered by linkcheck, which only walks <a>/<img>). Only fetch
  // when the canonical differs from the page itself; same-host only (no token leak); bounded+deduped.
  const canonTargets = new Map();
  for (const p of pages) {
    if (!p.canonical) continue;
    let cu, fu; try { cu = new URL(p.canonical, p.finalUrl); fu = new URL(p.finalUrl); } catch { continue; }
    if (cu.host !== fu.host || norm2(cu.href) === norm2(fu.href)) continue;
    if (!canonTargets.has(norm2(cu.href))) canonTargets.set(norm2(cu.href), cu.href);
  }
  for (const href of [...canonTargets.values()].slice(0, 10)) {
    const r = await fetchPage(href);
    if (r.error || !(r.status >= 200 && r.status < 300)) dupNote.push(`- ⚠️ \`canonical-resolve\` — canonical target ${safe(href)} returned ${r.error ? 'a fetch error' : 'HTTP ' + r.status} (canonical points to a non-200 URL)`);
  }
  if (dupNote.length) { note(''); note('### Cross-page & canonical resolution'); [...new Set(dupNote)].forEach((d) => { note('  ' + d); warn++; }); }

  // ---- verdict ----
  note('');
  note(`**critical: ${crit} · warnings: ${warn} · info: ${info}**`);
  if (crit > 0 && FAIL_ON_CRITICAL) { note(`BLOCKED — ${crit} critical check(s) failed. Fix the ❌ items above.`); flush(); process.exit(1); }
  if (crit > 0) note(`report-only — ${crit} critical check(s) would BLOCK under \`fail-on-critical: true\`.`);
  else note('PASS — no critical issues.');
  flush(); process.exit(0);
})().catch((e) => { note(`- ❌ seo-aeo crashed: ${e.stack || e.message}`); flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0); });

function sevRank(s) { return { critical: 0, warn: 1, info: 2, ok: 3 }[s] ?? 9; }
function pageIcon(findings) {
  if (findings.some((x) => x.sev === SEV.CRIT)) return ICON.critical;
  if (findings.some((x) => x.sev === SEV.WARN)) return ICON.warn;
  return ICON.ok;
}
function flush() { fs.appendFileSync(summaryFile, lines.join('\n') + '\n'); }
