// seo-aeo agent-readiness analyzers — PURE functions, no network, no process exit.
// The CLI (check.mjs) fetches the site's agent-facing surface (Markdown negotiation, Link
// headers, the Agent Skills index, the ARD catalog, Content Signals, WebMCP, trust pages) and
// feeds the responses here; selftest.mjs covers every branch offline.
//
// Severity model (same contract as checks.mjs): a capability that is ABSENT is INFO — adoption
// is a roadmap item, never a defect; a capability that is PRESENT BUT BROKEN is WARN, because a
// scanner or agent that finds it will act on a wrong answer. Four of the WARNs are promotable
// (T1, listed in checks.mjs) so a caller that has adopted one can lock it in; INFO is never
// elevated, so promoting an ID cannot block a site that has not adopted it yet. The homepage
// entity checks (entity-fields, homepage-type-breadth) live in checks.mjs: they read the page's
// JSON-LD inside analyzePage.
import { createHash } from 'node:crypto';
import { load } from 'cheerio';
import { SEV } from './checks.mjs';

const f = (id, sev, msg) => ({ id, sev, msg });
const lower = (s) => String(s == null ? '' : s).toLowerCase();
const looksHtml = (body) => /^\s*(<!doctype html|<html\b)/i.test(String(body || '').slice(0, 300));
const ctype = (headers) => lower((headers || {})['content-type']).split(';')[0].trim();
const ok2xx = (s) => s >= 200 && s < 300;
export const sameSite = (a, b) => String(a || '').replace(/^www\./, '') === String(b || '').replace(/^www\./, '');

// ---------- homepage: Link headers, Markdown alternate, WebMCP forms, script bundles ----------

// RFC 8288 Link header → [{ href, rel, type }]. Tolerates several headers joined by ", ".
export function parseLinkHeader(value) {
  const out = [];
  for (const m of String(value || '').matchAll(/<([^>]*)>\s*((?:;\s*[^;,]+)*)/g)) {
    const params = {};
    for (const p of m[2].split(';').map((x) => x.trim()).filter(Boolean)) {
      const kv = p.match(/^([a-z*-]+)\s*=\s*"?([^"]*)"?$/i);
      if (kv) params[kv[1].toLowerCase()] = kv[2];
    }
    out.push({ href: m[1], rel: lower(params.rel), type: lower(params.type) });
  }
  return out;
}

// input: { finalUrl, headers, html } of the homepage fetched as a browser would (Accept: text/html).
// Returns { findings, scripts (same-origin bundle URLs, capped), webmcpInline, toolForms }.
// The rels an agent follows to the site's machine-readable surface. WordPress sends
// rel="https://api.w.org/" (REST discovery) on every page, and shortlink, preload, preconnect and a
// language alternate are for browsers and crawlers: none of them is this layer, so a homepage that
// sends only those has not adopted it.
const AGENT_RELS = new Set(['sitemap', 'describedby', 'api-catalog', 'service-desc', 'service-doc', 'ard', 'ai-catalog']);
const relsOf = (l) => l.rel.split(/\s+/).filter(Boolean);
const agentRels = (l) => [...relsOf(l).filter((r) => AGENT_RELS.has(r)),
  ...(relsOf(l).includes('alternate') && l.type === 'text/markdown' ? ['alternate (text/markdown)'] : [])];

export function analyzeAgentHome({ finalUrl, headers = {}, html = '' }) {
  const findings = [];
  const links = parseLinkHeader(headers.link);
  const rels = [...new Set(links.flatMap(agentRels))];
  if (!links.length) findings.push(f('agent-link-headers', SEV.INFO, 'homepage sends no Link: header — advertise the sitemap, llms.txt and the Markdown alternate (RFC 8288) so agents find them without crawling'));
  else if (!rels.length) findings.push(f('agent-link-headers', SEV.INFO, `homepage Link: header carries only ${[...new Set(links.flatMap(relsOf))].slice(0, 4).join(', ') || 'links without rel'} — none an agent follows: advertise the sitemap, llms.txt and the Markdown alternate (RFC 8288)`));
  else findings.push(f('agent-link-headers', SEV.OK, `Link: header advertises ${rels.join(', ')}`));

  const $ = load(html);
  let origin = ''; try { origin = new URL(finalUrl).origin; } catch { /* none */ }
  const mdAlt = $('link[rel~="alternate"][type="text/markdown"]').attr('href') || links.find((l) => l.rel.split(/\s+/).includes('alternate') && l.type === 'text/markdown')?.href || '';
  const toolForms = $('form[toolname]').length;
  const webmcpInline = $('script:not([src])').toArray().some((el) => /modelContext/.test($(el).text()) && /registerTool|provideContext/.test($(el).text()));
  const scripts = [];
  $('script[src]').each((i, el) => {
    try { const u = new URL($(el).attr('src'), finalUrl); if (u.origin === origin && scripts.length < 6) scripts.push(u.href); } catch { /* skip */ }
  });
  // <link rel=modulepreload> bundles are executed too (Astro/Vite hoist the real entry there)
  $('link[rel="modulepreload"][href]').each((i, el) => {
    try { const u = new URL($(el).attr('href'), finalUrl); if (u.origin === origin && scripts.length < 6 && !scripts.includes(u.href)) scripts.push(u.href); } catch { /* skip */ }
  });
  return { findings, scripts, webmcpInline, toolForms, mdAlternate: mdAlt };
}

// WebMCP: declarative tool forms, or an imperative registerTool in an inline/same-origin script.
// bundles: [{ url, body }] — same-origin scripts the CLI fetched (capped).
export function analyzeWebmcp({ toolForms = 0, webmcpInline = false, bundles = [] }) {
  const hit = bundles.find((b) => /modelContext/.test(b.body || '') && /registerTool|provideContext/.test(b.body || ''));
  if (toolForms || webmcpInline || hit) {
    const how = [toolForms ? `${toolForms} declarative tool form(s)` : '', webmcpInline ? 'an inline registerTool' : '', hit ? 'registerTool in a same-origin bundle' : ''].filter(Boolean).join(' + ');
    return [f('agent-webmcp', SEV.OK, `WebMCP tools registered (${how})`)];
  }
  return [f('agent-webmcp', SEV.INFO, `no WebMCP tools on the homepage (no form with a toolname attribute, no document.modelContext.registerTool in ${bundles.length} same-origin bundle(s)) — browsing agents must scrape instead of calling tools`)];
}

// ---------- Markdown for agents ----------

// The homepage fetched with Accept: text/markdown.
export function analyzeMarkdownNegotiation({ status, headers = {}, body = '' }, { mdAlternate = '' } = {}) {
  const ct = ctype(headers), vary = lower(headers.vary);
  if (!ok2xx(status)) return [f('agent-markdown', SEV.INFO, `homepage with Accept: text/markdown returned HTTP ${status} — no Markdown negotiation`)];
  if (ct !== 'text/markdown') {
    return [f('agent-markdown', SEV.INFO, `homepage ignores Accept: text/markdown (served ${ct || 'no content-type'})${mdAlternate ? ' — a Markdown alternate is linked, but the URL itself does not negotiate' : ''}: serve a Markdown twin with Content-Type: text/markdown and Vary: Accept`)];
  }
  const out = [];
  if (looksHtml(body)) out.push(f('agent-markdown', SEV.WARN, 'Accept: text/markdown is answered with Content-Type text/markdown but an HTML body — the twin is not Markdown'));
  else if (String(body).trim().length < 50) out.push(f('agent-markdown', SEV.WARN, `Markdown twin of the homepage is nearly empty (${String(body).trim().length} chars)`));
  if (!/(^|,)\s*accept\s*(,|$)/.test(vary)) out.push(f('agent-markdown', SEV.WARN, `Markdown is negotiated but Vary lacks Accept (got "${vary || 'none'}") — a shared cache can serve the Markdown to browsers`));
  if (!out.length) out.push(f('agent-markdown', SEV.OK, 'homepage negotiates Markdown (text/markdown + Vary: Accept)'));
  return out;
}

// A path that cannot exist, fetched with Accept: text/markdown. Graded only once the homepage
// negotiates Markdown (adopted), except a 200 for a nonexistent path, which is a soft-404 either way.
export function analyzeMarkdown404({ status, headers = {}, body = '' }, { adopted = false } = {}) {
  if (ok2xx(status)) return [f('agent-markdown-404', SEV.WARN, `a nonexistent path returns HTTP ${status} (soft-404) — agents and crawlers read it as a real page`)];
  if (!adopted) return [];
  if (status !== 404 && status !== 410) return [f('agent-markdown-404', SEV.INFO, `a nonexistent path returns HTTP ${status}, not 404`)];
  if (ctype(headers) !== 'text/markdown' || looksHtml(body) || String(body).trim().length < 20) {
    return [f('agent-markdown-404', SEV.INFO, '404 answers Accept: text/markdown with HTML — give agents a short Markdown error (≥20 chars) that links /llms.txt or the sitemap')];
  }
  return [f('agent-markdown-404', SEV.OK, '404 serves a Markdown error body')];
}

// ---------- robots.txt Content Signals ----------

const CS_KEYS = new Set(['search', 'ai-input', 'ai-train']);
export function analyzeContentSignal(robotsBody) {
  const lines = String(robotsBody || '').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter((l) => /^content-signal\s*:/i.test(l));
  if (!lines.length) return [f('agent-content-signal', SEV.INFO, 'robots.txt declares no Content-Signal (search / ai-input / ai-train) — the site\'s AI-usage preference is unstated')];
  const bad = [], seen = {};
  for (const l of lines) {
    for (const pair of l.replace(/^content-signal\s*:/i, '').split(',').map((x) => x.trim()).filter(Boolean)) {
      const m = pair.match(/^([a-z-]+)\s*=\s*([a-z]+)$/i);
      if (!m || !CS_KEYS.has(m[1].toLowerCase()) || !/^(yes|no)$/i.test(m[2])) bad.push(pair);
      else seen[m[1].toLowerCase()] = m[2].toLowerCase();
    }
  }
  if (bad.length) return [f('agent-content-signal', SEV.WARN, `malformed Content-Signal entr${bad.length > 1 ? 'ies' : 'y'}: ${bad.slice(0, 3).join(' ; ')} — keys search / ai-input / ai-train, values yes / no`)];
  return [f('agent-content-signal', SEV.OK, `Content-Signal: ${Object.entries(seen).map(([k, v]) => `${k}=${v}`).join(', ')}`)];
}

// ---------- llms.txt agent guidance ----------

export function analyzeLlmsGuidance({ status, body = '' }) {
  if (!ok2xx(status) || looksHtml(body)) return []; // llms-txt already reports the missing file
  const h2 = String(body).split(/\r?\n/).filter((l) => /^##\s+\S/.test(l));
  if (h2.some((l) => /when to use|for (ai )?agents?\b|agent instructions|how (an )?agents?\b/i.test(l))) return [f('agent-llms-guidance', SEV.OK, 'llms.txt carries an agent "when to use" section')];
  return [f('agent-llms-guidance', SEV.INFO, 'llms.txt has no "## When to use (for AI agents)" section — name the jobs the site is right for and how an agent should act (search URL, cart link, contact)')];
}

// ---------- Agent Skills discovery (agent-skills RFC v0.2.0) ----------

export const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Phase 1: the index response → { findings, entries } (entries for the CLI to fetch).
export function parseSkillsIndex({ status, headers = {}, body = '' }) {
  if (status === 404 || status === 410 || status === 0) return { findings: [f('agent-skills-index', SEV.INFO, 'no /.well-known/agent-skills/index.json — agents cannot discover what the site can do for them (Agent Skills discovery RFC v0.2.0)')], entries: [] };
  if (!ok2xx(status)) return { findings: [f('agent-skills-index', SEV.WARN, `/.well-known/agent-skills/index.json returned HTTP ${status}`)], entries: [] };
  if (looksHtml(body)) return { findings: [f('agent-skills-index', SEV.WARN, '/.well-known/agent-skills/index.json serves HTML with a 2xx (soft-404) — scanners read that as a broken index')], entries: [] };
  let doc;
  try { doc = JSON.parse(String(body).replace(/^﻿/, '')); } catch (e) { return { findings: [f('agent-skills-index', SEV.WARN, `agent-skills index is not valid JSON (${String(e.message).slice(0, 60)})`)], entries: [] }; }
  const findings = [];
  if (ctype(headers) !== 'application/json') findings.push(f('agent-skills-index', SEV.WARN, `agent-skills index served as ${ctype(headers) || 'no content-type'} (want application/json)`));
  if (!/agentskills\.io\/discovery\//.test(String(doc.$schema || ''))) findings.push(f('agent-skills-index', SEV.WARN, 'agent-skills index has no "$schema" naming the agentskills.io discovery schema'));
  const skills = Array.isArray(doc.skills) ? doc.skills : null;
  if (!skills || !skills.length) { findings.push(f('agent-skills-index', SEV.WARN, 'agent-skills index lists no skills')); return { findings, entries: [] }; }
  const entries = [];
  skills.forEach((s, i) => {
    const tag = `skill #${i + 1}${s && s.name ? ` "${String(s.name).slice(0, 40)}"` : ''}`;
    const errs = [];
    if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(String(s?.name || '')) || String(s.name).length > 64) errs.push('name (1-64 lowercase-kebab)');
    if (!['skill-md', 'archive'].includes(s?.type)) errs.push('type (skill-md|archive)');
    if (!s?.description || String(s.description).length > 1024) errs.push('description (1-1024 chars)');
    if (!s?.url) errs.push('url');
    if (!/^sha256:[0-9a-f]{64}$/.test(String(s?.digest || ''))) errs.push('digest (sha256:<64 hex>)');
    if (errs.length) findings.push(f('agent-skills-index', SEV.WARN, `${tag}: invalid ${errs.join(', ')}`));
    if (s?.url) entries.push({ tag, url: String(s.url), type: s.type, digest: String(s.digest || '') });
  });
  return { findings, entries };
}

// Phase 2: grade each fetched artifact. artifacts: [{ tag, url, type, digest, status, headers, bytes, offSite }]
export function gradeSkillArtifacts(artifacts, indexFindings = []) {
  const findings = [];
  for (const a of artifacts) {
    if (a.offSite) { findings.push(f('agent-skills-index', SEV.INFO, `${a.tag}: url is on another host — not fetched (digest unverified)`)); continue; }
    if (!ok2xx(a.status)) { findings.push(f('agent-skills-index', SEV.WARN, `${a.tag}: ${a.url} returned HTTP ${a.status || 'fetch error'}`)); continue; }
    if (a.type === 'skill-md' && !['text/markdown', 'text/plain'].includes(ctype(a.headers))) findings.push(f('agent-skills-index', SEV.WARN, `${a.tag}: SKILL.md served as ${ctype(a.headers) || 'no content-type'} (want text/markdown)`));
    if (/^sha256:[0-9a-f]{64}$/.test(a.digest) && sha256hex(a.bytes) !== a.digest.slice(7)) findings.push(f('agent-skills-index', SEV.WARN, `${a.tag}: digest does not match the served bytes — regenerate the index at build time`));
  }
  const broken = [...indexFindings, ...findings].some((x) => x.sev === SEV.WARN);
  const verified = artifacts.filter((a) => !a.offSite).length;   // an off-site skill was never fetched: no claim about it
  if (!broken && verified) findings.push(f('agent-skills-index', SEV.OK, `agent-skills index lists ${artifacts.length} skill(s); ${verified} digest(s) verified against the bytes served`));
  return findings;
}

// ---------- Agentic Resource Discovery (ARD v0.91 / AI Catalog) ----------

// primary: /.well-known/ard.json, alias: /.well-known/ai-catalog.json — { status, headers, body } each.
export function analyzeArd(primary, alias, host) {
  const live = [['ard.json', primary], ['ai-catalog.json', alias]].filter(([, r]) => r && ok2xx(r.status) && !looksHtml(r.body));
  const soft = [['ard.json', primary], ['ai-catalog.json', alias]].filter(([, r]) => r && ok2xx(r.status) && looksHtml(r.body));
  if (soft.length) return [f('agent-ard', SEV.WARN, `/.well-known/${soft[0][0]} serves HTML with a 2xx (soft-404) — scanners read that as a broken catalog`)];
  if (!live.length) return [f('agent-ard', SEV.INFO, 'no /.well-known/ard.json (or ai-catalog.json) — publish an Agentic Resource Discovery catalog listing the site\'s skills')];
  const [name, r] = live[0];
  let doc;
  try { doc = JSON.parse(String(r.body).replace(/^﻿/, '')); } catch (e) { return [f('agent-ard', SEV.WARN, `/.well-known/${name} is not valid JSON (${String(e.message).slice(0, 60)})`)]; }
  const out = [];
  const entries = Array.isArray(doc.entries) ? doc.entries : null;
  if (!entries || !entries.length) out.push(f('agent-ard', SEV.WARN, `/.well-known/${name} has no entries`));
  (entries || []).forEach((e, i) => {
    const errs = [];
    const m = String(e?.identifier || '').match(/^urn:air:([^:]+):/);
    if (!m) errs.push('identifier (urn:air:<domain>:…)');
    else if (host && !sameSite(m[1].toLowerCase(), host.toLowerCase())) errs.push(`identifier domain ${m[1]} ≠ ${host}`);
    if (!e?.displayName) errs.push('displayName');
    if (!/^[a-z]+\/[a-z0-9.+-]+$/i.test(String(e?.type || ''))) errs.push('type (a media type)');
    if ((e?.url !== undefined) === (e?.data !== undefined)) errs.push('exactly one of url / data');
    if (errs.length) out.push(f('agent-ard', SEV.WARN, `${name} entry #${i + 1}: invalid ${errs.join(', ')}`));
  });
  if (live.length === 1) out.push(f('agent-ard', SEV.INFO, `catalog served only at /.well-known/${name} — serve the same document at /.well-known/${name === 'ard.json' ? 'ai-catalog.json' : 'ard.json'} too (both names are read)`));
  if (!out.some((x) => x.sev === SEV.WARN)) out.push(f('agent-ard', SEV.OK, `ARD catalog lists ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}`));
  return out;
}

// ---------- trust pages (/about, /contact, /privacy) ----------

// pages: [{ path, status, finalUrl, html, offSite }]
export function analyzeTrustPages(pages) {
  const missing = [];
  for (const p of pages) {
    if (p.offSite || !ok2xx(p.status)) { missing.push(p.path); continue; }
    const $ = load(p.html || '');
    $('script, style, noscript, template, nav, header, footer').remove();
    const text = ($('main').text() || $('body').text()).replace(/\s+/g, ' ').trim();
    if (text.length < 500) missing.push(`${p.path} (${text.length} chars)`);
  }
  if (!missing.length) return [f('agent-trust-pages', SEV.OK, '/about, /contact, /privacy resolve with real content')];
  return [f('agent-trust-pages', SEV.INFO, `trust pages agents look for are missing or thin: ${missing.join(', ')} — a 301 alias from the English path to the localized page is enough`)];
}

// ---------- sitemap lastmod ----------

export function analyzeSitemapLastmod(urlsetXml) {
  const xml = String(urlsetXml || '');
  const urls = (xml.match(/<url>/gi) || []).length;
  if (!urls) return [];
  const dated = (xml.match(/<lastmod>\s*[^<\s]+\s*<\/lastmod>/gi) || []).length;
  if (!dated) return [f('sitemap-lastmod', SEV.INFO, `none of ${urls} sitemap entries carries a lastmod date — agents and crawlers cannot tell what changed`)];
  return [f('sitemap-lastmod', SEV.OK, `${dated}/${urls} sitemap entries carry a lastmod date`)];
}
