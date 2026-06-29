// contract-check CLI — fetches each consumed WP/WC REST endpoint as raw JSON (the
// consumer's-eye view), runs the contract engine (checks.mjs), renders a per-endpoint
// report to GITHUB_STEP_SUMMARY, and exits non-zero only when a CRITICAL check fails AND
// fail-on-critical is set. Air-gapped: only touches the configured endpoints.
import fs from 'node:fs';
import path from 'node:path';
import { SEV, T1_CHECKS, analyzePayload } from './checks.mjs';

const env = process.env;
const FAIL_ON_CRITICAL = env.FAIL_ON_CRITICAL === 'true';
const MAX_ENDPOINTS = Math.max(1, parseInt(env.MAX_ENDPOINTS || '25', 10) || 25);
const VERIFY_TOKEN = env.VERIFY_TOKEN || '';
const CRITICAL_CHECKS = (env.CRITICAL_CHECKS || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const lines = [];
const note = (s = '') => lines.push(s);
const ICON = { critical: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };

// Neutralize page/payload-controlled strings before they reach the markdown summary: strip
// CR/LF + markdown-structural chars + cap length so a hostile field value (a product name, a
// slug, an error string) can't forge verdict lines or inject an image beacon into the job
// summary (report-spoofing guard) — same posture as seo-aeo's safe().
const safe = (s, max = 220) => String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/[`|<>[\]]/g, '').slice(0, max);

const baseHeaders = {
  accept: 'application/json',
  'user-agent': 'Mozilla/5.0 (compatible; ci-actions-contract-check/1.0; +https://github.com/mvalasis/ci-actions)',
};
// The WAF-bypass token + LiteSpeed cookie go ONLY to the configured endpoint hosts and their
// www/apex variants — never to a redirect target on another origin. undici forwards custom
// headers across cross-origin redirects (it only strips Cookie/Authorization), so we gate the
// token by host ourselves and follow redirects MANUALLY to re-scope it per hop.
const TOKEN_HEADERS = VERIFY_TOKEN ? { 'x-verify-source': VERIFY_TOKEN, cookie: '_lscache_vary=1' } : {};
const ALLOWED_HOSTS = new Set();
const addHost = (u) => { try { const h = new URL(u).host, apex = h.replace(/^www\./, ''); [h, apex, 'www.' + apex].forEach((x) => ALLOWED_HOSTS.add(x)); } catch { /* ignore */ } };
function headersFor(url) {
  let host = ''; try { host = new URL(url).host; } catch { /* none */ }
  return ALLOWED_HOSTS.has(host) ? { ...baseHeaders, ...TOKEN_HEADERS } : { ...baseHeaders };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Fetch following redirects MANUALLY (re-evaluating headersFor each hop) so the token is never
// carried to an off-host redirect target. Returns { status, finalUrl, contentType, body }.
async function followFetch(url, maxHops = 6) {
  let current = url, redirected = false;
  for (let i = 0; i < maxHops; i++) {
    const r = await fetch(current, { headers: headersFor(current), redirect: 'manual', signal: AbortSignal.timeout(25000) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { current = new URL(loc, current).href; redirected = true; continue; }
    return { status: r.status, finalUrl: current, redirected, contentType: r.headers.get('content-type') || '', body: await r.text() };
  }
  throw new Error('too many redirects');
}
// Retry once on a NETWORK/timeout error (transient) — never on a real HTTP status.
async function fetchJson(url) {
  let r;
  try { r = await followFetch(url); }
  catch (e1) { await sleep(1500); try { r = await followFetch(url); } catch (e2) { return { error: e2.message || String(e2) }; } }
  let json, parseError;
  try { json = JSON.parse(r.body); } catch (e) { parseError = e.message || String(e); }
  return { status: r.status, finalUrl: r.finalUrl, redirected: r.redirected, contentType: r.contentType, json, parseError };
}

// ---- build the endpoint list: `endpoints` (name->url map) and/or a committed `manifest` file ----
// manifest schema: { "endpoints": [ { "name", "url", "required":[], "types":{}, "invariants":[],
//   "optional":[], "money":[], "slug":[], "nonEmpty":bool, "expectFields":[], "allowExtra":bool } ] }
function loadEndpoints() {
  const items = [];
  // 1) inline endpoints map (name -> url) — contract is then minimal (encoding/transport floors only)
  if (env.ENDPOINTS) {
    let map;
    try { map = JSON.parse(env.ENDPOINTS); } catch (e) { return { items, error: `endpoints input is not valid JSON: ${e.message}` }; }
    for (const [name, url] of Object.entries(map || {})) items.push({ name, url, contract: {} });
  }
  // 2) committed manifest file (the rich contract source)
  if (env.MANIFEST) {
    const p = path.isAbsolute(env.MANIFEST) ? env.MANIFEST : path.join(env.GITHUB_WORKSPACE || process.cwd(), env.MANIFEST);
    let doc;
    try { doc = JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return { items, error: `manifest ${env.MANIFEST}: ${e.message}` }; }
    const eps = Array.isArray(doc) ? doc : (Array.isArray(doc.endpoints) ? doc.endpoints : []);
    for (const e of eps) {
      if (!e || !e.url) continue;
      const { url, name, ...contract } = e;
      items.push({ name: name || url, url, contract });
    }
  }
  return { items, error: null };
}

function sevRank(s) { return { critical: 0, warn: 1, info: 2, ok: 3 }[s] ?? 9; }
function rowIcon(findings) {
  if (findings.some((x) => x.sev === SEV.CRIT)) return ICON.critical;
  if (findings.some((x) => x.sev === SEV.WARN)) return ICON.warn;
  return ICON.ok;
}
function flush() { fs.appendFileSync(summaryFile, lines.join('\n') + '\n'); }

(async () => {
  const { items, error } = loadEndpoints();
  const inputGiven = !!(env.ENDPOINTS || env.MANIFEST);

  note('## 🔌 contract-check — WP/WC REST consumer-contract gate');
  note('');

  if (error) {
    note(`- ❌ **config error** — ${safe(error, 200)}`);
    note('');
    note('**critical: 1 · warnings: 0**');
    note(FAIL_ON_CRITICAL ? 'BLOCKED — bad config.' : 'report-only — would BLOCK under fail-on-critical.');
    flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0);
  }
  if (!inputGiven) { note('- no `endpoints`/`manifest` configured — nothing to check (skipped)'); flush(); process.exit(0); }

  // de-dupe by url, cap, register allowed hosts for the token
  const seen = new Set();
  let list = items.filter((e) => e.url && !seen.has(e.url) && seen.add(e.url));
  const truncated = list.length > MAX_ENDPOINTS;
  list = list.slice(0, MAX_ENDPOINTS);
  list.forEach((e) => addHost(e.url));

  if (list.length === 0) {
    note('- ❌ **no endpoints resolved** — `endpoints`/`manifest` was set but expanded to nothing.');
    note('');
    note('**critical: 1 · warnings: 0**');
    note(FAIL_ON_CRITICAL ? 'BLOCKED — gate checked nothing.' : 'report-only — would BLOCK under fail-on-critical.');
    flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0);
  }

  note(`- mode: ${FAIL_ON_CRITICAL ? '**BLOCK on critical**' : 'report-only (never blocks)'}`);
  note(`- endpoints checked: ${list.length}${truncated ? ` (capped at max-endpoints=${MAX_ENDPOINTS})` : ''}`);
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

  note('### Endpoints');
  for (const ep of list) {
    const r = await fetchJson(ep.url);
    if (r && r.error) {
      // a network/timeout error is infra, not a contract defect — downgrade to WARN so a
      // transient blip can't newly-block an enforcing caller (mirrors seo-aeo).
      note(`- ⚠️ **${safe(ep.name)}** — fetch failed (${safe(r.error, 120)}) — infra issue, not a contract defect (not counted as critical)`);
      warn++; continue;
    }
    // WAF/auth challenge OR a transient server error: infra-WARN, never a contract break.
    if ([401, 403, 408, 425, 429].includes(r.status) || (r.status >= 500 && r.status < 600)) {
      note(`- ⚠️ **${safe(ep.name)}** — origin returned HTTP ${r.status} (WAF/bot-challenge or transient origin error) — set \`verify-token\` if WAF-fronted; infra-WARN, not critical`);
      warn++; continue;
    }
    const res = analyzePayload({ name: ep.name, url: ep.url, status: r.status, json: r.json, parseError: r.parseError, contract: ep.contract });
    res.findings = res.findings.map(elevate);
    tally(res.findings);
    const fails = res.findings.filter((x) => x.sev !== SEV.OK);
    const head = `${rowIcon(res.findings)} **${safe(ep.name)}** — [${safe(ep.url)}](${safe(ep.url)})  \`HTTP ${r.status}\`${r.redirected ? ` · ↪ ${safe(r.finalUrl)}` : ''}`;
    note(`- ${head}`);
    if (fails.length) {
      for (const x of fails.sort((a, b) => sevRank(a.sev) - sevRank(b.sev))) note(`  - ${ICON[x.sev]} \`${x.id}\` — ${safe(x.msg, 300)}`);
    } else {
      const reqN = (ep.contract.required || []).length;
      note(`  - ✅ ${reqN} required field(s) present & typed · money/encoding invariants hold`);
    }
  }

  // ---- verdict ----
  note('');
  note(`**critical: ${crit} · warnings: ${warn} · info: ${info}**`);
  if (crit > 0 && FAIL_ON_CRITICAL) { note(`BLOCKED — ${crit} critical contract break(s). A consumed payload changed shape/price/encoding. Fix the ❌ items above.`); flush(); process.exit(1); }
  if (crit > 0) note(`report-only — ${crit} critical contract break(s) would BLOCK under \`fail-on-critical: true\`.`);
  else note('PASS — every consumed payload still satisfies its contract.');
  flush(); process.exit(0);
})().catch((e) => { note(`- ❌ contract-check crashed: ${e.stack || e.message}`); flush(); process.exit(FAIL_ON_CRITICAL ? 1 : 0); });
