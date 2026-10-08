// agent-benchmark — what two public agent-readiness scanners say about a site: ora.ai's score (0-100,
// graded, four layers) and Cloudflare's isitagentready.com level. seo-aeo grades the agent layer itself,
// air-gapped and promotable; this action asks the outside graders, for the trend and the order of work.
// REPORT-ONLY: it always exits 0, and a scanner that could not look is listed as such, never as a score.
// Not air-gapped, by design: the target URL goes to both services and nothing else does (no token, no
// header of the caller's). ora.ai lists every scan it runs on its public leaderboard.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const env = process.env;
// The report reaches the job log line by line through fd 1 (never by opening /dev/stdout: ENXIO when
// stdout is a socket) and the step summary at the end. `/dev/stdout` as the summary (the local idiom)
// means none.
const summaryFile = env.GITHUB_STEP_SUMMARY && env.GITHUB_STEP_SUMMARY !== '/dev/stdout' ? env.GITHUB_STEP_SUMMARY : '';
const lines = [];
let summaryWritten = false;

// Armed before anything that can fault. Report-only, so a fault in this tool exits 0: the report so far
// is already in the log, the fault is named there on one line, and the summary gets what it lacks.
// Everything the handler touches is declared above it or is a hoisted function declaration.
process.on('uncaughtException', crashed);
process.on('unhandledRejection', crashed);
function crashed(e) {
  const line = `- ❌ agent-benchmark crashed: ${safe((e && e.stack) || e, 400)}`;
  say(line);
  if (summaryFile) {
    try { fs.appendFileSync(summaryFile, `${summaryWritten ? line : [...lines, line].join('\n')}\n`); } catch { /* the job log has it */ }
  }
  process.exit(0);
}
function say(s = '') { try { fs.writeSync(1, `${s}\n`); } catch { /* stdout closed: nowhere left to say it */ } }
function note(s = '') { lines.push(s); say(s); }

// Every scanner string is untrusted: a check id, a recommendation, a level name, an error message.
// Control characters and line/paragraph separators become one space (a new line in the job log could
// start a workflow command); backtick, |, <, >, [ and ] go (no forged code span, table cell, HTML or
// link/image beacon in the summary, and no legacy `##[command]` anywhere). Every line starts with our
// own text, so no scanner string can start one.
function safe(s, max = 200) {
  return String(s == null ? '' : s).replace(/[\p{Cc}\p{Zl}\p{Zp}]+/gu, ' ').replace(/[`|<>[\]]/g, '').trim().slice(0, max);
}
// Workflow-command data encoding (@actions/core's): a `%` stays literal, a line break cannot end the command.
const escapeData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

const posInt = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : d; };
const on = (v) => String(v ?? '').trim().toLowerCase() !== 'false';
// The bases and the timing are env-overridable for the offline self-test, which stands both scanners
// up on 127.0.0.1. action.yml passes none of them.
const ORA_BASE = (env.AGENT_BENCHMARK_ORA_BASE || 'https://ora.ai').replace(/\/+$/, '');
const IIAR_BASE = (env.AGENT_BENCHMARK_IIAR_BASE || 'https://isitagentready.com').replace(/\/+$/, '');
const TIMEOUT_MS = posInt(env.AGENT_BENCHMARK_TIMEOUT_MS, 120000);    // ora scores within the request: ~10 s seen
const POLL_MS = posInt(env.AGENT_BENCHMARK_POLL_MS, 20000);            // ora's GET allows 10 a minute per IP
const POLL_MAX_MS = posInt(env.AGENT_BENCHMARK_POLL_MAX_MS, 240000);
const MAX_BYTES = 5 * 1024 * 1024;                                      // a full ora audit is ~65 KB
const UA = 'ci-actions-agent-benchmark/1.0 (+https://github.com/mvalasis/ci-actions)';
const GRADE = /^[A-F][+-]?$/;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const num = (n) => (Number.isFinite(n) ? String(Math.round(n * 10) / 10) : '?');
const has = (o, k) => !!o && typeof o === 'object' && Object.hasOwn(o, k);
function dur(sec) {
  if (sec < 90) return `${Math.round(sec)} s`;
  if (sec < 90 * 60) return `${Math.round(sec / 60)} min`;
  if (sec < 36 * 3600) return `${Math.round(sec / 3600)} h`;
  return `${Math.round(sec / 86400)} d`;
}

// The site as both scanners receive it: http(s) only, no credentials, no fragment.
function targetOf(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u; try { u = new URL(s); } catch { return null; }
  if (!/^https?:$/.test(u.protocol) || !u.hostname) return null;
  u.username = ''; u.password = ''; u.hash = '';
  return u;
}

// One request to a scanner. Never throws: a network error, a timeout or an oversized body comes back as
// `error`, which the leg reports as could-not-look. `json` is null when the body is not JSON.
async function call(method, url, body) {
  try {
    const r = await fetch(url, {
      method,
      headers: { 'user-agent': UA, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const chunks = [];
    let size = 0;
    if (r.body) {
      for await (const c of r.body) {
        size += c.length;
        if (size > MAX_BYTES) return { status: r.status, error: `answered with over ${MAX_BYTES / 1048576} MB` };
        chunks.push(c);
      }
    }
    const text = Buffer.concat(chunks).toString('utf8');
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON: the leg says so */ }
    return { status: r.status, json, retryAfter: r.headers.get('retry-after') };
  } catch (e) {
    if (e && e.name === 'TimeoutError') return { error: `no answer within ${Math.round(TIMEOUT_MS / 1000)} s` };
    return { error: safe((e && e.cause && (e.cause.code || e.cause.message)) || (e && e.message) || e, 120) };
  }
}

// Why a response is not a reading: the transport error, the HTTP status, or the missing field.
function why(r, what) {
  if (r.error) return r.error;
  const msg = r.json && typeof r.json === 'object' ? (r.json.error || r.json.message || r.json.code) : '';
  const tail = msg ? ` (${safe(msg, 120)})` : '';
  if (r.status !== 200 && r.status !== 202) return `HTTP ${r.status}${tail}`;
  if (r.json === null) return `HTTP ${r.status}, but the answer is not JSON`;
  return `HTTP ${r.status}, but the answer has no ${what}${tail}`;
}

// ---- ora.ai: POST /api/scan?format=audit (the versioned audit contract) ----
const isAudit = (j) => !!j && typeof j === 'object' && Number.isFinite(j.score) && Array.isArray(j.layers);
const settled = (a) => a.analysisStatus !== 'partial';   // complete, or stuck: nothing more is coming
const when = (a) => { const t = Date.parse(a && a.scannedAt); return Number.isFinite(t) ? t : 0; };
const hostname = (h) => (typeof h === 'string' && h.length <= 253
  && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(h) ? h : '');

async function ora(target) {
  // Only `url`: never `force` (6 a day per IP), never `ephemeral` (refused for a domain ora already
  // stores). A stored result younger than ora's default window (6 h) comes back as is and costs no quota.
  const scan = () => call('POST', `${ORA_BASE}/api/scan?format=audit`, { url: target.href });
  let r = await scan();
  // 429 is the 10-a-minute burst cap or the per-IP daily quota (30 scans). A short Retry-After is the
  // burst cap: wait it out once. A long one is the quota: ora's last stored result is still a reading.
  if (r.status === 429) {
    const wait = Number(r.retryAfter);
    if (r.retryAfter !== null && Number.isFinite(wait) && wait >= 0 && wait <= 60) { await sleep(wait * 1000); r = await scan(); }
  }
  const scoreUrl = `${ORA_BASE}/api/score/${encodeURIComponent(hostname(r.json && r.json.domain) || target.hostname)}?format=audit`;
  if (r.status === 429) {
    const s = await call('GET', scoreUrl);
    if (s.status === 200 && isAudit(s.json)) return { looked: true, via: 'stored', audit: s.json, polls: 0 };
    return { looked: false, why: `rate-limited (HTTP 429), and ${s.status === 404 ? 'ora has no stored result for this domain' : `its stored result could not be read: ${why(s, 'score')}`}` };
  }
  if ((r.status !== 200 && r.status !== 202) || !isAudit(r.json)) return { looked: false, why: why(r, 'score') };
  // 202: scored, deeper analysis still running. Poll the stored result until it settles. That GET is
  // served through a CDN that caches a 200 for an hour, so an answer OLDER than the scan in hand is a
  // cached copy of an earlier scan, never the answer: it is ignored and the scan in hand stays.
  let audit = r.json, polls = 0;
  const deadline = Date.now() + POLL_MAX_MS;
  while (!settled(audit) && Date.now() < deadline) {
    await sleep(Math.min(POLL_MS, Math.max(0, deadline - Date.now())));
    polls++;
    const p = await call('GET', scoreUrl);
    if (p.status === 200 && isAudit(p.json) && when(p.json) >= when(audit)) audit = p.json;
  }
  return { looked: true, via: audit.servedFromCache === true ? 'cache' : 'scan', audit, polls };
}

// ---- isitagentready.com: POST /api/scan ----
const isLevel = (j) => !!j && typeof j === 'object' && Number.isInteger(j.level) && !!j.checks && typeof j.checks === 'object';
async function iiar(target) {
  const r = await call('POST', `${IIAR_BASE}/api/scan`, { url: target.href });
  if (r.status !== 200 || !isLevel(r.json)) return { looked: false, why: why(r, 'level') };
  return { looked: true, result: r.json };
}

// ---- the report ----
const ORA_ICON = { pass: '✅', warning: '⚠️', fail: '❌', na: '➖' };
const IIAR_ICON = { pass: '✅', fail: '❌', neutral: '➖' };
const TIER_RANK = { required: 0, recommended: 1, emerging: 2 };
const icon = (map, s) => (has(map, s) ? map[s] : '❔');

function provenance(o) {
  const a = o.audit;
  const t = when(a);
  const age = Number.isFinite(a.resultAgeSeconds) ? a.resultAgeSeconds : t ? (Date.now() - t) / 1000 : NaN;
  const stamp = t ? `${new Date(t).toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'at an unstated time';
  const ago = Number.isFinite(age) && age >= 0 ? `, ${dur(age)} ago` : '';
  const from = o.via === 'stored' ? `ora rate-limited this runner, so this is its last stored result (scanned ${stamp}${ago})`
    : o.via === 'cache' ? `served from ora's cache (scanned ${stamp}${ago}; a run within 6 h of a scan reads the same result)`
      : `scanned ${stamp}`;
  const s = a.analysisStatus;
  const state = s === 'complete' ? (o.polls ? `analysis complete after ${o.polls} poll(s)` : 'analysis complete')
    : s === 'stuck' ? 'ora reports its analysis stuck: the score is what it reached'
      : s === 'partial' ? (o.via === 'stored' ? 'stored mid-analysis: the score may have moved since'
        : `analysis still running after ${dur(POLL_MAX_MS / 1000)}: the score may still move`)
        : `analysis status ${safe(s, 30) || 'not given'}`;
  return `${from} · ${state}`;
}

function renderOra(o) {
  note('### ora.ai');
  if (o.skipped) { note('- off (`ora: false`)'); return; }
  if (!o.looked) { note(`- ⚠️ could not look: ${o.why}. Not a verdict about the site.`); return; }
  const a = o.audit;
  const max = Number.isFinite(a.scoreMax) ? a.scoreMax : 100;
  note(`- **${num(a.score)}/${num(max)}, grade ${GRADE.test(String(a.grade)) ? a.grade : '?'}** · ${provenance(o)}`);
  const layers = a.layers.filter((L) => L && typeof L === 'object').slice(0, 12);
  note(`- layers: ${layers.map((L) => `${safe(L.name || L.id, 40)} ${num(L.score)}/${num(L.maxScore)}`).join(' · ') || 'none listed'}`);
  const checks = [];
  for (const L of layers) {
    for (const c of (Array.isArray(L.checks) ? L.checks : []).slice(0, 200)) if (c && typeof c === 'object') checks.push({ ...c, layer: L });
  }
  const count = (s) => checks.filter((c) => c.status === s).length;
  note(`- checks: ${count('pass')} pass · ${count('warning')} warning · ${count('fail')} fail · ${count('na')} not applicable`);
  const fixes = (Array.isArray(a.topFixes) ? a.topFixes : []).filter((f) => f && typeof f === 'object').slice(0, 6);
  if (fixes.length) note(`- top fixes (ora's estimated score gain): ${fixes.map((f) => `\`${safe(f.id, 60)}\` +${num(f.estScoreGain)}`).join(' · ')}`);
  // A layer with no points to give (maxScore 0: Payments on a site ora does not see as a store) scores
  // nothing, so its warnings are not on the to-do list.
  const unscored = layers.filter((L) => L.maxScore === 0).map((L) => safe(L.name || L.id, 40));
  if (unscored.length) note(`- unscored here (layer max 0): ${unscored.join(', ')}`);
  const todo = checks.filter((c) => (c.status === 'fail' || c.status === 'warning') && c.layer.maxScore !== 0)
    .sort((x, y) => ((has(TIER_RANK, x.tier) ? TIER_RANK[x.tier] : 3) - (has(TIER_RANK, y.tier) ? TIER_RANK[y.tier] : 3))
      || ((Number.isFinite(y.estScoreGain) ? y.estScoreGain : 0) - (Number.isFinite(x.estScoreGain) ? x.estScoreGain : 0)));
  if (!todo.length) return;
  note('');
  note(`<details><summary>ora: ${todo.length} check(s) fail or warn, required tier first</summary>`);
  note('');
  note('| layer | check | tier | status | ora recommends |');
  note('|---|---|---|---|---|');
  for (const c of todo.slice(0, 80)) {
    note(`| ${safe(c.layer.name || c.layer.id, 30)} | \`${safe(c.id, 60)}\` | ${safe(c.tier, 20)} | ${icon(ORA_ICON, c.status)} ${safe(c.status, 12)} | ${safe(c.recommendation || c.details, 220)} |`);
  }
  if (todo.length > 80) note(`| … | ${todo.length - 80} more in the JSON | | | |`);
  note('');
  note('</details>');
}

function renderIiar(o) {
  note('### isitagentready.com');
  if (o.skipped) { note('- off (`isitagentready: false`)'); return; }
  if (!o.looked) { note(`- ⚠️ could not look: ${o.why}. Not a verdict about the site.`); return; }
  const j = o.result;
  note(`- **level ${j.level}${j.levelName ? ` (${safe(j.levelName, 60)})` : ''}**`);
  const nl = j.nextLevel;
  const reqs = nl && typeof nl === 'object' && Array.isArray(nl.requirements) ? nl.requirements.filter((q) => q && typeof q === 'object').slice(0, 8) : [];
  if (reqs.length) {
    note(`- next: level ${Number.isInteger(nl.target) ? nl.target : '?'}${nl.name ? ` (${safe(nl.name, 60)})` : ''} needs ${reqs.map((q) => `\`${safe(q.check, 40)}\`: ${safe(q.description, 160)}`).join('; ')}`);
  }
  for (const [cat, group] of Object.entries(j.checks).slice(0, 12)) {
    if (!group || typeof group !== 'object') continue;
    const by = new Map();
    for (const [id, c] of Object.entries(group).slice(0, 40)) {
      const k = icon(IIAR_ICON, c && c.status);
      by.set(k, [...(by.get(k) || []), safe(id, 40)]);
    }
    note(`- ${safe(cat, 40)}: ${[...by].map(([k, ids]) => `${k} ${ids.join(', ')}`).join(' · ') || 'no checks listed'}`);
  }
}

function headline(o, i) {
  const a = o.looked ? `ora ${num(o.audit.score)}/${num(Number.isFinite(o.audit.scoreMax) ? o.audit.scoreMax : 100)}${GRADE.test(String(o.audit.grade)) ? ` (${o.audit.grade})` : ''}`
    : o.skipped ? 'ora off' : 'ora could not look';
  const b = i.looked ? `isitagentready level ${i.result.level}${i.result.levelName ? ` (${safe(i.result.levelName, 60)})` : ''}`
    : i.skipped ? 'isitagentready off' : 'isitagentready could not look';
  return `${a} · ${b}`;
}

// Every run leaves through here: the JSON, the step outputs, the summary, one notice. Always exit 0.
function finish(target, o, i) {
  const out = { 'ora-score': '', 'ora-grade': '', 'isitagentready-level': '', json: '' };
  if (target) {
    const file = path.join(env.RUNNER_TEMP || os.tmpdir(), 'agent-benchmark.json');
    try {
      fs.writeFileSync(file, `${JSON.stringify({ target: target.href, generatedAt: new Date().toISOString(), ora: o, isitagentready: i }, null, 2)}\n`);
      if (!/[\r\n]/.test(file)) out.json = file;
      note('');
      note(`Both answers in full, as JSON: \`${safe(file, 200)}\` (upload it as an artifact to keep the history).`);
    } catch (e) { note(`- ⚠️ the JSON could not be written: ${safe(e && e.message, 160)}`); }
    if (o.looked) {
      out['ora-score'] = num(o.audit.score) === '?' ? '' : num(o.audit.score);
      out['ora-grade'] = GRADE.test(String(o.audit.grade)) ? o.audit.grade : '';
    }
    if (i.looked) out['isitagentready-level'] = String(i.result.level);
  }
  if (env.GITHUB_OUTPUT) {
    try { fs.appendFileSync(env.GITHUB_OUTPUT, `${Object.entries(out).map(([k, v]) => `${k}=${v}`).join('\n')}\n`); } catch (e) { note(`- ⚠️ the step outputs could not be written: ${safe(e && e.message, 160)}`); }
  }
  if (summaryFile) { fs.appendFileSync(summaryFile, `${lines.join('\n')}\n`); summaryWritten = true; }
  if (env.GITHUB_ACTIONS === 'true' && target && (!o.skipped || !i.skipped)) say(`::notice title=agent-benchmark::${escapeData(headline(o, i))}`);
  process.exit(0);
}

(async () => {
  note('## 🤖 agent-benchmark — what public agent-readiness scanners say (report-only)');
  note('');
  const target = targetOf(env.TARGET_URL);
  if (!target) {
    note(`- no usable \`url\`${(env.TARGET_URL || '').trim() ? ` (${safe(env.TARGET_URL, 120)} is not an http(s) URL)` : ''}: nothing to scan (skipped)`);
    return finish(null);
  }
  const wantOra = on(env.ORA), wantIiar = on(env.ISITAGENTREADY);
  note(`Target: ${safe(target.href, 200)}`);
  note('');
  if (!wantOra && !wantIiar) {
    note('- both scanners are off (`ora: false`, `isitagentready: false`): nothing to ask (skipped)');
    return finish(null);
  }
  const [o, i] = await Promise.all([wantOra ? ora(target) : { skipped: true }, wantIiar ? iiar(target) : { skipped: true }]);
  renderOra(o);
  note('');
  renderIiar(i);
  note('');
  note('seo-aeo grades the same layer itself (its `### Agent readiness` block, air-gapped): that, not these scores, is what a caller promotes and blocks on. These are for the trend and the order of work.');
  return finish(target, o, i);
})().catch(crashed);
