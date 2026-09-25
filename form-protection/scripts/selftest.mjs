// Offline self-test for the form-protection gate. Two layers:
//   1. engine fixtures — pure analyzers (checks.mjs) against fixture HTML, no I/O
//   2. e2e — a LOCAL node:http server (127.0.0.1 only, no external network)
//      serving fixture pages + reject/accept endpoints; the real CLI
//      (check.mjs) runs against it as a subprocess and its exit code, summary
//      and job log (stdout: the report + one annotation per CRITICAL) are
//      asserted. This pins the whole probe path, not just the analyzers.
// Run locally or in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SEV, classifySitekey, parseEndpointMap, analyzeForms, buildProbeBody, judgeProbe,
  safe, escapeData, escapeProperty, annotation, annotations,
} from './checks.mjs';

let failed = 0;
function check(name, cond, detail = '') { if (cond) { console.log(`  ✅ ${name}`); } else { console.log(`  ❌ ${name} ${detail}`); failed++; } }
const ids = (fs_) => fs_.map((x) => x.id);
const sevOf = (fs_, id) => fs_.filter((x) => x.id === id).map((x) => x.sev);

const REAL_KEY = '0x4AAAAAAABkMYinukE8nzYd'; // shape of a real Turnstile sitekey
// Google's documented reCAPTCHA universal test site key — public, and deliberately NOT
// named *KEY: spelled inline as data-sitekey="<value>", gitleaks' generic-api-key read it
// as a credential (a T0 critical in the security-baseline self-scan).
const RECAPTCHA_UNIVERSAL_TEST = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
const A = (html, opts = {}) => analyzeForms({ requestUrl: opts.url || 'https://example.com/contact/', html, endpointMap: opts.map || [], extraTestKeys: opts.extra || [] });

console.log('\n# sitekey classification');
check('real Turnstile key → real', classifySitekey(REAL_KEY) === 'real');
check('Turnstile force-pass 1x…AA → test', classifySitekey('1x00000000000000000000AA') === 'test');
check('Turnstile force-block 2x…AB → test', classifySitekey('2x00000000000000000000AB') === 'test');
check('Turnstile force-challenge 3x…FF → test', classifySitekey('3x00000000000000000000FF') === 'test');
check('all-zeros placeholder 0x000…0 → test (the epn fallback)', classifySitekey('0x0000000000000000000000') === 'test');
check('reCAPTCHA universal test key → test', classifySitekey(RECAPTCHA_UNIVERSAL_TEST) === 'test');
check('hCaptcha test key → test', classifySitekey('10000000-ffff-ffff-ffff-000000000001') === 'test');
check('empty/missing → missing', classifySitekey('') === 'missing' && classifySitekey(null) === 'missing' && classifySitekey('  ') === 'missing');
check('extra exact value → test', classifySitekey(REAL_KEY, [REAL_KEY]) === 'test');
check('extra prefix (trailing *) → test', classifySitekey('0x4STAGINGKEY123', ['0x4STAGING*']) === 'test');
check('real key with unrelated extras → real', classifySitekey(REAL_KEY, ['0xOTHER']) === 'real');

console.log('\n# form-endpoints map parsing');
{
  const m = parseEndpointMap('#checkout-form => /api/checkout/create-order mode=json token=turnstileToken expect=turnstile_failed\n# comment\n[data-epn-form="contact"] => /api/contact expect=turnstile_failed\ngarbage-line-no-arrow');
  check('json entry parsed (mode/token/expect)', m[0].selector === '#checkout-form' && m[0].mode === 'json' && m[0].token === 'turnstileToken' && m[0].expect === 'turnstile_failed');
  check('form entry defaults to mode=form', m[1].mode === 'form' && m[1].selector === '[data-epn-form="contact"]' && m[1].endpoint === '/api/contact');
  check('comment skipped, garbage → error entry', m.length === 3 && m[2].error === 'garbage-line-no-arrow');
}

console.log('\n# page analyzer — the epn shape (static data-sitekey + action attr)');
{
  const html = `<form data-epn-form="contact" method="post" action="/api/contact"><input type="hidden" name="formType" value="contact"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`;
  const { findings, surfaces } = A(html);
  check('real key → no sitekey-real finding', !ids(findings).includes('sitekey-real'), JSON.stringify(findings));
  check('endpoint resolved from action attr against page URL', surfaces.length === 1 && surfaces[0].endpoint === 'https://example.com/api/contact');
  check('turnstile token field inferred', surfaces[0].tokenField === 'cf-turnstile-response' && surfaces[0].mode === 'form');
  check('hidden control field picked up (routing before the bot gate)', surfaces[0].fields.formType === 'contact');
}
{
  // map fields= override + hidden pickup merge; token-named hidden inputs excluded
  const html = `<form id="f" action="/api/x"><input type="hidden" name="formType" value="contact"><input type="hidden" name="cf-turnstile-response" value="stale"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`;
  const map = parseEndpointMap('#f => /api/x fields=formType:employer,ref:ci');
  const { surfaces } = A(html, { map });
  check('fields= map opt overrides hidden value + adds extras; token-named hidden excluded', surfaces[0].fields.formType === 'employer' && surfaces[0].fields.ref === 'ci' && !('cf-turnstile-response' in surfaces[0].fields));
}
{
  const { findings } = A(`<form action="/api/contact"><div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div></form>`);
  check('test key → CRITICAL sitekey-real', sevOf(findings, 'sitekey-real').includes(SEV.CRIT));
}
{
  const { findings } = A(`<form action="/api/contact"><div class="cf-turnstile" data-sitekey="0x0000000000000000000000"></div></form>`);
  check('all-zeros placeholder shipped (unset env at build) → CRITICAL', sevOf(findings, 'sitekey-real').includes(SEV.CRIT));
}
{
  const { findings } = A(`<form action="/api/contact"><div class="cf-turnstile" data-sitekey=""></div></form>`);
  check('empty data-sitekey → CRITICAL (missing)', sevOf(findings, 'sitekey-real').includes(SEV.CRIT));
}
{
  const { findings, surfaces } = A(`<form><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`);
  check('widget form with no action + no map → WARN endpoint-unknown, no surface', sevOf(findings, 'endpoint-unknown').includes(SEV.WARN) && surfaces.length === 0);
}
{
  const { findings, surfaces } = A('<main><h1>No forms here</h1></main>');
  check('no widget + no map match → WARN no-gated-form', sevOf(findings, 'no-gated-form').includes(SEV.WARN) && surfaces.length === 0);
}
{
  const { findings } = A(`<form action="/x"><div class="g-recaptcha" data-sitekey="${RECAPTCHA_UNIVERSAL_TEST}"></div></form>`);
  check('reCAPTCHA widget with Google test key → CRITICAL', sevOf(findings, 'sitekey-real').includes(SEV.CRIT));
}

console.log('\n# page analyzer — the lampakia shape (client-rendered, JSON endpoint via map)');
const LAMPAKIA_MAP = parseEndpointMap('#checkout-form => /api/checkout/create-order mode=json token=turnstileToken expect=turnstile_failed');
{
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form><script>const turnstileSiteKey = "${REAL_KEY}"; turnstile.render(el, { sitekey: turnstileSiteKey });</script>`;
  const { findings, surfaces } = A(html, { url: 'https://www.lampakia.gr/checkout/', map: LAMPAKIA_MAP });
  check('mapped form, real script sitekey → no CRIT', !findings.some((x) => x.sev === SEV.CRIT), JSON.stringify(findings));
  check('surface from map: json mode + token + expect', surfaces.length === 1 && surfaces[0].mode === 'json' && surfaces[0].tokenField === 'turnstileToken' && surfaces[0].expect === 'turnstile_failed');
  check('map endpoint resolved absolute', surfaces.length === 1 && surfaces[0].endpoint === 'https://www.lampakia.gr/api/checkout/create-order');
}
{
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form><script>const turnstileSiteKey = ""; turnstile.render(el, { sitekey: turnstileSiteKey });</script>`;
  const { findings } = A(html, { url: 'https://www.lampakia.gr/checkout/', map: LAMPAKIA_MAP });
  check('empty script sitekey (unset env at build) → CRITICAL', sevOf(findings, 'sitekey-real').includes(SEV.CRIT));
}
{
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form>`;
  const { findings, surfaces } = A(html, { url: 'https://www.lampakia.gr/checkout/', map: LAMPAKIA_MAP });
  check('mapped form, no static widget/sitekey → INFO widget-not-static, still probed', sevOf(findings, 'widget-not-static').includes(SEV.INFO) && surfaces.length === 1);
}
{
  // map selector matching an element OUTSIDE any form (fully JS-driven surface)
  const html = `<div id="checkout-app"><div id="turnstile-checkout"></div></div>`;
  const map = parseEndpointMap('#turnstile-checkout => /api/checkout/create-order mode=json expect=turnstile_failed');
  const { surfaces } = A(html, { url: 'https://www.lampakia.gr/checkout/', map });
  check('formless mapped surface still probed (json token default turnstileToken)', surfaces.length === 1 && surfaces[0].tokenField === 'turnstileToken');
}
{
  // an empty sitekey string in an unrelated blob must NOT mask/false-fire next to a real one
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form><script>window.cfg={sitekey:""};</script><script>const turnstileSiteKey = "${REAL_KEY}";</script>`;
  const { findings } = A(html, { url: 'https://www.lampakia.gr/checkout/', map: LAMPAKIA_MAP });
  check('empty script match ignored when a non-empty sitekey exists', !findings.some((x) => x.sev === SEV.CRIT), JSON.stringify(findings));
}

console.log('\n# probe bodies');
{
  const s = { mode: 'json', tokenField: 'turnstileToken', widgetType: 'client-rendered' };
  check('json tokenless = {}', buildProbeBody(s, 'tokenless').body === '{}');
  check('json junk-token carries the field', JSON.parse(buildProbeBody(s, 'junk-token').body).turnstileToken.includes('ci-form-protection-probe'));
  const t = { mode: 'form', tokenField: '', widgetType: 'turnstile' };
  check('form junk-token uses cf-turnstile-response', buildProbeBody(t, 'junk-token').body.startsWith('cf-turnstile-response='));
  check('form tokenless body is empty', buildProbeBody(t, 'tokenless').body === '');
}

console.log('\n# probe verdicts');
const J = (status, body, expect = '') => judgeProbe({ kind: 'tokenless', status, body, expect, endpoint: 'https://e/api' });
check('403 {ok:false,turnstile_failed} + expect → OK', J(403, '{"ok":false,"error":"turnstile_failed"}', 'turnstile_failed').sev === SEV.OK);
check('403 no expect configured → OK', J(403, 'Forbidden').sev === SEV.OK);
check('400 field-validation reject + expect mismatch → CRITICAL (gate never fired)', J(400, '{"error":"missing_fields"}', 'turnstile_failed').sev === SEV.CRIT);
check('200 {ok:true} → CRITICAL skip-verify', J(200, '{"ok":true}').sev === SEV.CRIT);
check('200 plain HTML thanks-page → CRITICAL skip-verify', J(200, '<html>Thanks!</html>').sev === SEV.CRIT);
check('200 {ok:false} soft reject → OK', J(200, '{"ok":false,"error":"turnstile_failed"}').sev === SEV.OK);
check('200 {success:false} soft reject → OK', J(200, '{"success":false}').sev === SEV.OK);
check('200 {ok:false} but expect mismatch → CRITICAL', J(200, '{"ok":false,"error":"missing_fields"}', 'turnstile_failed').sev === SEV.CRIT);
check('302 redirect → WARN inconclusive (PRG ambiguity)', J(302, '').sev === SEV.WARN && J(302, '').id === 'probe-inconclusive');
check('500 → WARN inconclusive', J(500, 'oops').sev === SEV.WARN);

console.log('\n# report + annotation encoding (pure)');
{
  check('safe() strips CR/LF and markdown-structural chars, caps length', safe('a\r\n`|<b>[c]', 5) === 'a bc' && safe('x'.repeat(500)).length === 300, JSON.stringify(safe('a\r\n`|<b>[c]', 5)));
  check('escapeData encodes % CR LF', escapeData('a%b\r\nc') === 'a%25b%0D%0Ac');
  check('escapeProperty also encodes : and ,', escapeProperty('a:b,c%') === 'a%3Ab%2Cc%25');
  const x = { id: 'server-rejects', sev: SEV.CRIT, msg: 'endpoint ACCEPTED the POST', rule: 'tokenless', where: 'https://e.test/api/contact' };
  check('annotation = title + `<check> <probe> at <url>`, no file=/line= (a URL is not a repo file)', annotation(x) === '::error title=form-protection server-rejects::server-rejects tokenless at https://e.test/api/contact', annotation(x));
  check('a page finding has no probe kind: `<check> at <page>`', annotation({ id: 'sitekey-real', sev: SEV.CRIT, where: 'https://e.test/contact/' }) === '::error title=form-protection sitekey-real::sitekey-real at https://e.test/contact/');
  check('annotation never carries msg (page text stays in the report)', !annotation(x).includes('ACCEPTED'));
  check("annotation level is the caller's", annotation(x, 'warning').startsWith('::warning title=form-protection server-rejects::'));
  // A hostile location stays ONE command: a line break would start a second one (stop-commands),
  // a raw % would be unescaped by the runner, and [ ] would let the legacy `##[cmd]` form in.
  const evil = annotation({ ...x, where: 'https://e.test/p%0A\n::stop-commands::tok\r##[error]x' });
  check('a hostile location stays ONE line', !/[\r\n]/.test(evil), JSON.stringify(evil));
  check('a hostile location cannot add a property (title is the only one)', /^::error title=form-protection server-rejects::/.test(evil) && evil.split('::').length === 5, JSON.stringify(evil));
  check('…its % is escaped and its brackets are gone', evil.includes('p%250A') && !evil.includes('##['), JSON.stringify(evil));
  const many = Array.from({ length: 12 }, (_, i) => ({ ...x, where: `https://e.test/${i}` }));
  const warnOnly = { id: 'probe-inconclusive', sev: SEV.WARN, msg: 'm', where: 'w' };
  const out = annotations([...many, warnOnly]);
  check("annotations: 10 CRITICALs (GitHub's per-step cap) + one overflow line", out.length === 11 && out.slice(0, 10).every((l) => l.startsWith('::error ')) && /^form-protection: 2 more critical/.test(out[10]), `got ${out.length}`);
  check('annotations: a WARN finding is never annotated', !out.some((l) => l.includes('probe-inconclusive')) && annotations([warnOnly]).length === 0);
}

// ---------------------------------------------------------------------------
console.log('\n# e2e — local http server + the real CLI');

const PAGES = {
  '/page-good.html': `<html><body><form data-epn-form="contact" method="post" action="/api/reject"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form></body></html>`,
  '/page-testkey.html': `<html><body><form action="/api/reject"><div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div></form></body></html>`,
  '/page-skipverify.html': `<html><body><form action="/api/accept"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form></body></html>`,
  '/page-jsdriven.html': `<html><body><form id="checkout-form"><div id="turnstile-checkout"></div></form><script>const turnstileSiteKey = "${REAL_KEY}";</script></body></html>`,
  // the epn shape: a hidden routing field the handler checks BEFORE the bot gate
  '/page-routed.html': `<html><body><form data-epn-form="contact" method="post" action="/api/routed-reject"><input type="hidden" name="formType" value="contact"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form></body></html>`,
  // a test key carrying a planted workflow command: sitekey-real quotes the raw key, newline included
  '/page-hostile.html': '<html><body><form action="/api/reject"><div class="cf-turnstile" data-sitekey="1x00000000000000000000AA&#10;::error title=forged::pwned-key"></div></form></body></html>',
};
const server = createServer((req, res) => {
  if (req.method === 'GET' && PAGES[req.url]) { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGES[req.url]); return; }
  if (req.method === 'POST' && req.url === '/api/reject') { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"ok":false,"error":"turnstile_failed"}'); return; }
  if (req.method === 'POST' && req.url === '/api/accept') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); return; }
  if (req.method === 'POST' && req.url === '/api/wrong-layer') { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{"error":"missing_fields"}'); return; }
  if (req.method === 'POST' && req.url === '/api/routed-reject') {
    // router first (400 unknown_form_type), bot gate second (403 turnstile_failed)
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      const hasFormType = new URLSearchParams(body).get('formType');
      if (!hasFormType) { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{"ok":false,"error":"unknown_form_type"}'); }
      else { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"ok":false,"error":"turnstile_failed"}'); }
    });
    return;
  }
  res.writeHead(404); res.end('not found');
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

// MUST be async (spawn, not spawnSync): the fixture http server lives in THIS
// process — a sync child-wait blocks the event loop and every child request
// times out against a server that can't answer. stdout is PIPED, not inherited:
// since v1.18.0 it is the job log (the whole report, plus annotations when
// GITHUB_ACTIONS=true), which the cases below assert. The env is built from
// scratch, so a CI runner's own GITHUB_ACTIONS / GITHUB_STEP_SUMMARY never leak
// into a case; a case unsets the summary with `GITHUB_STEP_SUMMARY: undefined`.
function runCli(extraEnv) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'form-prot-'));
  const summary = path.join(dir, 'summary.md');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('./check.mjs', import.meta.url))], {
      env: { PATH: process.env.PATH, HOME: dir, TMPDIR: dir, GITHUB_STEP_SUMMARY: summary, MAX_URLS: '15', ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (code) => {
      clearTimeout(killer);
      const text = fs.existsSync(summary) && fs.statSync(summary).isFile() ? fs.readFileSync(summary, 'utf8') : '';
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({ code, summary: text, stdout, stderr });
    });
  });
}

// clean run: good page + properly-rejecting endpoint → PASS, exit 0 even when enforcing
{
  const r = await runCli({ URLS: `${BASE}/page-good.html`, FAIL_ON_CRITICAL: 'true' });
  check('e2e clean: exit 0 under fail-on-critical', r.code === 0, r.stderr);
  check('e2e clean: PASS verdict + probe OKs in summary', r.summary.includes('PASS — no critical issues') && r.summary.includes('hard reject'), r.summary);
}
// the incident class: test sitekey AND skip-verifying server, enforcing → exit 1
{
  const r = await runCli({ URLS: `${BASE}/page-testkey.html ${BASE}/page-skipverify.html`, FAIL_ON_CRITICAL: 'true' });
  check('e2e incident class: exit 1 under fail-on-critical', r.code === 1, r.stderr);
  check('e2e incident class: sitekey-real CRIT reported', r.summary.includes('sitekey-real') && r.summary.includes('KNOWN TEST/PLACEHOLDER'), r.summary);
  check('e2e incident class: server-rejects CRIT reported (2xx accept)', r.summary.includes('server-rejects') && r.summary.includes('ACCEPTED'), r.summary);
}
// same page in report-mode → exit 0 but would-block note
{
  const r = await runCli({ URLS: `${BASE}/page-skipverify.html`, FAIL_ON_CRITICAL: 'false' });
  check('e2e report-mode: exit 0', r.code === 0, r.stderr);
  check('e2e report-mode: would-BLOCK note present', r.summary.includes('would BLOCK'), r.summary);
}
// JS-driven form via form-endpoints map, expect-mismatch (reject from the wrong layer) → CRIT
{
  const r = await runCli({
    URLS: `${BASE}/page-jsdriven.html`, FAIL_ON_CRITICAL: 'true',
    FORM_ENDPOINTS: '#checkout-form => /api/wrong-layer mode=json token=turnstileToken expect=turnstile_failed',
  });
  check('e2e expect-mismatch: exit 1 (field-validation reject masks skip-verify)', r.code === 1, r.stderr);
  check('e2e expect-mismatch: signature-missing CRIT reported', r.summary.includes('WITHOUT the bot-gate signature'), r.summary);
}
// same JS-driven form pointed at the properly-rejecting endpoint → green
{
  const r = await runCli({
    URLS: `${BASE}/page-jsdriven.html`, FAIL_ON_CRITICAL: 'true',
    FORM_ENDPOINTS: '#checkout-form => /api/reject mode=json token=turnstileToken expect=turnstile_failed',
  });
  check('e2e mapped+expect green: exit 0', r.code === 0, `${r.stderr} ${r.summary}`);
}
// routed endpoint (formType checked before the bot gate): hidden-field pickup
// must carry the probe PAST the router so the reject bears the gate signature
{
  const r = await runCli({
    URLS: `${BASE}/page-routed.html`, FAIL_ON_CRITICAL: 'true',
    FORM_ENDPOINTS: '[data-epn-form="contact"] => /api/routed-reject expect=turnstile_failed',
  });
  check('e2e routed: hidden formType reaches the bot gate → exit 0', r.code === 0, `${r.stderr} ${r.summary}`);
  check('e2e routed: gate signature present in reject', r.summary.includes('hard reject') && r.summary.includes('signature "turnstile_failed" present'), r.summary);
}
// submit-probe off → sitekey checks only, skip-verify endpoint NOT probed
{
  const r = await runCli({ URLS: `${BASE}/page-skipverify.html`, FAIL_ON_CRITICAL: 'true', SUBMIT_PROBE: 'false' });
  check('e2e submit-probe off: exit 0 (server never probed)', r.code === 0, r.stderr);
  check('e2e submit-probe off: summary flags probes off', r.summary.includes('server-side verification NOT asserted'), r.summary);
}

// ---------------------------------------------------------------------------
console.log('\n# the job log carries the report; CRITICALs annotate');
{
  // A line the runner would read as a command: `::` after leading whitespace, or `##[` anywhere.
  const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l) || l.includes('##['));
  const why = (r) => `exit ${r.code}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
  const HEADER = '## 🛡️ form-protection';
  const once = (r) => r.stdout.split(HEADER).length === 2 && !r.stdout.includes('crashed');
  const URLS = `${BASE}/page-testkey.html ${BASE}/page-skipverify.html ${BASE}/page-hostile.html`;
  const expected = (level) => [
    `::${level} title=form-protection sitekey-real::sitekey-real at ${BASE}/page-testkey.html`,
    `::${level} title=form-protection sitekey-real::sitekey-real at ${BASE}/page-hostile.html`,
    `::${level} title=form-protection server-rejects::server-rejects tokenless at ${BASE}/api/accept`,
    `::${level} title=form-protection server-rejects::server-rejects junk-token at ${BASE}/api/accept`,
  ];

  // (A) On Actions, enforcing: summary + job log + one ::error per CRITICAL (page AND probe).
  const a = await runCli({ URLS, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true' });
  check('Actions run: two sitekey + two probe CRITICALs BLOCK (exit 1)', a.code === 1, why(a));
  check('the step summary is the report, verdict included', a.summary.startsWith(HEADER) && a.summary.includes('\nBLOCKED — 4 critical check(s) failed.'), JSON.stringify(a.summary.slice(-120)));
  check('the job log carries the WHOLE report, byte for byte', a.summary.length > 0 && a.stdout.includes(a.summary));
  check('the report reaches the log once, not twice', once(a), why(a));
  check('the hostile sitekey reached the report, flattened onto its line', a.stdout.includes('1x00000000000000000000AA ::error title=forged::pwned-key'), why(a));
  check('one ::error per CRITICAL — the page, or the probe kind + endpoint — and nothing else command-shaped',
    JSON.stringify(commands(a.stdout)) === JSON.stringify(expected('error')), JSON.stringify(commands(a.stdout)));
  check('annotations stay out of the step summary', commands(a.summary).length === 0);

  // (B) Off Actions: stdout is the only output — the report prints once, with no commands. spawn
  // hands the child a SOCKET as stdout: the case that crashes an `appendFileSync('/dev/stdout')`
  // fallback on Linux (ENXIO) with nothing printed and an exit code that still looks like a verdict.
  for (const [label, sink] of [['local run', undefined], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', '/dev/stdout']]) {
    const b = await runCli({ URLS, FAIL_ON_CRITICAL: 'true', GITHUB_STEP_SUMMARY: sink });
    check(`${label}: the report prints exactly once, verdict included, no crash`, b.code === 1 && once(b) && b.stdout.includes('\nBLOCKED — 4 critical check(s) failed.'), why(b));
    check(`${label}: no workflow commands`, b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
  }

  // (C) report-only: the same criticals annotate as ::warning, and nothing blocks.
  const c = await runCli({ URLS, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
  check('report-only: exit 0', c.code === 0, why(c));
  check('report-only: the criticals annotate as ::warning, never ::error', JSON.stringify(commands(c.stdout)) === JSON.stringify(expected('warning')), JSON.stringify(commands(c.stdout)));
  check('report-only: the log still carries the whole report', c.summary.length > 0 && c.stdout.includes(c.summary) && c.summary.includes('report-only — 4 critical check(s) would BLOCK'));

  // (D) The summary sink itself fails: the report is already in the log (it is echoed first), the
  // fault is named there, and the exit is the caller's setting — our fault never blocks report-only.
  const sinkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'form-prot-sink-'));
  const d = await runCli({ URLS: `${BASE}/page-testkey.html`, GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
  fs.rmSync(sinkDir, { recursive: true, force: true });
  check('unwritable summary: the report still reaches the job log', d.stdout.includes(HEADER) && d.stdout.includes('report-only — 1 critical check(s) would BLOCK'), why(d));
  check('unwritable summary: the fault is named in the log', /form-protection crashed: .*EISDIR/.test(d.stdout), why(d));
  check('unwritable summary: the crash note is ONE line (no stack frame starts a log line)', !/^\s+at /m.test(d.stdout), why(d));
  check('unwritable summary: the crash re-flush echoes only the new line, not the report again', d.stdout.split(HEADER).length === 2);
  check('unwritable summary under report-only: exit 0, not an unhandled throw', d.code === 0, why(d));

  // (E) The early exits run before check.mjs's first await, i.e. while the module is still
  // evaluating, so anything they touch must already be initialized (no TDZ crash).
  const e = await runCli({});
  check('no input: skipped, exit 0, printed once, no crash', e.code === 0 && once(e) && e.stdout.includes('nothing to check (skipped)'), why(e));
  const f = await runCli({ URLS: ' ', GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true' });
  check('input resolving to no URL: BLOCKED (exit 1), printed once, no crash', f.code === 1 && once(f) && f.stdout.includes('BLOCKED — gate checked nothing.'), why(f));
  check('…annotated as the one CRITICAL it counts', JSON.stringify(commands(f.stdout)) === JSON.stringify(['::error title=form-protection no-urls-resolved::no-urls-resolved']), JSON.stringify(commands(f.stdout)));
}

server.close();

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
