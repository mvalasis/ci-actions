// Offline self-test for the form-protection gate. Two layers:
//   1. engine fixtures — pure analyzers (checks.mjs) against fixture HTML, no I/O
//   2. e2e — a LOCAL node:http server (127.0.0.1 only, no external network)
//      serving fixture pages + reject/accept endpoints; the real CLI
//      (check.mjs) runs against it as a subprocess and its exit code + summary
//      are asserted. This pins the whole probe path, not just the analyzers.
// Run locally or in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  SEV, classifySitekey, parseEndpointMap, analyzeForms, buildProbeBody, judgeProbe,
} from './checks.mjs';

let failed = 0;
function check(name, cond, detail = '') { if (cond) { console.log(`  ✅ ${name}`); } else { console.log(`  ❌ ${name} ${detail}`); failed++; } }
const ids = (fs_) => fs_.map((x) => x.id);
const sevOf = (fs_, id) => fs_.filter((x) => x.id === id).map((x) => x.sev);

const REAL_KEY = '0x4AAAAAAABkMYinukE8nzYd'; // shape of a real Turnstile sitekey
const A = (html, opts = {}) => analyzeForms({ requestUrl: opts.url || 'https://example.com/contact/', html, endpointMap: opts.map || [], extraTestKeys: opts.extra || [] });

console.log('\n# sitekey classification');
check('real Turnstile key → real', classifySitekey(REAL_KEY) === 'real');
check('Turnstile force-pass 1x…AA → test', classifySitekey('1x00000000000000000000AA') === 'test');
check('Turnstile force-block 2x…AB → test', classifySitekey('2x00000000000000000000AB') === 'test');
check('Turnstile force-challenge 3x…FF → test', classifySitekey('3x00000000000000000000FF') === 'test');
check('all-zeros placeholder 0x000…0 → test (the epn fallback)', classifySitekey('0x0000000000000000000000') === 'test');
check('reCAPTCHA universal test key → test', classifySitekey('6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI') === 'test');
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
  const html = `<form data-epn-form="contact" method="post" action="/api/contact"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`;
  const { findings, surfaces } = A(html);
  check('real key → no sitekey-real finding', !ids(findings).includes('sitekey-real'), JSON.stringify(findings));
  check('endpoint resolved from action attr against page URL', surfaces.length === 1 && surfaces[0].endpoint === 'https://example.com/api/contact');
  check('turnstile token field inferred', surfaces[0].tokenField === 'cf-turnstile-response' && surfaces[0].mode === 'form');
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
  const { findings } = A(`<form action="/x"><div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"></div></form>`);
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

// ---------------------------------------------------------------------------
console.log('\n# e2e — local http server + the real CLI');

const PAGES = {
  '/page-good.html': `<html><body><form data-epn-form="contact" method="post" action="/api/reject"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form></body></html>`,
  '/page-testkey.html': `<html><body><form action="/api/reject"><div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div></form></body></html>`,
  '/page-skipverify.html': `<html><body><form action="/api/accept"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form></body></html>`,
  '/page-jsdriven.html': `<html><body><form id="checkout-form"><div id="turnstile-checkout"></div></form><script>const turnstileSiteKey = "${REAL_KEY}";</script></body></html>`,
};
const server = createServer((req, res) => {
  if (req.method === 'GET' && PAGES[req.url]) { res.writeHead(200, { 'content-type': 'text/html' }); res.end(PAGES[req.url]); return; }
  if (req.method === 'POST' && req.url === '/api/reject') { res.writeHead(403, { 'content-type': 'application/json' }); res.end('{"ok":false,"error":"turnstile_failed"}'); return; }
  if (req.method === 'POST' && req.url === '/api/accept') { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); return; }
  if (req.method === 'POST' && req.url === '/api/wrong-layer') { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{"error":"missing_fields"}'); return; }
  res.writeHead(404); res.end('not found');
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const PORT = server.address().port;
const BASE = `http://127.0.0.1:${PORT}`;

// MUST be async (spawn, not spawnSync): the fixture http server lives in THIS
// process — a sync child-wait blocks the event loop and every child request
// times out against a server that can't answer.
function runCli(extraEnv) {
  const summary = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'form-prot-')), 'summary.md');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [new URL('./check.mjs', import.meta.url).pathname], {
      env: { ...process.env, GITHUB_STEP_SUMMARY: summary, MAX_URLS: '15', ...extraEnv },
      stdio: ['ignore', 'inherit', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (code) => {
      clearTimeout(killer);
      resolve({ code, summary: fs.existsSync(summary) ? fs.readFileSync(summary, 'utf8') : '', stderr });
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
// submit-probe off → sitekey checks only, skip-verify endpoint NOT probed
{
  const r = await runCli({ URLS: `${BASE}/page-skipverify.html`, FAIL_ON_CRITICAL: 'true', SUBMIT_PROBE: 'false' });
  check('e2e submit-probe off: exit 0 (server never probed)', r.code === 0, r.stderr);
  check('e2e submit-probe off: summary flags probes off', r.summary.includes('server-side verification NOT asserted'), r.summary);
}

server.close();
console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
