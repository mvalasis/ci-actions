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
  safe, escapeData, escapeProperty, annotation, annotations, fitReport,
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
  const { surfaces, gatedForms } = A(html, { url: 'https://www.lampakia.gr/checkout/', map });
  check('formless mapped surface still probed (json token default turnstileToken)', surfaces.length === 1 && surfaces[0].tokenField === 'turnstileToken');
  check('…and counts as one gated form', gatedForms === 1, `gatedForms=${gatedForms}`);
}
{
  // an empty sitekey string in an unrelated blob must NOT mask/false-fire next to a real one
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form><script>window.cfg={sitekey:""};</script><script>const turnstileSiteKey = "${REAL_KEY}";</script>`;
  const { findings } = A(html, { url: 'https://www.lampakia.gr/checkout/', map: LAMPAKIA_MAP });
  check('empty script match ignored when a non-empty sitekey exists', !findings.some((x) => x.sev === SEV.CRIT), JSON.stringify(findings));
}

console.log('\n# one form, several map entries (the lampakia checkout: the order + the abandoned-cart ping)');
{
  // Two gated JSON endpoints behind one client-rendered form, the second mapped through a widget
  // container inside it; a hidden input stands in for the form's context. A third entry maps
  // another form and must stay off this one.
  const html = `<form id="checkout-form"><input type="hidden" name="brand" value="lampakia"><div id="turnstile-checkout"></div><div id="turnstile-cart-track"></div></form><form id="other-form"></form><script>const turnstileSiteKey = "${REAL_KEY}";</script>`;
  const map = parseEndpointMap([
    '#checkout-form => /api/checkout/create-order mode=json token=turnstileToken expect=turnstile_failed',
    '#turnstile-cart-track => /api/cart/track mode=json token=cartToken expect=cart_gate',
    '#other-form => /api/other mode=json expect=turnstile_failed',
  ].join('\n'));
  const { findings, surfaces, gatedForms } = A(html, { url: 'https://www.lampakia.gr/checkout/', map });
  const mine = surfaces.filter((s) => s.form === 'form#checkout-form');
  check('every entry matching the form is a probe target of that form, in map order', mine.map((s) => s.endpoint).join(' ') === 'https://www.lampakia.gr/api/checkout/create-order https://www.lampakia.gr/api/cart/track', JSON.stringify(surfaces));
  check("each target keeps its own entry's token + expect", mine[0]?.tokenField === 'turnstileToken' && mine[0]?.expect === 'turnstile_failed' && mine[1]?.tokenField === 'cartToken' && mine[1]?.expect === 'cart_gate', JSON.stringify(mine));
  check("the later entry carries the form's hidden inputs", mine[1]?.fields?.brand === 'lampakia' && mine[1]?.mapped === true, JSON.stringify(mine[1]));
  check('an entry for another form stays off this one, and nothing is probed twice', surfaces.length === 3 && surfaces[2].form === 'form#other-form', JSON.stringify(surfaces));
  check('gatedForms counts forms, not endpoints (2 forms, 3 targets)', gatedForms === 2, `gatedForms=${gatedForms}`);
  check('a real key on a doubly-mapped form → no finding', findings.length === 0, JSON.stringify(findings));
}
{
  const html = `<form id="checkout-form"><div id="turnstile-checkout"></div></form><script>const turnstileSiteKey = "1x00000000000000000000AA";</script>`;
  const { findings, surfaces } = A(html, { map: parseEndpointMap('#checkout-form => /api/a mode=json\n#checkout-form => /api/b mode=json') });
  check('a test sitekey is ONE critical however many entries map its form', sevOf(findings, 'sitekey-real').length === 1 && surfaces.length === 2, JSON.stringify(findings));
}
{
  // the epn shape, form mode: a later entry without token=/fields= must still reach the bot gate
  const html = `<form data-epn-form="contact" action="/api/contact"><input type="hidden" name="formType" value="contact"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`;
  const map = parseEndpointMap('[data-epn-form="contact"] => /api/contact expect=turnstile_failed\n.cf-turnstile => /api/callback expect=turnstile_failed');
  const { findings, surfaces } = A(html, { map });
  check("form mode: the later entry gets the widget's token field and the routing field", surfaces.length === 2 && surfaces[1].tokenField === 'cf-turnstile-response' && surfaces[1].fields.formType === 'contact' && surfaces[1].widgetType === 'turnstile', JSON.stringify(surfaces));
  check('…and no widget-not-static INFO for a form whose widget is static', !ids(findings).includes('widget-not-static'), JSON.stringify(findings));
}
{
  const map = parseEndpointMap('#checkout-form => https://[bad/api mode=json\n#checkout-form => /api/cart/track mode=json');
  const { findings, surfaces } = A('<form id="checkout-form"></form>', { url: 'https://www.lampakia.gr/checkout/', map });
  check('an entry whose endpoint is no URL is named in a WARN, and the next entry is still probed', surfaces.length === 1 && surfaces[0].endpoint === 'https://www.lampakia.gr/api/cart/track' && findings.some((x) => x.id === 'endpoint-unknown' && x.sev === SEV.WARN && x.msg.includes('=> https://[bad/api')), JSON.stringify({ findings, surfaces }));
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

console.log("\n# the step summary's cut (pure)");
{
  // Reports in check.mjs's grammar, each line labelled by hand: F fixed, P a parent, [rank, parent] a row.
  // The cut at a cap is then built here the long way — the largest k for which the fixed lines, the first
  // k rows (❌ first, report order within a rank) with their parents, a blank line and the longest note
  // (every row left out) fit — and fitReport must give exactly that, at every cap.
  const C = 'https://shop.example/contact/', G = 'https://shop.example/επικοινωνία/', E = 'https://shop.example/api/contact';
  const NL = 'https://shop.example/api/newsletter';
  const HEAD = [
    ['## 🛡️ form-protection — bot-gate enforced end-to-end', 'F'], ['', 'F'],
    ['- mode: report-only (never blocks)', 'F'], ['- pages checked: 4', 'F'],
    ['- submit probe: on (tokenless + junk-token POST per endpoint)', 'F'],
  ];
  const SPEC = [
    ...HEAD,
    ['- ⚠️ unparseable `form-endpoints` line (want `selector => endpoint [mode=json] [token=…] [expect=…]`): `#checkout-form - /api/order`', 'F'],
    ['', 'F'], ['### Pages', 'F'],
    ['- ⚠️ https://shop.example/old-form/ — HTTP 404 (page missing?) — nothing to check here; fix the wired URL', [1, -1]],
    [`- ❌ [${C}](${C})  \`HTTP 200\` · 2 gated form(s)`, 'P'],
    [`  - ❌ \`sitekey-real\` — form#contact on ${C} — sitekey "1x00000000000000000000AA" is a KNOWN TEST/PLACEHOLDER key (test keys pass every client, so the widget is decorative)`, [0, 9]],
    [`  - ⚠️ \`endpoint-unknown\` — form#callback on ${C} — no form action and no form-endpoints entry matches; server-rejects probe skipped (add a form-endpoints mapping)`, [1, 9]],
    [`  - ℹ️ \`widget-not-static\` — form#newsletter on ${C} — mapped for probing but no bot widget (or sitekey) in the static HTML; widget is client-rendered, static sitekey-real check skipped`, [2, 9]],
    ['- ⚠️ https://shop.example/quote/ — fetch failed (ECONNRESET) — infra issue, not a content defect (not counted as critical)', [1, -1]],
    [`- ✅ [${G}](${G})  \`HTTP 200\` · 1 gated form(s)`, 'P'],
    [`  - ✅ form#epafi → ${E}`, [3, 14]],
    ['', 'F'], ['### Submit probes (tokenless + junk-token POST must hard-reject)', 'F'],
    [`- **${E}** (form) ← form#contact @ ${C} · form#epafi @ ${G}`, 'P'],
    [`  - ✅ ${E} (tokenless POST) — hard reject (HTTP 403)`, [3, 18]],
    [`  - ❌ \`server-rejects\` — ${E} (junk-token POST) — endpoint ACCEPTED the POST (HTTP 200) — the server never verifies the token (skip-verify): bot protection is a client-side decoration`, [0, 18]],
    [`- **${NL}** (json) ← form#newsletter @ ${C}`, 'P'],
    ['  - ⚠️ tokenless POST — network error (ECONNRESET); probe inconclusive', [1, 21]],
    ['  - ⚠️ junk-token POST — network error (ECONNRESET); probe inconclusive', [1, 21]],
    ['', 'F'], ['**critical: 2 · warnings: 6 · info: 1**', 'F'],
    ['report-only — 2 critical check(s) would BLOCK under `fail-on-critical: true`.', 'F'],
  ];
  // No endpoint to probe: the section's one line is a row with no icon, ranked with ✅.
  const BARE = [
    ...HEAD, ['', 'F'], ['### Pages', 'F'],
    [`- ❌ [${C}](${C})  \`HTTP 200\` · 0 gated form(s)`, 'P'],
    [`  - ❌ \`sitekey-real\` — form#contact on ${C} — bot widget has no data-sitekey and no sitekey found in inline scripts (missing key)`, [0, 7]],
    [`  - ⚠️ \`endpoint-unknown\` — form#contact on ${C} — no form action and no form-endpoints entry matches; server-rejects probe skipped (add a form-endpoints mapping)`, [1, 7]],
    [`- ⚠️ [${G}](${G})  \`HTTP 200\` · 0 gated form(s)`, 'P'],
    [`  - ⚠️ \`no-gated-form\` — ${G} — no bot-widget form and no form-endpoints match on this page (widget removed, selector drifted, or the wrong URL is wired)`, [1, 10]],
    ['', 'F'], ['### Submit probes (tokenless + junk-token POST must hard-reject)', 'F'],
    ['- no probe-able endpoints resolved (no gated forms found, or all lacked an endpoint)', [3, -1]],
    ['', 'F'], ['**critical: 1 · warnings: 2 · info: 0**', 'F'],
    ['report-only — 1 critical check(s) would BLOCK under `fail-on-critical: true`.', 'F'],
  ];
  const RUN = 'https://github.com/acme/site/actions/runs/33911783576';
  const by = (spec) => {
    const lines = spec.map(([l]) => l);
    const whole = `${lines.join('\n')}\n`;
    const order = spec.map((_, i) => i).filter((i) => Array.isArray(spec[i][1])).sort((a, b) => spec[a][1][0] - spec[b][1][0] || a - b);
    const built = (k, n) => {
      const keep = new Set(spec.map((_, i) => i).filter((i) => spec[i][1] === 'F'));
      for (const i of order.slice(0, k)) { keep.add(i); if (spec[i][1][1] >= 0) keep.add(spec[i][1][1]); }
      return `${[...lines.filter((_, i) => keep.has(i)), '', `(truncated — ${n} more rows; the full report is in the run log: ${RUN})`].join('\n')}\n`;
    };
    const expect = (cap) => {
      if (Buffer.byteLength(whole) <= cap) return whole;
      let k = 0;
      while (k < order.length && Buffer.byteLength(built(k + 1, order.length)) <= cap) k++;
      return built(k, order.length - k);
    };
    const lo = Buffer.byteLength(built(0, order.length)), hi = Buffer.byteLength(whole) + 1;
    const bad = [];
    for (let cap = lo - 3; cap <= hi; cap++) if (fitReport(lines, RUN, cap) !== expect(cap)) bad.push(cap);
    return { lines, order, built, lo, hi, bad };
  };
  const full = by(SPEC), bare = by(BARE);
  for (const [label, s] of [['a report with every kind of line', full], ['a report with no endpoint to probe', bare]]) {
    check(`fitReport, ${label}: at every cap from ${s.lo - 3} to ${s.hi} bytes it is the cut built by hand`, s.bad.length === 0, `wrong at ${s.bad.slice(0, 5).join(', ')}`);
  }
  const { lines, built, order } = full;
  const mid = fitReport(lines, RUN, Buffer.byteLength(built(4, order.length)));
  check('…a mid cut: both ❌ rows with their page and endpoint, the first two ⚠️, the note counting the other 6',
    mid === built(4, order.length - 4) && mid.includes('`server-rejects`') && mid.includes('/old-form/ — HTTP 404') && !mid.includes('fetch failed') && mid.endsWith(`(truncated — 6 more rows; the full report is in the run log: ${RUN})\n`), JSON.stringify(mid.slice(-300)));
  // Ranked ❌, the short row with no icon would take the second place; with ✅, a ⚠️ row has it.
  const low = fitReport(bare.lines, RUN, Buffer.byteLength(bare.built(2, 4)));
  check('…a row with no icon ranks with ✅, after every ⚠️', low === bare.built(2, 2) && !low.includes('no probe-able endpoints'), JSON.stringify(low.slice(-300)));
  // A crash mid-report: no totals, the crash note last — kept where no row fits, so never a row.
  const crashed = [...lines.slice(0, 16), '- ❌ form-protection crashed: TypeError: x is not a function'];
  const one = `${[...lines.slice(0, 8), crashed[16], '', `(truncated — 6 more rows; the full report is in the run log: ${RUN})`].join('\n')}\n`;
  check('…a report cut short by a crash: the crash note is kept where no row fits', fitReport(crashed, RUN, Buffer.byteLength(one)) === one, JSON.stringify(fitReport(crashed, RUN, Buffer.byteLength(one))));
  const noRows = [lines[0], '', '- ❌ **no URLs resolved** — `sitemap-url`/`urls` was set but expanded to nothing (the gate checked zero pages).', '', '**critical: 1 · warnings: 0**', 'x'.repeat(200)];
  check('…no row to cut: an over-cap report goes whole, with no note', fitReport(noRows, RUN, 100) === `${noRows.join('\n')}\n`);
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
  // one client-rendered form fronting two gated endpoints (the lampakia checkout shape)
  '/page-two-endpoints.html': `<html><body><form id="checkout-form"><input type="hidden" name="formType" value="contact"><div id="turnstile-checkout"></div><div id="turnstile-cart-track"></div></form><script>const turnstileSiteKey = "${REAL_KEY}";</script></body></html>`,
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
// `script`: a copy with a fault injected (F).
function runCli(extraEnv, script = fileURLToPath(new URL('./check.mjs', import.meta.url))) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'form-prot-'));
  const summary = path.join(dir, 'summary.md');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], {
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
// one form, two entries: the second (a widget container inside the form, form mode) needs the
// form's hidden routing field to reach its bot gate — probed as a formless surface it would
// bounce off the router without the signature, a false CRITICAL
{
  const r = await runCli({
    URLS: `${BASE}/page-two-endpoints.html`, FAIL_ON_CRITICAL: 'true',
    FORM_ENDPOINTS: '#checkout-form => /api/reject mode=json token=turnstileToken expect=turnstile_failed\n#turnstile-cart-track => /api/routed-reject expect=turnstile_failed',
  });
  check('e2e two endpoints on one form: both reach their gate → exit 0', r.code === 0, `${r.stderr} ${r.summary}`);
  check('e2e two endpoints on one form: page line counts 1 form, 2 endpoints', r.summary.includes('· 1 gated form(s) · 2 endpoints'), r.summary);
  check('e2e two endpoints on one form: both probed, all four POSTs hard-rejected with the signature', r.summary.includes(`**${BASE}/api/reject**`) && r.summary.includes(`**${BASE}/api/routed-reject**`) && r.summary.split('signature "turnstile_failed" present').length === 5, r.summary);
}
// …and a skip-verifying SECOND endpoint on the form still blocks
{
  const r = await runCli({
    URLS: `${BASE}/page-two-endpoints.html`, FAIL_ON_CRITICAL: 'true',
    FORM_ENDPOINTS: '#checkout-form => /api/reject mode=json token=turnstileToken expect=turnstile_failed\n#checkout-form => /api/accept mode=json',
  });
  check('e2e skip-verify behind the second entry: exit 1, ACCEPTED reported for that endpoint', r.code === 1 && r.summary.includes(`${BASE}/api/accept (tokenless POST) — endpoint ACCEPTED`), `${r.stderr} ${r.summary}`);
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

  // (F) The step summary stays under GitHub's limit (v1.29.6). GitHub drops a step summary over 1 MiB (the
  // upload fails with an error annotation, so the run shows none), so a report over 900,000 bytes is cut for
  // the summary alone (fitReport, pinned cap by cap above): the fixed lines, as many whole rows as fit, worst
  // first, each with its page or endpoint line, then a note counting the rows left out. The log keeps every
  // line. No GITHUB_ACTIONS here, so a run's log is its report whole.
  const CAP = 900000;
  const RUN_URL = 'https://github.com/acme/site/actions/runs/33911783576';
  // Pages of four kinds, five in turn: 20 forms on a test sitekey (a ❌ row each) and 20 with no action (a ⚠️
  // row each); 40 with no action; a mapped form with no widget (an ℹ️ row); a clean form (✅), twice. Every
  // probe-able form posts to /api/reject with one token field, so the probes come to one endpoint.
  const forms = (n, html) => Array.from({ length: n }, (_, j) => html(String(j).padStart(2, '0'))).join('');
  const onTestKey = (id) => `<form id="t${id}" action="/api/reject"><div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div></form>`;
  const noAction = (id) => `<form id="w${id}"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`;
  const KINDS = [
    forms(20, onTestKey) + forms(20, noAction),
    forms(40, noAction),
    '<form id="m" class="m"></form>',
    `<form id="ok" action="/api/reject"><div class="cf-turnstile" data-sitekey="${REAL_KEY}"></div></form>`,
  ];
  const big = createServer((req, res) => {
    const n = Number((req.url.match(/^\/sitemap-(\d+)\.xml$/) || [])[1]), m = req.url.match(/^\/p\/(\d{5})\/$/);
    if (req.method === 'POST' && req.url === '/api/reject') { res.writeHead(403, { 'content-type': 'application/json' }); return res.end('{"ok":false,"error":"turnstile_failed"}'); }
    if (n) { res.writeHead(200, { 'content-type': 'application/xml' }); return res.end(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${Array.from({ length: n }, (_, i) => `<url><loc>http://${req.headers.host}/p/${String(i).padStart(5, '0')}/</loc></url>`).join('')}</urlset>`); }
    if (!m) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(`<html><body>${KINDS[Math.min(Number(m[1]) % 5, 3)]}</body></html>`);
  });
  await new Promise((r) => big.listen(0, '127.0.0.1', r));
  const SITE = `http://127.0.0.1:${big.address().port}`;
  // K unparseable `form-endpoints` lines in every run, a head line each, with `pad` bytes spread over them: the
  // knob for the boundary below (each prints whole up to 120 characters, and a constant K keeps the counts).
  const K = 250;
  const pages = (n, pad = 0, extra = {}) => ({
    GITHUB_REPOSITORY: 'acme/site', GITHUB_RUN_ID: '33911783576', SITEMAP_URL: `${SITE}/sitemap-${n}.xml`, MAX_URLS: String(n),
    FORM_ENDPOINTS: ['.m => /api/reject token=cf-turnstile-response', ...Array.from({ length: K }, (_, j) => 'x'.repeat(1 + Math.floor(pad / K) + (j < pad % K ? 1 : 0)))].join('\n'),
    ...extra,
  });
  // What a cut summary owes against its report (`log`), each property on its own. A row is an indented line
  // (this site prints no other); its parent is the margin line above it, unless a heading comes between.
  const ICONS = ['❌', '⚠️', 'ℹ️', '✅'];
  const rankOf = (l) => { const k = ICONS.findIndex((c) => l.trimStart().slice(2).startsWith(c)); return k < 0 ? 3 : k; };
  const cutOf = (summary, log, cap = CAP) => {
    const m = summary.match(/^([\s\S]*)\n\n\(truncated — (\d+) more rows; the full report is in the run log: (\S+)\)\n$/);
    const rep = log.slice(0, -1).split('\n');
    let j = 0;
    const at = (m ? m[1].split('\n') : []).map((l) => { while (j < rep.length && rep[j] !== l) j++; return j++; });
    const kept = new Set(at);
    const first = rep.findIndex((l) => l.startsWith('### ')), tail = rep.findLastIndex((l) => l.startsWith('**critical: '));
    const body = (i) => i > first && i < tail && rep[i] !== '' && !rep[i].startsWith('### ');
    const parentOf = [];
    let p = -1;
    rep.forEach((l, i) => { if (l.startsWith(' ')) parentOf[i] = p; else p = body(i) ? i : -1; });
    const rows = rep.map((_, i) => i).filter((i) => body(i) && rep[i].startsWith(' '));
    const order = [...rows].sort((a, b) => rankOf(rep[a]) - rankOf(rep[b]) || a - b);
    const k = order.findIndex((i) => !kept.has(i));
    const keptRows = rows.filter((i) => kept.has(i));
    const under = new Set(keptRows.map((i) => parentOf[i]));
    const size = Buffer.byteLength(summary);
    const cost = (i) => Buffer.byteLength(rep[i]) + 1 + (parentOf[i] >= 0 && !kept.has(parentOf[i]) ? Buffer.byteLength(rep[parentOf[i]]) + 1 : 0);
    return { size, rep, rows, keptRows,
      under: size <= cap,
      shape: !!m && m[3] === RUN_URL,
      inOrder: at.length > 0 && at.every((x) => x < rep.length),
      fixed: rep.every((_, i) => body(i) || kept.has(i)),
      prefix: k > 0 && order.slice(k).every((i) => !kept.has(i)),
      parents: keptRows.every((i) => parentOf[i] < 0 || kept.has(parentOf[i])) && at.every((i) => !body(i) || rep[i].startsWith(' ') || under.has(i)),
      count: !!m && Number(m[2]) === rows.length - keptRows.length,
      // The first row left out would not fit, the note budgeted at its longest (every row left out).
      fill: k > 0 && cap - size - (String(rows.length).length - String(rows.length - k).length) < cost(order[k]) };
  };
  const owed = (c) => c.under && c.shape && c.inOrder && c.fixed && c.prefix && c.parents && c.count && c.fill;
  const N = 350;
  try {
    const huge = await runCli(pages(N));
    const h = cutOf(huge.summary, huge.stdout);
    check(`summary, ${N} pages: exit 0, the report in the log once, past 1 MiB`, huge.code === 0 && once(huge) && Buffer.byteLength(huge.stdout) > 1048576, `${why(huge)} ${Buffer.byteLength(huge.stdout)} B`);
    check('…the summary is at most 900,000 bytes', h.under, `${h.size} B`);
    check('…the report cut, then the note with the run URL', h.shape, JSON.stringify(huge.summary.slice(-200)));
    check("…every line is the log's, in the log's order", h.inOrder);
    check('…the head (its unparseable-line warnings too), every heading, the totals and the verdict kept', h.fixed);
    const counts = [0, 1, 2, 3].map((r) => [h.rows, h.keptRows].map((set) => set.filter((i) => rankOf(h.rep[i]) === r).length));
    check(`…every ❌ row kept, the cut inside ⚠️ (kept ${counts.map(([all, kept]) => `${kept}/${all}`).join(', ')})`,
      counts[0][0] > 0 && counts[0][1] === counts[0][0] && counts[1][1] > 0 && counts[1][1] < counts[1][0] && counts[2][0] > 0 && counts[2][1] === 0 && counts[3][0] > 0 && counts[3][1] === 0);
    check('…the rows kept are the first in rank order, report order within a rank', h.prefix);
    check('…each with its page or endpoint line, and no such line without one', h.parents);
    check(`…the note counts the ${h.rows.length - h.keptRows.length} rows left out`, h.count);
    check('…and fills the room: the first row left out would not fit', h.fill, `${h.size} B`);

    // The boundary, both sides: whole groups of five pages to a little under 900,000 bytes, then the K head
    // lines lengthened to exactly 900,000 — the summary must be the report, byte for byte — then one byte more.
    const n = 5 * Math.floor((N * (CAP - 8000)) / (5 * Buffer.byteLength(huge.stdout)));
    const pad = CAP - Buffer.byteLength((await runCli(pages(n))).stdout);
    const atCap = await runCli(pages(n, pad));
    check(`summary, ${n} pages built to a report of exactly 900,000 bytes: the summary is the report, byte for byte`,
      pad >= 0 && pad + 1 <= 118 * K && Buffer.byteLength(atCap.stdout) === CAP && atCap.summary === atCap.stdout, `pad ${pad}, ${Buffer.byteLength(atCap.stdout)} B`);
    const pastCap = await runCli(pages(n, pad + 1));
    check('…one byte more: cut to at most 900,000, whole rows worst first, the rest counted',
      Buffer.byteLength(pastCap.stdout) === CAP + 1 && owed(cutOf(pastCap.summary, pastCap.stdout)), `${Buffer.byteLength(pastCap.summary)} B`);

    // A fault in the cut costs the run its summary, never its exit code: the log keeps the report whole and
    // names the fault in one plain line. A copy of the scripts whose fitReport throws.
    const HERE = path.dirname(fileURLToPath(import.meta.url));
    const faulty = fs.mkdtempSync(path.join(os.tmpdir(), 'form-prot-faulty-'));
    try {
      const source = fs.readFileSync(path.join(HERE, 'checks.mjs'), 'utf8');
      const CUT = 'export function fitReport(lines, runUrl, cap = SUMMARY_CAP) {';
      check('fault-injection anchor still present in checks.mjs', source.includes(CUT));
      fs.writeFileSync(path.join(faulty, 'checks.mjs'), source.replace(CUT, `${CUT} throw new Error('injected cut fault');`));
      fs.copyFileSync(path.join(HERE, 'check.mjs'), path.join(faulty, 'check.mjs'));
      fs.symlinkSync(path.join(HERE, '..', 'node_modules'), path.join(faulty, 'node_modules'));
      const FAULT = "form-protection: the report is over the step summary's limit and could not be cut, so the summary does not carry it; the job log above holds every row (injected cut fault)";
      const sunk = await runCli(pages(N), path.join(faulty, 'check.mjs'));
      check('a fault in the cut: the log is the report whole, then one plain line naming it; no summary; exit 0',
        sunk.stdout === `${huge.stdout}${FAULT}\n` && sunk.summary === '' && sunk.code === 0, `${why(sunk)} ${JSON.stringify(sunk.stdout.slice(-200))}`);
      const sunkEnforcing = await runCli(pages(N, 0, { FAIL_ON_CRITICAL: 'true' }), path.join(faulty, 'check.mjs'));
      check('…under fail-on-critical: the criticals still BLOCK (exit 1), the fault a line, not a crash',
        sunkEnforcing.code === 1 && /\nBLOCKED — \d+ critical check\(s\) failed\. Fix the ❌ items above\.\n$/.test(sunkEnforcing.stdout.slice(0, -FAULT.length - 1))
          && sunkEnforcing.stdout.endsWith(`\n${FAULT}\n`) && !sunkEnforcing.stdout.includes('crashed') && sunkEnforcing.summary === '', why(sunkEnforcing));
    } finally {
      fs.rmSync(faulty, { recursive: true, force: true });
    }
  } finally {
    big.close();
  }
}

server.close();

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
