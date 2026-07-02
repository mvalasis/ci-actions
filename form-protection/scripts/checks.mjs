// form-protection check engine — PURE functions, no network, no process exit.
// Parses the raw (JS-disabled) served HTML with a real DOM parser (cheerio),
// finds bot-widget-carrying forms, classifies their sitekeys, and resolves the
// submit endpoint for the live probe. The CLI (check.mjs) does the fetching +
// POST probes + I/O and calls these; selftest.mjs unit-tests them offline.
//
// Two CRITICAL checks (see README):
//   sitekey-real    — the widget ships a real sitekey, not a test/placeholder key
//   server-rejects  — the submit endpoint hard-rejects a tokenless / junk-token POST
// Everything else is WARN/INFO advisory.
import { load } from 'cheerio';

export const SEV = { CRIT: 'critical', WARN: 'warn', INFO: 'info', OK: 'ok' };

const f = (id, sev, msg) => ({ id, sev, msg });

// ---------- sitekey classification ----------

// Cloudflare Turnstile: real sitekeys are issued under 0x4…; the documented
// force-pass/force-block/force-challenge test keys all start 1x/2x/3x, and
// 0x followed by all zeros is the classic unset-env placeholder (exactly what
// epn-astro falls back to when PUBLIC_TURNSTILE_SITE_KEY is missing at build).
const TURNSTILE_TEST_PREFIX = /^[123]x/i;
const TURNSTILE_ZERO_PLACEHOLDER = /^0x0+$/i;
// Google reCAPTCHA: the documented universal test pair starts 6LeIxAcT (site)
// / same-shape secret — real keys have a random middle, so the prefix is safe.
const RECAPTCHA_TEST_PREFIX = /^6L[ec]IxAcT/i;
// hCaptcha: documented publisher/pro/enterprise test sitekeys.
const HCAPTCHA_TEST_KEYS = new Set([
  '10000000-ffff-ffff-ffff-000000000001',
  '20000000-ffff-ffff-ffff-000000000002',
  '30000000-ffff-ffff-ffff-000000000003',
]);

// → 'missing' | 'test' | 'real'. extra entries are exact values, or prefixes
// when they end with '*' (the test-sitekeys input).
export function classifySitekey(raw, extra = []) {
  const key = String(raw ?? '').trim();
  if (!key) return 'missing';
  if (TURNSTILE_TEST_PREFIX.test(key)) return 'test';
  if (TURNSTILE_ZERO_PLACEHOLDER.test(key)) return 'test';
  if (RECAPTCHA_TEST_PREFIX.test(key)) return 'test';
  if (HCAPTCHA_TEST_KEYS.has(key.toLowerCase())) return 'test';
  for (const e of extra) {
    if (!e) continue;
    if (e.endsWith('*') ? key.startsWith(e.slice(0, -1)) : key === e) return 'test';
  }
  return 'real';
}

// ---------- form-endpoints map ----------

// One entry per line: `<css-selector> => <endpoint> [mode=json] [token=<field>] [expect=<substring>]`
//   selector — matches the form element itself OR any element inside it (so a
//              widget container id like #turnstile-checkout works too)
//   endpoint — absolute URL or path (resolved against the page URL)
//   mode     — form (default, urlencoded) | json
//   token    — token field name for the junk-token probe (default: per widget
//              type in form mode, turnstileToken in json mode)
//   expect   — substring the reject body MUST contain (the bot-gate's reject
//              signature, e.g. turnstile_failed). This is what distinguishes
//              "the bot gate rejected" from "field validation rejected while
//              the bot gate silently skip-verified" — set it wherever you know
//              the signature.
export function parseEndpointMap(raw) {
  const entries = [];
  for (const line of String(raw || '').split(/\n+/)) {
    const t = line.trim();
    if (!t) continue;
    const i = t.indexOf('=>');
    // '#'-lines are comments ONLY when they carry no '=>' — an id selector
    // (#checkout-form => …) also starts with '#'.
    if (i < 0 && t.startsWith('#')) continue;
    const selector = i > 0 ? t.slice(0, i).trim() : '';
    const parts = i > 0 ? t.slice(i + 2).trim().split(/\s+/) : [];
    const endpoint = parts.shift() || '';
    if (!selector || !endpoint) { entries.push({ error: t }); continue; }
    const opts = {};
    for (const p of parts) { const j = p.indexOf('='); if (j > 0) opts[p.slice(0, j)] = p.slice(j + 1); }
    entries.push({
      selector, endpoint,
      mode: opts.mode === 'json' ? 'json' : 'form',
      token: opts.token || '',
      expect: opts.expect || '',
    });
  }
  return entries;
}

// ---------- page analysis ----------

const WIDGET_TYPES = [
  ['.cf-turnstile', 'turnstile'],
  ['.g-recaptcha', 'recaptcha'],
  ['.h-captcha', 'hcaptcha'],
  ['[data-sitekey]', 'sitekey'],
];
const WIDGET_UNION = WIDGET_TYPES.map(([s]) => s).join(', ');

export const TOKEN_FIELD = {
  turnstile: 'cf-turnstile-response',
  recaptcha: 'g-recaptcha-response',
  hcaptcha: 'h-captcha-response',
};

// Client-rendered widgets (lampakia checkout) carry no data-sitekey in the
// static HTML — the key lives in an inline script (`turnstileSiteKey = "…"`,
// `sitekey: "…"`). Scrape every quoted value assigned to a *sitekey-ish name.
export function sitekeysFromScripts($) {
  const keys = [];
  $('script').each((_, el) => {
    const text = $(el).text() || '';
    for (const m of text.matchAll(/sitekey["']?\s*[:=]\s*["']([^"']*)["']/gi)) keys.push(m[1]);
  });
  return keys;
}

function describeForm($, el) {
  const $el = $(el);
  const id = $el.attr('id');
  if (id) return `form#${id}`;
  const name = $el.attr('data-epn-form') || $el.attr('name');
  if (name) return `form[${$el.attr('data-epn-form') ? 'data-epn-form' : 'name'}="${name}"]`;
  const cls = ($el.attr('class') || '').trim().split(/\s+/)[0];
  return cls ? `form.${cls}` : 'form';
}

function resolveUrl(endpoint, base) {
  try { return new URL(endpoint, base).href; } catch { return null; }
}

// Analyze one fetched page. Returns { findings, surfaces } where each surface
// is a probe target: { form, page, endpoint, mode, tokenField, expect,
// widgetType, mapped }. Endpoints are NOT deduped here — the CLI dedupes
// across pages before probing.
export function analyzeForms({ requestUrl, html, endpointMap = [], extraTestKeys = [] }) {
  const $ = load(html);
  const findings = [];
  const surfaces = [];
  const scriptKeys = sitekeysFromScripts($);
  const usedEntries = new Set();

  const gradeKey = (key, where) => {
    const cls = classifySitekey(key, extraTestKeys);
    if (cls === 'missing') findings.push(f('sitekey-real', SEV.CRIT, `${where} — sitekey is missing/empty (widget can never issue a token; on an enforcing server every real user is rejected, on a skip-verifying server the gate is a no-op)`));
    else if (cls === 'test') findings.push(f('sitekey-real', SEV.CRIT, `${where} — sitekey "${key}" is a KNOWN TEST/PLACEHOLDER key (test keys pass every client, so the widget is decorative)`));
    return cls;
  };

  // Grade sitekeys scraped from inline scripts. A page can match more than one
  // assignment (unrelated config blobs); empty matches only count when NOTHING
  // non-empty was found — an all-empty scrape is the unset-env-at-build signal.
  const gradeScriptKeys = (where) => {
    const nonEmpty = scriptKeys.filter((k) => String(k).trim() !== '');
    (nonEmpty.length ? nonEmpty : scriptKeys).forEach((k) => gradeKey(k, where));
  };

  const mapEntryFor = (formEl) => endpointMap.find((e) => {
    if (e.error) return false;
    try { return $(formEl).is(e.selector) || $(formEl).find(e.selector).length > 0; } catch { return false; }
  });

  // 1. widget-carrying <form>s (the epn-astro shape: static data-sitekey + action attr)
  $('form').each((_, formEl) => {
    const $form = $(formEl);
    const widget = $form.find(WIDGET_UNION).first();
    const entry = mapEntryFor(formEl);
    if (entry) usedEntries.add(entry);
    if (!widget.length && !entry) return; // plain form — not this gate's business

    const where = `${describeForm($, formEl)} on ${requestUrl}`;
    let widgetType = null;
    if (widget.length) {
      widgetType = (WIDGET_TYPES.find(([sel]) => widget.is(sel)) || [])[1] || 'sitekey';
      const attrKey = widget.attr('data-sitekey');
      if (attrKey !== undefined) gradeKey(attrKey, where);
      else if (scriptKeys.length) gradeScriptKeys(`${where} (sitekey from inline script)`);
      else findings.push(f('sitekey-real', SEV.CRIT, `${where} — bot widget has no data-sitekey and no sitekey found in inline scripts (missing key)`));
    } else {
      // mapped form with no static widget (the lampakia shape: client-rendered)
      if (scriptKeys.length) gradeScriptKeys(`${where} (client-rendered widget; sitekey from inline script)`);
      else findings.push(f('widget-not-static', SEV.INFO, `${where} — mapped for probing but no bot widget (or sitekey) in the static HTML; widget is client-rendered, static sitekey-real check skipped`));
    }

    // No/empty action ≠ "posts to the page": on a static host that masks the
    // probe entirely, so treat it as unmapped and ask for a form-endpoints entry.
    const action = ($form.attr('action') || '').trim();
    const endpoint = entry ? resolveUrl(entry.endpoint, requestUrl)
      : (action ? resolveUrl(action, requestUrl) : null);
    if (!endpoint) {
      findings.push(f('endpoint-unknown', SEV.WARN, `${where} — no <form action> and no form-endpoints entry matches; server-rejects probe skipped (add a form-endpoints mapping)`));
      return;
    }
    surfaces.push({
      form: describeForm($, formEl), page: requestUrl, endpoint,
      mode: entry?.mode || 'form',
      tokenField: entry?.token || (widgetType && TOKEN_FIELD[widgetType]) || '',
      expect: entry?.expect || '',
      widgetType: widgetType || 'client-rendered',
      mapped: !!entry,
    });
  });

  // 2. map entries that match the page OUTSIDE any <form> (JS-driven surfaces
  // with no form element at all)
  for (const entry of endpointMap) {
    if (entry.error || usedEntries.has(entry)) continue;
    let hits; try { hits = $(entry.selector); } catch { continue; }
    if (!hits.length) continue;
    const endpoint = resolveUrl(entry.endpoint, requestUrl);
    if (!endpoint) continue;
    const where = `${entry.selector} on ${requestUrl}`;
    if (scriptKeys.length) gradeScriptKeys(`${where} (sitekey from inline script)`);
    else findings.push(f('widget-not-static', SEV.INFO, `${where} — mapped surface with no static widget markup; sitekey check skipped (client-rendered)`));
    surfaces.push({
      form: entry.selector, page: requestUrl, endpoint,
      mode: entry.mode, tokenField: entry.token || (entry.mode === 'json' ? 'turnstileToken' : ''),
      expect: entry.expect, widgetType: 'client-rendered', mapped: true,
    });
  }

  // 3. nothing gated at all on a page the caller explicitly listed → drift signal
  if (!surfaces.length && !findings.length) {
    findings.push(f('no-gated-form', SEV.WARN, `${requestUrl} — no bot-widget form and no form-endpoints match on this page (widget removed, selector drifted, or the wrong URL is wired)`));
  }

  return { findings, surfaces };
}

// ---------- probe verdicts ----------

export const JUNK_TOKEN = 'ci-form-protection-probe.invalid.00000000000000000000000000000000';

// Default token field when we couldn't infer one (json mode default matches
// the common hand-rolled JSON API shape).
export function defaultTokenField(surface) {
  if (surface.tokenField) return surface.tokenField;
  return surface.mode === 'json' ? 'turnstileToken' : TOKEN_FIELD.turnstile;
}

// Build the POST body for a probe. Tokenless = minimal valid body with NO
// token field; junk-token = same + a syntactically-invalid token. We never
// fill in real-looking form fields: a correctly-gated endpoint rejects before
// validation, and on a broken endpoint an empty payload can't create a record
// — that's what keeps the probe read-safe even against the failure it hunts.
export function buildProbeBody(surface, kind) {
  const tokenField = defaultTokenField(surface);
  if (surface.mode === 'json') {
    const body = kind === 'junk-token' ? { [tokenField]: JUNK_TOKEN } : {};
    return { body: JSON.stringify(body), contentType: 'application/json' };
  }
  const params = new URLSearchParams();
  if (kind === 'junk-token') {
    if (surface.tokenField || surface.widgetType in TOKEN_FIELD) params.set(tokenField, JUNK_TOKEN);
    else Object.values(TOKEN_FIELD).forEach((tf) => params.set(tf, JUNK_TOKEN)); // widget type unknown — cover all three
  }
  return { body: params.toString(), contentType: 'application/x-www-form-urlencoded' };
}

const bodyLooksRejected = (body) => {
  try {
    const j = JSON.parse(body);
    return j && typeof j === 'object' && (j.ok === false || j.success === false || (typeof j.error === 'string' && j.error !== ''));
  } catch { return false; }
};

// Judge one probe response (pure). kind: 'tokenless' | 'junk-token'.
// Returns a finding ({id, sev, msg}) — sev OK when the endpoint behaved.
export function judgeProbe({ kind, status, body, expect, endpoint }) {
  const label = `${endpoint} (${kind} POST)`;
  const snippet = String(body || '').slice(0, 2048);

  if (status >= 200 && status < 300) {
    if (bodyLooksRejected(snippet)) {
      if (expect && !snippet.includes(expect)) {
        return f('server-rejects', SEV.CRIT, `${label} — soft-rejected (HTTP ${status}) but WITHOUT the bot-gate signature "${expect}": the reject came from a later layer (field validation / upstream), so the bot gate never fired — server skip-verifies`);
      }
      return f('server-rejects', SEV.OK, `${label} — soft reject (HTTP ${status}, ok:false body)`);
    }
    return f('server-rejects', SEV.CRIT, `${label} — endpoint ACCEPTED the POST (HTTP ${status}) — the server never verifies the token (skip-verify): bot protection is a client-side decoration`);
  }
  if (status >= 300 && status < 400) {
    return f('probe-inconclusive', SEV.WARN, `${label} — redirected (HTTP ${status}); can't distinguish a PRG success from a reject. Make the endpoint reject with 403/JSON, or set expect= on its form-endpoints entry`);
  }
  if (status >= 500) {
    return f('probe-inconclusive', SEV.WARN, `${label} — endpoint errored (HTTP ${status}); not a clean reject, verification unconfirmed`);
  }
  // 4xx — rejected. With an expect signature we can assert WHICH layer rejected.
  if (expect && !snippet.includes(expect)) {
    return f('server-rejects', SEV.CRIT, `${label} — rejected (HTTP ${status}) but WITHOUT the bot-gate signature "${expect}": the reject came from a different layer (field validation / WAF), so the bot gate did not fire — on a well-formed submission the server would skip-verify`);
  }
  return f('server-rejects', SEV.OK, `${label} — hard reject (HTTP ${status}${expect ? `, signature "${expect}" present` : ''})`);
}
