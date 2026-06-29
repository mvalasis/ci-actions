// security-baseline Astro/TS rule self-test fixture (semgrep --test).
// Each block isolates ONE rule. Run: semgrep --test --config rules/astro-ts.yaml rules/selftest/astro-ts.ts

declare const cp: any, AsyncStorage: any, SecureStore: any, Astro: any, req: any, env: any;

// ---- ts-dynamic-code-exec ----
function evalBad(input: string) {
  // ruleid: ts-dynamic-code-exec
  return new Function('ctx', input);
}
function evalOk() {
  // ok: ts-dynamic-code-exec
  return new Function('a', 'b', 'return a + b');
}

// ---- ts-child-process-dynamic ----
async function cpBad(host: string) {
  // ruleid: ts-child-process-dynamic
  cp.execSync(`ping -c1 ${host}`);
}
function cpOk() {
  // ok: ts-child-process-dynamic
  cp.execSync('git rev-parse HEAD');
}

// ---- ts-public-env-secret-leak ----
function pubSecretBad() {
  // ruleid: ts-public-env-secret-leak
  return import.meta.env.PUBLIC_STRIPE_SECRET_KEY;
}
function pubSecretOk() {
  // ok: ts-public-env-secret-leak
  return import.meta.env.PUBLIC_GA4_ID;
}

// ---- ts-ssrf-request-derived-fetch ----
async function ssrfBad() {
  const target = new URL(req.url).searchParams.get('u');
  // ruleid: ts-ssrf-request-derived-fetch
  return fetch(target);
}
async function ssrfOk() {
  // ok: ts-ssrf-request-derived-fetch
  return fetch(`${env.FIXED_BASE}/wp-json/wc/v3/stock`);
}
async function ssrfOkBodyTainted() {
  const body = await req.json();
  // ok: ts-ssrf-request-derived-fetch
  return fetch(`${env.FIXED_BASE}/save`, { method: 'POST', body: JSON.stringify(body) });
}
async function ssrfOkFixedOriginProxy() {
  const skus = new URL(req.url).searchParams.get('skus');
  // ok: ts-ssrf-request-derived-fetch
  return fetch(`${env.FIXED_BASE}?skus=${encodeURIComponent(skus)}`);
}

// ---- ts-open-redirect ----
function redirBad() {
  const next = Astro.url.searchParams.get('next');
  // ruleid: ts-open-redirect
  return Astro.redirect(next);
}
function redirOk() {
  // ok: ts-open-redirect
  return Astro.redirect('/');
}

// ---- ts-rn-token-in-asyncstorage ----
async function storeBad(jwt: string) {
  // ruleid: ts-rn-token-in-asyncstorage
  await AsyncStorage.setItem('auth_token', jwt);
}
async function storeOk(jwt: string) {
  // ok: ts-rn-token-in-asyncstorage
  await SecureStore.setItemAsync('auth_token', jwt);
}

// ---- ts-cleartext-http-fetch ----
async function httpBad() {
  // ruleid: ts-cleartext-http-fetch
  return fetch('http://api.lux-airport.lu/flights');
}
async function httpOk() {
  // ok: ts-cleartext-http-fetch
  return fetch('https://api.lux-airport.lu/flights');
}

// ---- ts-secret-in-log ----
function logBad() {
  // ruleid: ts-secret-in-log
  console.error('debug', env.MYPOS_PRIVATE_KEY);
}
function logOk() {
  // ok: ts-secret-in-log
  console.error('mypos signature generation failed');
}

// ---- ts-turnstile-test-sitekey ----
function turnstileBad() {
  // ruleid: ts-turnstile-test-sitekey
  return import.meta.env.PUBLIC_TURNSTILE_SITE_KEY || '0x0000000000000000000000';
}
function turnstileOk() {
  // ok: ts-turnstile-test-sitekey
  return import.meta.env.PUBLIC_TURNSTILE_SITE_KEY;
}

// ---- ts-cors-wildcard (T2 advisory) ----
function corsBad(h: Headers) {
  // ruleid: ts-cors-wildcard
  h.set('Access-Control-Allow-Origin', '*');
}
function corsOk(h: Headers) {
  // ok: ts-cors-wildcard
  h.set('Access-Control-Allow-Origin', 'https://www.lampakia.gr');
}
