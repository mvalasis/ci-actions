// contract-check engine — PURE functions, no network, no process exit.
// Validates a fetched WP/WC REST JSON payload against a committed contract entry
// (required fields + type expectations + money/encoding invariants). The CLI
// (check.mjs) does the fetching + I/O and calls these; selftest.mjs unit-tests them
// offline against saved fixtures.
//
// Severity tiers (see README): T0 = always CRITICAL — a declared required field is
// MISSING or its TYPE changed, or a money/encoding invariant is violated. These are
// the silent-breakage / mis-pricing class a backend change inflicts on a deployed
// Astro/RN consumer. T1 = WARN, opt-in promotable to CRITICAL per-caller via
// `critical-checks`. T2 = advisory WARN/INFO drift.

export const SEV = { CRIT: 'critical', WARN: 'warn', INFO: 'info', OK: 'ok' };

// T0 — the only checks born CRITICAL. Each is binary, config-free, and always a real
// break of the consumer contract: a missing/retyped required field, or a money/encoding
// invariant. These are what a backend change must never silently do to a live consumer.
export const T0_CHECKS = new Set([
  'required-present',   // a declared required field is missing/null
  'required-type',      // a declared required field changed JS type
  'invariant-price',    // a price field is present but <= 0 (free items must be declared, not zero-by-accident)
  'invariant-vat',      // inc-VAT < ex-VAT when BOTH present (over-discounted / mis-ordered totals)
  'invariant-currency', // currency code missing/empty when a price is present
  'invariant-slug',     // a slug/permalink field is present but empty
  'invariant-encoding', // a string field carries a double-encoded entity (&amp;amp; / &amp;#039;)
]);

// T1 — clean today, real drift, but not safe to assert fleet-wide without per-site
// eyeballing. A caller may ELEVATE any of these to CRITICAL via `critical-checks`.
export const T1_CHECKS = new Set([
  'invariant-declared',  // a declared invariant referenced a field that isn't in the payload
  'optional-null',       // a declared optional field came back null (consumer should handle, but flag drift)
  'unexpected-field',    // a top-level field appeared that the contract didn't declare (backend added a field)
  'array-empty',         // an endpoint declared to return a non-empty collection came back []
]);
// Everything else is T2 (advisory; ignored if a caller tries to promote it).

const f = (id, sev, msg) => ({ id, sev, msg });

// ---------- small helpers ----------

// JS-runtime type label that's stable for contract comparison. We distinguish
// null / array / object / number / string / boolean — the JSON type set a consumer
// actually destructures on. A WP/WC field flipping string->number (e.g. price "12.00"
// -> 12) or object->array (an empty WC meta_data {} that becomes []) is the classic
// silent break, so the labels must be precise.
export function jsonType(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v; // 'object' | 'number' | 'string' | 'boolean' | 'undefined'
}

// Resolve a dotted/bracketed path against a payload. Supports `a.b`, `a.0.b`,
// `a[0].b`. Returns { found, value } so a present-but-null/undefined field is
// distinguishable from an absent one.
export function getPath(obj, path) {
  const parts = String(path).replace(/\[(\d+)\]/g, '.$1').split('.').filter((s) => s !== '');
  let cur = obj;
  for (const p of parts) {
    if (cur === null || cur === undefined) return { found: false, value: undefined };
    if (typeof cur !== 'object') return { found: false, value: undefined };
    if (Array.isArray(cur)) {
      const idx = Number(p);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return { found: false, value: undefined };
      cur = cur[idx];
    } else {
      if (!Object.prototype.hasOwnProperty.call(cur, p)) return { found: false, value: undefined };
      cur = cur[p];
    }
  }
  return { found: true, value: cur };
}

// Coerce a money-ish value to a finite number, or null if it isn't one. WP/WC commonly
// serialise prices as strings ("14.00"), so accept a numeric string; reject ''/null/NaN.
export function toMoney(v) {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null;
  if (typeof v === 'string') {
    const s = v.trim();
    if (s === '') return null;
    // strip a single leading currency symbol / trailing code is NOT done here — a contract
    // money field is expected to be the raw numeric amount (WC `price`, `regular_price`…).
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

// Double-encoded HTML entity: an `&amp;` that itself encodes another entity
// (`&amp;amp;`, `&amp;#039;`, `&amp;quot;`, `&amp;lt;`…). This is the WP REST
// double-encode bug that ships "Q&amp;amp;A" / "It&amp;#039;s" to a headless renderer
// that then prints the literal `&amp;`. A single `&amp;` is normal/correct, so the
// pattern requires `&amp;` immediately followed by `#`/`x`/a known entity name + `;`
// or another `amp;`.
const DOUBLE_ENCODED = /&amp;(?:amp;|#\d+;|#x[0-9a-f]+;|[a-z]+;)/i;
export function isDoubleEncoded(s) {
  return typeof s === 'string' && DOUBLE_ENCODED.test(s);
}

// A "price-shaped" field name a WC payload exposes — used to apply the price>0 invariant
// to any declared money field generically, and (when a contract doesn't enumerate them)
// to auto-detect the common WC trio for the inc/ex-VAT ordering check.
const PRICE_FIELD_RE = /(^|[._-])(price|regular_price|sale_price|total|subtotal|amount|gross|net)([._-]|$)/i;

// ---------- the per-payload analyzer ----------

// input: { name, url, status, contentType, json (parsed) OR parseError, contract }
//   contract = { required?: string[], types?: {path:type}, invariants?: string[],
//                optional?: string[], nonEmpty?: boolean, allowExtra?: boolean,
//                expectFields?: string[], money?: string[], slug?: string[] }
// Returns { name, url, status, findings }.
export function analyzePayload(input) {
  const { name, url, status, contract = {} } = input;
  const findings = [];
  const add = (...x) => findings.push(...x);
  const out = { name, url, status, findings };

  // T0.0 — transport. A non-2xx or a body that didn't parse as JSON is a hard break of
  // a JSON consumer contract (the consumer's `await res.json()` throws / it gets HTML).
  if (input.parseError) {
    add(f('json-parse', SEV.CRIT, `response is not valid JSON (${String(input.parseError).slice(0, 80)})`));
    return out;
  }
  if (status !== undefined && !(status >= 200 && status < 300)) {
    add(f('http-2xx', SEV.CRIT, `endpoint returned HTTP ${status} (expected 2xx) — consumer gets no payload`));
    return out;
  }
  add(f('http-2xx', SEV.OK, `HTTP ${status ?? '200'} · JSON parsed`));

  const root = input.json;
  // WP/WC list endpoints return a top-level array; the contract describes ONE item, so
  // validate the first element (and record array-shape for the nonEmpty check). A single
  // resource endpoint returns an object — validate it directly.
  const isArray = Array.isArray(root);
  const subject = isArray ? root[0] : root;

  if (contract.nonEmpty) {
    if (isArray && root.length === 0) { add(f('array-empty', SEV.WARN, 'endpoint declared nonEmpty but returned an empty array []')); return out; }
    if (!isArray && (root === null || (typeof root === 'object' && Object.keys(root).length === 0))) {
      add(f('array-empty', SEV.WARN, 'endpoint declared nonEmpty but returned an empty/null object')); return out;
    }
  }
  if (subject === undefined) { add(f('array-empty', SEV.WARN, 'no item to validate (empty collection)')); return out; }

  // ---- resolve money / slug / invariant config up front (the type comparison below needs
  //      to know which fields are money to grant the number<->string serialization exemption) ----
  const declaredMoney = Array.isArray(contract.money) ? contract.money : [];
  const declaredSlug = Array.isArray(contract.slug) ? contract.slug : [];
  const invariants = (Array.isArray(contract.invariants) ? contract.invariants : []).map((s) => String(s).trim()).filter(Boolean);
  // money paths: declared explicitly, else auto-detect price-shaped top-level keys.
  const moneyPaths = new Set(declaredMoney);
  if (declaredMoney.length === 0 && subject && typeof subject === 'object' && !Array.isArray(subject)) {
    for (const k of Object.keys(subject)) if (PRICE_FIELD_RE.test(k)) moneyPaths.add(k);
  }
  const isMoneyField = (path) => moneyPaths.has(path) || PRICE_FIELD_RE.test(String(path));

  // Shared type comparison. A number<->string flip is a real retype EXCEPT on a money field
  // (WC ships prices as numeric strings: `"14.00"` vs `14` is a serialization convention, not a
  // break). Scoping the exemption to money fields means an `id` declared `number` that arrives
  // as the string "412" is STILL caught — that genuinely breaks a consumer that does arithmetic
  // on it. Every other cross-kind flip (string<->object, object<->array, *->boolean) is a break.
  const typeBreak = (path, expected, value) => {
    const actual = jsonType(value);
    if (actual === expected) return null;
    const numStrFlip = (expected === 'number' && actual === 'string' && toMoney(value) !== null)
      || (expected === 'string' && actual === 'number');
    if (numStrFlip && isMoneyField(path)) return null;
    return actual;
  };

  // ---- required fields: presence (T0) + type (T0) ----
  const required = Array.isArray(contract.required) ? contract.required : [];
  const types = (contract.types && typeof contract.types === 'object') ? contract.types : {};
  for (const path of required) {
    const { found, value } = getPath(subject, path);
    if (!found || value === undefined || value === null) {
      add(f('required-present', SEV.CRIT, `required field \`${path}\` is ${found ? 'null' : 'MISSING'} — a consumer reading it breaks`));
      continue;
    }
    const expected = types[path];
    if (expected) {
      const got = typeBreak(path, expected, value);
      if (got) add(f('required-type', SEV.CRIT, `required field \`${path}\` changed type: expected ${expected}, got ${got}`));
    }
  }
  // type expectations on NON-required fields: a declared type that's wrong is still a break,
  // but a missing optional-typed field is fine (only flagged via optional-null below).
  for (const [path, expected] of Object.entries(types)) {
    if (required.includes(path)) continue;
    const { found, value } = getPath(subject, path);
    if (!found || value === null || value === undefined) continue;
    const got = typeBreak(path, expected, value);
    if (got) add(f('required-type', SEV.CRIT, `field \`${path}\` changed type: expected ${expected}, got ${got}`));
  }

  // ---- money / encoding invariants (T0) ----
  // Always honor explicit `price>0`-style invariants too (parsed below). The price floor
  // only fires when the invariant set asks for it OR a money field is explicitly declared —
  // auto-detected sale_price=0 is legitimately "no sale", so we DON'T floor auto-detected
  // fields on value, only declared ones.
  const wantsPriceFloor = invariants.some((i) => /price\s*>\s*0|price-?positive/i.test(i)) || declaredMoney.length > 0;
  if (wantsPriceFloor) {
    for (const path of moneyPaths) {
      const { found, value } = getPath(subject, path);
      if (!found || value === null || value === undefined || value === '') continue;
      const m = toMoney(value);
      if (m === null) { add(f('invariant-price', SEV.CRIT, `money field \`${path}\` is not a number: ${JSON.stringify(value).slice(0, 40)}`)); continue; }
      if (declaredMoney.includes(path) && m <= 0) add(f('invariant-price', SEV.CRIT, `money field \`${path}\` is ${m} (expected > 0)`));
    }
  }

  // inc-VAT >= ex-VAT when both present. The contract can pin the pair via an invariant
  // `incVat>=exVat:price_inc,price_ex`; otherwise auto-detect the WC convention
  // (price_including_tax vs price_excluding_tax / price vs price_excluding_tax).
  const vatInv = invariants.find((i) => /inc.?vat\s*>?=?\s*ex.?vat|incvat>=exvat/i.test(i));
  let incPath, exPath;
  if (vatInv) {
    const m = vatInv.split(':')[1];
    if (m) { const [a, b] = m.split(',').map((s) => s.trim()); incPath = a; exPath = b; }
  }
  if (!incPath || !exPath) {
    const keys = (subject && typeof subject === 'object' && !Array.isArray(subject)) ? Object.keys(subject) : [];
    incPath = incPath || keys.find((k) => /price_including_tax|price_inc|total_inc|gross/i.test(k));
    exPath = exPath || keys.find((k) => /price_excluding_tax|price_ex|total_ex|net/i.test(k));
  }
  if (incPath && exPath) {
    const inc = toMoney(getPath(subject, incPath).value);
    const ex = toMoney(getPath(subject, exPath).value);
    if (inc !== null && ex !== null && inc < ex) {
      add(f('invariant-vat', SEV.CRIT, `inc-VAT \`${incPath}\`=${inc} < ex-VAT \`${exPath}\`=${ex} — tax math inverted (consumer would show a price below net)`));
    }
  }

  // currency present when a price is present (a WC payload that drops `currency`/`priceCurrency`
  // leaves a headless cart unable to format/charge correctly).
  const hasAnyPrice = [...moneyPaths].some((p) => { const r = getPath(subject, p); return r.found && r.value !== null && r.value !== '' && toMoney(r.value) !== null; });
  const wantsCurrency = invariants.some((i) => /currency/i.test(i)) || declaredMoney.length > 0;
  if (hasAnyPrice && wantsCurrency) {
    const curKeys = ['currency', 'priceCurrency', 'currency_code', 'price_currency'];
    const curFromContract = invariants.find((i) => /currency:/i.test(i))?.split(':')[1]?.trim();
    const candidates = curFromContract ? [curFromContract, ...curKeys] : curKeys;
    const present = candidates.some((k) => { const r = getPath(subject, k); return r.found && typeof r.value === 'string' && r.value.trim() !== ''; });
    if (!present) add(f('invariant-currency', SEV.CRIT, `a price is present but no currency field (${candidates.slice(0, 4).join('/')}) is set — consumer can't format/charge`));
  }

  // slug/permalink non-empty (a headless route key going empty 404s the consumer's page).
  const slugPaths = new Set(declaredSlug);
  if (declaredSlug.length === 0 && subject && typeof subject === 'object' && !Array.isArray(subject)) {
    for (const k of Object.keys(subject)) if (/^slug$|(^|[._-])slug([._-]|$)|permalink/i.test(k)) slugPaths.add(k);
  }
  const wantsSlug = invariants.some((i) => /slug/i.test(i)) || declaredSlug.length > 0 || slugPaths.size > 0;
  if (wantsSlug) {
    for (const path of slugPaths) {
      const { found, value } = getPath(subject, path);
      if (!found) continue;
      if (typeof value !== 'string' || value.trim() === '') add(f('invariant-slug', SEV.CRIT, `slug/permalink field \`${path}\` is empty — breaks the consumer's route/permalink`));
    }
  }

  // encoding: NO double-encoded HTML entity in any string field (recursively). The WP REST
  // double-encode bug ships `&amp;amp;`/`&amp;#039;` that a headless renderer prints literally.
  const enc = [];
  walkStrings(subject, (s, path) => { if (isDoubleEncoded(s)) enc.push({ s, path }); });
  for (const e of enc.slice(0, 6)) {
    add(f('invariant-encoding', SEV.CRIT, `double-encoded entity in \`${e.path}\`: "${e.s.slice(0, 50)}" — consumer renders a literal &amp;`));
  }

  // declared invariant referenced a field absent from the payload (T1 — the contract drifted
  // from the API, or the API dropped the field; either way the invariant couldn't be evaluated).
  for (const inv of invariants) {
    const refs = (inv.match(/[A-Za-z_][\w.]*/g) || []).filter((w) => !/^(price|currency|slug|inc|ex|vat|positive)$/i.test(w) && !/^incVat|exVat$/.test(w));
    for (const r of refs) {
      // only check refs that look like a field path AND were named after a ':' (explicit field args)
      if (!inv.includes(':')) continue;
      const argPart = inv.split(':').slice(1).join(':');
      if (!argPart.includes(r)) continue;
      if (!getPath(subject, r).found) add(f('invariant-declared', SEV.WARN, `invariant "${inv}" references field \`${r}\` not present in the payload`));
    }
  }

  // ---- T1/T2 drift ----
  // optional fields that came back null (consumer should tolerate, but flag the drift)
  for (const path of (Array.isArray(contract.optional) ? contract.optional : [])) {
    const { found, value } = getPath(subject, path);
    if (found && value === null) add(f('optional-null', SEV.WARN, `optional field \`${path}\` is null`));
  }
  // unexpected new top-level fields (only when the contract enumerates an expected-field set
  // and didn't opt into allowExtra) — a backend that ADDS a field isn't a break, but it's drift
  // a consumer's strict schema might reject, so WARN.
  const expectFields = Array.isArray(contract.expectFields) ? contract.expectFields : null;
  if (expectFields && contract.allowExtra !== true && subject && typeof subject === 'object' && !Array.isArray(subject)) {
    const known = new Set([...expectFields, ...required, ...Object.keys(types), ...(contract.optional || []), ...declaredMoney, ...declaredSlug]);
    const extra = Object.keys(subject).filter((k) => !known.has(k));
    if (extra.length) add(f('unexpected-field', SEV.WARN, `payload has ${extra.length} field(s) not in the contract: ${extra.slice(0, 8).join(', ')}`));
  }

  return out;
}

// Recurse into a parsed JSON value, invoking cb(stringValue, dottedPath) on every string.
// Bounded depth + node budget so a pathological payload can't blow the stack / hang CI.
export function walkStrings(value, cb, path = '', depth = 0, budget = { n: 20000 }) {
  if (depth > 12 || budget.n <= 0) return;
  budget.n--;
  if (typeof value === 'string') { cb(value, path || '(root)'); return; }
  if (Array.isArray(value)) { for (let i = 0; i < value.length && budget.n > 0; i++) walkStrings(value[i], cb, `${path}[${i}]`, depth + 1, budget); return; }
  if (value && typeof value === 'object') { for (const k of Object.keys(value)) { if (budget.n <= 0) break; walkStrings(value[k], cb, path ? `${path}.${k}` : k, depth + 1, budget); } }
}
