// Offline self-test for the contract-check engine. NO network — feeds saved JSON
// fixtures (parsed objects) to the pure analyzer and asserts the findings; then runs the real
// check.mjs against a LOCAL node:http server (127.0.0.1 only) to assert what reaches the job
// log. Run locally or in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SEV, T0_CHECKS, T1_CHECKS, analyzePayload, getPath, jsonType, toMoney, isDoubleEncoded,
  safe, escapeData, escapeProperty, annotation, annotations,
} from './checks.mjs';

let failed = 0;
const ids = (fs) => fs.map((x) => x.id);
const sevOf = (fs, id) => fs.filter((x) => x.id === id).map((x) => x.sev);
function check(name, cond, detail = '') { if (cond) { console.log(`  ✅ ${name}`); } else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

// A realistic WC product payload (the shape a headless Astro/RN consumer destructures).
const GOOD_WC_PRODUCT = {
  id: 412,
  name: 'Warm White Fairy Lights — 10m',
  slug: 'warm-white-fairy-lights-10m',
  permalink: 'https://cms.example.gr/product/warm-white-fairy-lights-10m/',
  type: 'simple',
  status: 'publish',
  price: '14.00',
  regular_price: '18.00',
  sale_price: '14.00',
  price_excluding_tax: '11.29',
  price_including_tax: '14.00',
  currency: 'EUR',
  stock_status: 'instock',
  images: [{ id: 9, src: 'https://cms.example.gr/wp-content/uploads/lights.jpg', alt: 'Fairy lights' }],
};

// The committed contract for that endpoint.
const WC_CONTRACT = {
  required: ['id', 'name', 'slug', 'price', 'currency', 'stock_status'],
  types: { id: 'number', name: 'string', slug: 'string', price: 'string', currency: 'string', images: 'array' },
  money: ['price', 'regular_price'],
  slug: ['slug'],
  invariants: ['price>0', 'incVat>=exVat:price_including_tax,price_excluding_tax', 'currency'],
  optional: ['sale_price'],
};

const A = (json, contract = WC_CONTRACT, opts = {}) =>
  analyzePayload({ name: opts.name || 'wc-product', url: opts.url || 'https://cms.example.gr/wp-json/wc/store/products/412', status: opts.status ?? 200, json, parseError: opts.parseError, contract }).findings;

// deep-clone a fixture so mutating one case never bleeds into the next
const clone = (o) => JSON.parse(JSON.stringify(o));

console.log('\n# helpers');
check('jsonType distinguishes null/array/object/number/string', jsonType(null) === 'null' && jsonType([]) === 'array' && jsonType({}) === 'object' && jsonType(1) === 'number' && jsonType('x') === 'string');
check('getPath resolves a.b and a[0].b', getPath({ a: { b: 1 } }, 'a.b').value === 1 && getPath({ a: [{ b: 2 }] }, 'a[0].b').value === 2);
check('getPath present-null distinct from missing', getPath({ a: null }, 'a').found === true && getPath({}, 'a').found === false);
check('toMoney accepts numeric string, rejects empty/NaN', toMoney('14.00') === 14 && toMoney(12) === 12 && toMoney('') === null && toMoney('abc') === null);
check('isDoubleEncoded: &amp;amp; yes, single &amp; no', isDoubleEncoded('Q&amp;amp;A') && isDoubleEncoded('It&amp;#039;s') && !isDoubleEncoded('Tom &amp; Jerry') && !isDoubleEncoded('plain'));

console.log('\n# good payload passes clean');
{
  const fs = A(GOOD_WC_PRODUCT);
  const noisy = fs.filter((x) => x.sev !== SEV.OK);
  check('clean WC product → zero crit/warn', noisy.length === 0, `got: ${JSON.stringify(noisy.map((x) => x.id + ':' + x.sev + ':' + x.msg))}`);
  check('clean WC product → http-2xx OK present', sevOf(fs, 'http-2xx').includes(SEV.OK));
}
// list-endpoint shape: a top-level array is validated against its first item
{
  const fs = A([GOOD_WC_PRODUCT, GOOD_WC_PRODUCT], WC_CONTRACT);
  check('array payload → validates first item, clean', fs.filter((x) => x.sev !== SEV.OK).length === 0);
}

console.log('\n# CRITICAL: missing required field');
{
  const p = clone(GOOD_WC_PRODUCT); delete p.slug;
  check('missing required slug → required-present CRITICAL', sevOf(A(p), 'required-present').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.name = null;
  check('required field null → required-present CRITICAL', sevOf(A(p), 'required-present').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: required field TYPE changed');
{
  const p = clone(GOOD_WC_PRODUCT); p.id = '412'; // number -> string (a real consumer destructure break)
  check('id number→string → required-type CRITICAL', sevOf(A(p), 'required-type').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.images = {}; // array -> object (WC empty-collection flip)
  check('images array→object → required-type CRITICAL', sevOf(A(p), 'required-type').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.price = 14; // string→number money: serialization convention, NOT a break
  check('price string→number → NOT a type break (money serialization)', !sevOf(A(p), 'required-type').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: negative / zero price');
{
  const p = clone(GOOD_WC_PRODUCT); p.price = '-5.00';
  check('negative price → invariant-price CRITICAL', sevOf(A(p), 'invariant-price').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.regular_price = '0';
  check('declared money field = 0 → invariant-price CRITICAL', sevOf(A(p), 'invariant-price').includes(SEV.CRIT));
}
{
  // sale_price is NOT a declared money field here; 0 means "no sale" → must NOT fire
  const p = clone(GOOD_WC_PRODUCT); p.sale_price = '0';
  check('auto-detected sale_price=0 → NOT flagged (legit no-sale)', !sevOf(A(p), 'invariant-price').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: inc-VAT < ex-VAT');
{
  const p = clone(GOOD_WC_PRODUCT); p.price_including_tax = '10.00'; p.price_excluding_tax = '11.29';
  check('inc-VAT < ex-VAT → invariant-vat CRITICAL', sevOf(A(p), 'invariant-vat').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.price_including_tax = '14.00'; p.price_excluding_tax = '14.00';
  check('inc-VAT == ex-VAT (tax-free) → NOT flagged', !sevOf(A(p), 'invariant-vat').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: currency missing while priced');
{
  const p = clone(GOOD_WC_PRODUCT); delete p.currency;
  const fs = A(p);
  // currency is also a required field here → required-present fires; AND the invariant fires
  check('missing currency → invariant-currency CRITICAL', sevOf(fs, 'invariant-currency').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: empty slug');
{
  const p = clone(GOOD_WC_PRODUCT); p.slug = '';
  const fs = A(p);
  check('empty slug → invariant-slug CRITICAL', sevOf(fs, 'invariant-slug').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: double-encoded entity in a string field');
{
  const p = clone(GOOD_WC_PRODUCT); p.name = 'Q&amp;amp;A Lights';
  check('double-encoded name → invariant-encoding CRITICAL', sevOf(A(p), 'invariant-encoding').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.name = "It&amp;#039;s Bright"; // numeric-entity double encode, nested in an array too
  check('double-encoded numeric entity → invariant-encoding CRITICAL', sevOf(A(p), 'invariant-encoding').includes(SEV.CRIT));
}
{
  const p = clone(GOOD_WC_PRODUCT); p.name = 'Tom &amp; Jerry Lights'; // single, CORRECT encoding
  check('single &amp; (correct) → NOT flagged', !sevOf(A(p), 'invariant-encoding').includes(SEV.CRIT));
}
{
  // double-encode buried deep in a nested array of objects must still be caught
  const p = clone(GOOD_WC_PRODUCT); p.images[0].alt = 'Bath &amp;amp; Body';
  check('double-encode in nested images[0].alt → CRITICAL', sevOf(A(p), 'invariant-encoding').includes(SEV.CRIT));
}

console.log('\n# CRITICAL: transport / parse');
{
  const fs = A(null, WC_CONTRACT, { parseError: 'Unexpected token < in JSON' });
  check('non-JSON body (HTML error page) → json-parse CRITICAL', sevOf(fs, 'json-parse').includes(SEV.CRIT));
}
{
  const fs = A({ code: 'rest_no_route' }, WC_CONTRACT, { status: 404 });
  check('HTTP 404 → http-2xx CRITICAL, short-circuits (no field grading)', sevOf(fs, 'http-2xx').includes(SEV.CRIT) && !ids(fs).includes('required-present'));
}

console.log('\n# minimal contract (endpoints-map mode): encoding/transport floors still apply');
{
  // no manifest contract at all — just the raw payload. A double-encode must still trip.
  const fs = analyzePayload({ name: 'x', url: 'https://e/wp-json/wp/v2/posts', status: 200, json: { title: { rendered: 'A&amp;amp;B' }, slug: 'a-b' }, contract: {} }).findings;
  check('no-contract payload: double-encode still CRITICAL', sevOf(fs, 'invariant-encoding').includes(SEV.CRIT));
  check('no-contract payload: empty-slug auto-detect still CRITICAL', sevOf(analyzePayload({ name: 'x', url: 'u', status: 200, json: { slug: '' }, contract: {} }).findings, 'invariant-slug').includes(SEV.CRIT));
}

console.log('\n# requiredNullable — the present-but-may-be-null tier');
{
  // Modelled on lampakia's hlek/v1: the producer ALWAYS sends these keys and null is their normal
  // state (no sale / unmanaged stock / no image), while the consumer's Zod declares them
  // `z.number().nullable()` — nullable but NOT optional, so an absent KEY fails its parse.
  // Deliberately non-money field names: a price-shaped name would earn the number↔string
  // exemption and mask the retype case below.
  const NULLABLE_PRODUCT = { id: 7, slug: 'lamp', name: 'Lamp', sale_cents: 1005, stock_qty: null, image: null };
  const NULLABLE_CONTRACT = {
    required: ['id', 'slug', 'name'],
    requiredNullable: ['sale_cents', 'stock_qty', 'image'],
    types: { id: 'number', slug: 'string', name: 'string', sale_cents: 'number', stock_qty: 'number', image: 'string' },
  };
  const N = (json, contract = NULLABLE_CONTRACT) => A(json, contract);

  // 1. present-and-null is the HEALTHY case — the whole reason the tier exists.
  {
    const fs = N(clone(NULLABLE_PRODUCT));
    const noisy = fs.filter((x) => x.sev !== SEV.OK);
    check('two of three nullable fields null → zero crit/warn (silent on null)', noisy.length === 0,
      `got: ${JSON.stringify(noisy.map((x) => x.id + ':' + x.sev + ':' + x.msg))}`);
  }
  // 2. an absent KEY is the break — same severity as required-present, because the consumer's
  //    `z.number().nullable()` rejects `undefined` exactly as it rejects a missing required field.
  {
    const p = clone(NULLABLE_PRODUCT); delete p.sale_cents;
    const fs = N(p);
    const miss = fs.find((x) => x.id === 'required-present' && x.sev === SEV.CRIT);
    check('requiredNullable key ABSENT → required-present CRITICAL', !!miss);
    check('  …and its id is in the T0 blocking core', !!miss && T0_CHECKS.has(miss.id));
    check('  …and the message names the nullable tier, not plain required',
      !!miss && /required-nullable/.test(miss.msg), `got: ${miss && miss.msg}`);
  }
  // 3. a non-null value is still type-graded — the tier relaxes NULLABILITY, never the type.
  {
    const p = clone(NULLABLE_PRODUCT); p.sale_cents = '1005'; // number → string on a NON-money field
    check('requiredNullable present with wrong non-null type → required-type CRITICAL', sevOf(N(p), 'required-type').includes(SEV.CRIT));
  }
  {
    const p = clone(NULLABLE_PRODUCT); p.image = 42; // string → number
    check('requiredNullable string→number → required-type CRITICAL', sevOf(N(p), 'required-type').includes(SEV.CRIT));
  }
  // 4. the noise-suppression property: null must NOT produce optional-null even when a manifest
  //    names the path in BOTH tiers. This is what makes the tier usable weekly.
  {
    const contract = { ...NULLABLE_CONTRACT, optional: ['stock_qty', 'image'] };
    check('path in requiredNullable AND optional → null does NOT fire optional-null', !sevOf(N(clone(NULLABLE_PRODUCT), contract), 'optional-null').includes(SEV.WARN));
  }
  // 5. `required` is strictly stronger and wins when a manifest contradicts itself by naming a
  //    path in both tiers — no downgrade of null, and ONE finding per defect.
  {
    const contract = { ...NULLABLE_CONTRACT, required: [...NULLABLE_CONTRACT.required, 'stock_qty'] };
    const fs = N(clone(NULLABLE_PRODUCT), contract); // stock_qty present-but-null
    check('path in BOTH required and requiredNullable → null still CRITICAL (required wins, no downgrade)', sevOf(fs, 'required-present').includes(SEV.CRIT));
  }
  {
    // The ABSENT case is what actually exercises the de-dup guard: null short-circuits the
    // nullable loop on its own, so only a missing key can produce two findings for one defect.
    const contract = { ...NULLABLE_CONTRACT, required: [...NULLABLE_CONTRACT.required, 'stock_qty'] };
    const p = clone(NULLABLE_PRODUCT); delete p.stock_qty;
    const fs = N(p, contract);
    check('path in BOTH tiers and ABSENT → exactly one required-present finding (no double-report)',
      fs.filter((x) => x.id === 'required-present').length === 1,
      `got: ${JSON.stringify(fs.filter((x) => x.id === 'required-present').map((x) => x.msg))}`);
  }
  // 6. a field declared ONLY as requiredNullable is a KNOWN field for the expectFields sweep.
  {
    const contract = { ...NULLABLE_CONTRACT, types: { id: 'number' }, expectFields: ['id', 'slug', 'name'], allowExtra: false };
    check('requiredNullable field is not reported as an unexpected-field', !sevOf(N(clone(NULLABLE_PRODUCT), contract), 'unexpected-field').includes(SEV.WARN));
  }
  // 7. ADDITIVE-SAFETY: the tier is inert for every manifest that doesn't use it. This is what
  //    lets the key ship as a v1 tag move across all callers instead of a v2 break.
  {
    const before = A(clone(GOOD_WC_PRODUCT), WC_CONTRACT);
    const after = A(clone(GOOD_WC_PRODUCT), { ...WC_CONTRACT, requiredNullable: [] });
    check('a manifest WITHOUT requiredNullable is graded identically (additive, not breaking)',
      JSON.stringify(before) === JSON.stringify(after));
    const p = clone(GOOD_WC_PRODUCT); delete p.sale_price; // optional, absent — still tolerated
    check('  …and an absent OPTIONAL field is still tolerated (no new block)', !sevOf(A(p), 'required-present').includes(SEV.CRIT));
  }
}

console.log('\n# T1 drift (WARN by default, promotable)');
{
  const p = clone(GOOD_WC_PRODUCT); p.sale_price = null;
  check('optional field null → optional-null WARN', sevOf(A(p), 'optional-null').includes(SEV.WARN));
}
{
  const contract = { ...WC_CONTRACT, expectFields: Object.keys(GOOD_WC_PRODUCT), allowExtra: false };
  const p = clone(GOOD_WC_PRODUCT); p.new_backend_field = 'surprise';
  check('unexpected new top-level field → unexpected-field WARN', sevOf(A(p, contract), 'unexpected-field').includes(SEV.WARN));
}
{
  const contract = { ...WC_CONTRACT, nonEmpty: true };
  check('nonEmpty endpoint returns [] → array-empty WARN', sevOf(analyzePayload({ name: 'x', url: 'u', status: 200, json: [], contract }).findings, 'array-empty').includes(SEV.WARN));
}

console.log('\n# promotion: a T1 WARN elevated to CRITICAL is honored by the engine consumer');
{
  // the engine emits WARN; the CLI's elevate() does the promotion. Assert the WARN id is in T1.
  check('unexpected-field is promotable (T1)', T1_CHECKS.has('unexpected-field'));
  check('invariant-encoding is NOT promotable (already T0 CRITICAL)', !T1_CHECKS.has('invariant-encoding') && T0_CHECKS.has('invariant-encoding'));
}

console.log('\n# severity-tier contract');
check('T0 core contains the money/encoding invariants + required present/type',
  ['required-present', 'required-type', 'invariant-price', 'invariant-vat', 'invariant-currency', 'invariant-slug', 'invariant-encoding'].every((c) => T0_CHECKS.has(c)));
check('promotable T1 set excludes every T0 id', ![...T0_CHECKS].some((c) => T1_CHECKS.has(c)));

console.log('\n# report + annotation encoding (pure)');
{
  check('safe() strips CR/LF and markdown-structural chars, caps length', safe('a\r\n`|<b>[c]', 5) === 'a bc' && safe('x'.repeat(300)).length === 220, JSON.stringify(safe('a\r\n`|<b>[c]', 5)));
  check('escapeData encodes % CR LF', escapeData('a%b\r\nc') === 'a%25b%0D%0Ac');
  check('escapeProperty also encodes : and ,', escapeProperty('a:b,c%') === 'a%3Ab%2Cc%25');
  const x = { id: 'required-present', sev: SEV.CRIT, msg: 'required field `price` is MISSING', where: 'products (https://cms.example.gr/wp-json/wc/store/products)' };
  check('annotation = title + `<check> at <endpoint>`, no file=/line= (an endpoint is not a repo file)', annotation(x) === '::error title=contract-check required-present::required-present at products (https://cms.example.gr/wp-json/wc/store/products)', annotation(x));
  check('annotation never carries msg (payload values stay in the report)', !annotation(x).includes('MISSING'));
  check("annotation level is the caller's", annotation(x, 'warning').startsWith('::warning title=contract-check required-present::'));
  check('no location → just the check id', annotation({ id: 'no-endpoints-resolved', sev: SEV.CRIT, where: '' }) === '::error title=contract-check no-endpoints-resolved::no-endpoints-resolved');
  // A hostile location stays ONE command: a line break would start a second one (stop-commands),
  // a raw % would be unescaped by the runner, and [ ] would let the legacy `##[cmd]` form in.
  const evil = annotation({ ...x, where: 'p%0A\n::stop-commands::tok\r##[error]x' });
  check('a hostile location stays ONE line', !/[\r\n]/.test(evil), JSON.stringify(evil));
  check('a hostile location cannot add a property (title is the only one)', /^::error title=contract-check required-present::/.test(evil) && evil.split('::').length === 5, JSON.stringify(evil));
  check('…its % is escaped and its brackets are gone', evil.includes('p%250A') && !evil.includes('##['), JSON.stringify(evil));
  const many = Array.from({ length: 12 }, (_, i) => ({ ...x, where: `ep-${i}` }));
  const warnOnly = { id: 'optional-null', sev: SEV.WARN, msg: 'm', where: 'w' };
  const out = annotations([...many, warnOnly]);
  check("annotations: 10 CRITICALs (GitHub's per-step cap) + one overflow line", out.length === 11 && out.slice(0, 10).every((l) => l.startsWith('::error ')) && /^contract-check: 2 more critical/.test(out[10]), `got ${out.length}`);
  check('annotations: a WARN finding is never annotated', !out.some((l) => l.includes('optional-null')) && annotations([warnOnly]).length === 0);
}

console.log('\n# check.mjs end to end — the job log carries the report; CRITICALs annotate');
{
  // check.mjs runs a top-level IIFE, so it is exercised as a PROCESS against a local server. The
  // broken payload plants workflow commands where only check.mjs's safe() stands between them and
  // the start of a log line: the invariant-encoding message quotes the raw value, unexpected-field
  // lists the raw key, and V8's JSON.parse error quotes the raw body — newlines included.
  const broken = clone(GOOD_WC_PRODUCT);
  delete broken.price;                                                  // required-present CRITICAL
  broken.name = 'Lamp &amp;amp;\n::error title=forged::pwned-name';     // invariant-encoding CRITICAL
  broken['x\n::warning::pwned-key'] = 1;                                // unexpected-field (T1 WARN)
  const server = createServer((req, res) => {
    const send = (status, type, body) => { res.writeHead(status, { 'content-type': type }); res.end(body); };
    if (req.url === '/wp-json/good') return send(200, 'application/json', JSON.stringify([GOOD_WC_PRODUCT]));
    if (req.url === '/wp-json/broken') return send(200, 'application/json', JSON.stringify(broken));
    if (req.url === '/wp-json/html') return send(200, 'text/html', 'x\n::echo::on\n::error::pwned-body');
    return send(404, 'application/json', '{"code":"rest_no_route"}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const BASE = `http://127.0.0.1:${server.address().port}`;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-e2e-'));
  const summaryPath = path.join(tmp, 'summary.md');
  const manifest = path.join(tmp, 'contract.json');
  fs.writeFileSync(manifest, JSON.stringify({ endpoints: [
    { name: 'products', url: `${BASE}/wp-json/broken`, ...WC_CONTRACT, expectFields: Object.keys(GOOD_WC_PRODUCT), allowExtra: false },
    { name: 'catalog', url: `${BASE}/wp-json/good`, ...WC_CONTRACT },
    { url: `${BASE}/wp-json/html` },
  ] }));
  // MUST be async (spawn, not spawnSync): the fixture server lives in THIS process. The env is built
  // from scratch so a CI runner's own GITHUB_ACTIONS / GITHUB_STEP_SUMMARY never leak into a case.
  const run = (extra) => new Promise((resolve) => {
    try { fs.rmSync(summaryPath, { force: true }); } catch { /* fresh file per run */ }
    const child = spawn(process.execPath, [fileURLToPath(new URL('./check.mjs', import.meta.url))], {
      env: { PATH: process.env.PATH, HOME: tmp, TMPDIR: tmp, ...extra }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (status) => {
      clearTimeout(killer);
      const summary = fs.existsSync(summaryPath) && fs.statSync(summaryPath).isFile() ? fs.readFileSync(summaryPath, 'utf8') : '';
      resolve({ status, stdout, stderr, summary });
    });
  });
  // A line the runner would read as a command: `::` after leading whitespace, or `##[` anywhere.
  const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l) || l.includes('##['));
  const why = (r) => `exit ${r.status}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
  const HEADER = '## 🔌 contract-check';
  const once = (r) => r.stdout.split(HEADER).length === 2 && !r.stdout.includes('crashed');
  const expected = (level, promoted) => [
    `::${level} title=contract-check required-present::required-present at products (${BASE}/wp-json/broken)`,
    `::${level} title=contract-check invariant-encoding::invariant-encoding at products (${BASE}/wp-json/broken)`,
    ...(promoted ? [`::${level} title=contract-check unexpected-field::unexpected-field at products (${BASE}/wp-json/broken)`] : []),
    `::${level} title=contract-check json-parse::json-parse at ${BASE}/wp-json/html`,
  ];
  try {
    // (A) On Actions, enforcing, one T1 promoted: summary + job log + one ::error per CRITICAL.
    const a = await run({ MANIFEST: manifest, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: 'unexpected-field' });
    check('Actions run: three T0 + one promoted T1 BLOCK (exit 1)', a.status === 1, why(a));
    check('the step summary is the report, verdict included', a.summary.startsWith(HEADER) && a.summary.includes('\nBLOCKED — 4 critical contract break(s).'), JSON.stringify(a.summary.slice(-160)));
    check('the job log carries the WHOLE report, byte for byte', a.summary.length > 0 && a.stdout.includes(a.summary));
    check('the report reaches the log once, not twice', once(a), why(a));
    // (V8 quotes only the body's first 10 characters in a JSON.parse error — newline included.)
    check('the fixtures reached the report, all three planted values flattened onto their line',
      a.stdout.includes('Lamp &amp;amp; ::error title=forged::pwned-name') && a.stdout.includes('x ::warning::pwned-key') && a.stdout.includes('"x ::echo::"'), why(a));
    check('one ::error per CRITICAL (the promoted T1 included), none for the clean endpoint, nothing else command-shaped',
      JSON.stringify(commands(a.stdout)) === JSON.stringify(expected('error', true)), JSON.stringify(commands(a.stdout)));
    check('annotations stay out of the step summary', commands(a.summary).length === 0);

    // (B) Off Actions: stdout is the only output — the report prints once, with no commands. spawn
    // hands the child a SOCKET as stdout: the case that crashes an `appendFileSync('/dev/stdout')`
    // fallback on Linux (ENXIO) with nothing printed and an exit code that still looks like a verdict.
    for (const [label, extra] of [['local run', {}], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', { GITHUB_STEP_SUMMARY: '/dev/stdout' }]]) {
      const b = await run({ MANIFEST: manifest, FAIL_ON_CRITICAL: 'true', CRITICAL_CHECKS: 'unexpected-field', ...extra });
      check(`${label}: the report prints exactly once, verdict included, no crash`, b.status === 1 && once(b) && b.stdout.includes('\nBLOCKED — 4 critical contract break(s).'), why(b));
      check(`${label}: no workflow commands`, b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
    }

    // (C) report-only: the T0s annotate as ::warning, the (unpromoted) WARN not at all, exit 0.
    const c = await run({ MANIFEST: manifest, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('report-only: exit 0', c.status === 0, why(c));
    check('report-only: the criticals annotate as ::warning, a WARN never', JSON.stringify(commands(c.stdout)) === JSON.stringify(expected('warning', false)), JSON.stringify(commands(c.stdout)));
    check('report-only: the log still carries the whole report', c.summary.length > 0 && c.stdout.includes(c.summary) && c.summary.includes('report-only — 3 critical contract break(s) would BLOCK'));

    // (D) The summary sink itself fails: the report is already in the log (it is echoed first), the
    // fault is named there, and the exit is the caller's setting — our fault never blocks report-only.
    const sinkDir = path.join(tmp, 'summary-is-a-dir');
    fs.mkdirSync(sinkDir);
    const d = await run({ MANIFEST: manifest, GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('unwritable summary: the report still reaches the job log', d.stdout.includes(HEADER) && d.stdout.includes('report-only — 3 critical contract break(s) would BLOCK'), why(d));
    check('unwritable summary: the fault is named in the log', /contract-check crashed: .*EISDIR/.test(d.stdout), why(d));
    check('unwritable summary: the crash note is ONE line (no stack frame starts a log line)', !/^\s+at /m.test(d.stdout), why(d));
    check('unwritable summary: the crash re-flush echoes only the new line, not the report again', d.stdout.split(HEADER).length === 2);
    check('unwritable summary under report-only: exit 0, not an unhandled throw', d.status === 0, why(d));

    // (E) The early exits run before check.mjs's first await, i.e. while the module is still
    // evaluating, so anything they touch must already be initialized (no TDZ crash).
    const e = await run({});
    check('no input: skipped, exit 0, printed once, no crash', e.status === 0 && once(e) && e.stdout.includes('nothing to check (skipped)'), why(e));
    const f = await run({ MANIFEST: path.join(tmp, 'no-such-contract.json'), GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'true' });
    check('an unreadable manifest: BLOCKED — bad config (exit 1), printed once, no crash', f.status === 1 && once(f) && f.stdout.includes('BLOCKED — bad config.'), why(f));
    check('…annotated as the one CRITICAL it counts, at the manifest', JSON.stringify(commands(f.stdout)) === JSON.stringify([`::error title=contract-check config-error::config-error at manifest ${path.join(tmp, 'no-such-contract.json')}`]), JSON.stringify(commands(f.stdout)));
    const g = await run({ ENDPOINTS: '{}', GITHUB_ACTIONS: 'true', FAIL_ON_CRITICAL: 'false' });
    check('an empty endpoints map: report-only exit 0, annotated as ::warning', g.status === 0
      && JSON.stringify(commands(g.stdout)) === JSON.stringify(['::warning title=contract-check no-endpoints-resolved::no-endpoints-resolved']), `${why(g)} ${JSON.stringify(commands(g.stdout))}`);
  } finally {
    server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
