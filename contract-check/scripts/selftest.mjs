// Offline self-test for the contract-check engine. NO network — feeds saved JSON
// fixtures (parsed objects) to the pure analyzer and asserts the findings. Run locally
// or in CI (`node scripts/selftest.mjs`); exits non-zero on any regression.
import {
  SEV, T0_CHECKS, T1_CHECKS, analyzePayload, getPath, jsonType, toMoney, isDoubleEncoded,
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

console.log(`\n${failed === 0 ? '✅ all self-tests passed' : `❌ ${failed} self-test(s) FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
