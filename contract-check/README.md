# contract-check

Validate that the **WP/WC REST JSON payloads a deployed consumer reads** still satisfy a
**committed contract** — so a backend change that silently drops a field, flips a type, zeroes a
price, inverts the VAT math, or double-encodes a name can't ship a broken/mis-priced page to a live
**Astro** or **React Native** frontend without CI catching it.

It fetches each endpoint as **raw JSON** (the consumer's-eye view — no JS, no browser) and checks
the payload against a manifest of required fields, type expectations, and money/encoding invariants.
**Air-gapped:** it only fetches the configured endpoints — no SaaS, no telemetry. **Zero runtime
dependencies** (Node 22 built-in `fetch` + `JSON.parse`; nothing to `npm ci`).

This is the **api-contract seam** guard for the headless splits in the fleet:
`cms.hlektrologos` → lampakia/ilektrologika, `cms.epn.one` → epn-astro, `prevedourou-wp` →
prevedourougr, lux WP → the RN app. Wire it in the **consumer** repo so the contract describes what
*that* frontend depends on.

## Severity model — tiny CRITICAL core, promotable WARN drift

Like the other gates behind `@v1`, CRITICAL is kept small, config-free, and always-a-real-break, so
a caller can run it enforcing without false blocks. Everything softer reports without blocking, and a
clean caller can ratchet individual checks up.

| Tier | Behaviour | Checks |
|---|---|---|
| **T0 — CRITICAL** | blocks when `fail-on-critical: true` | `http-2xx` (endpoint resolves to 2xx — a WAF 403/429/5xx/timeout is downgraded to infra-WARN, not a block), `json-parse` (body is valid JSON), `required-present` (a declared required field is missing/null), `required-type` (a declared required field changed JS type), `invariant-price` (a declared money field present but ≤ 0 / non-numeric), `invariant-vat` (inc-VAT < ex-VAT when both present), `invariant-currency` (a price present but no currency field), `invariant-slug` (a slug/permalink field present but empty), `invariant-encoding` (a string field carries a double-encoded entity, e.g. `&amp;amp;` / `&amp;#039;`) |
| **T1 — promotable WARN** | reports; a caller may elevate to CRITICAL via `critical-checks` | `invariant-declared` (an invariant referenced a field absent from the payload), `optional-null` (a declared optional field came back null), `unexpected-field` (a top-level field appeared that the contract didn't declare), `array-empty` (an endpoint declared `nonEmpty` returned `[]`) |

The number↔string flip is treated as a **serialization convention, not a break — only on money
fields** (WC ships prices as numeric strings: `"14.00"` vs `14`). An `id` declared `number` that
arrives as `"412"` is still a CRITICAL retype.

**Scope — this is a detector, not a generator.** It *flags* a contract break; it never *authors* the
fix — remediation lives in the backend (the WP/WC theme/plugin/filter) or the consumer's schema.
Deliberately **out of scope:** full JSON-Schema validation (this is a focused breakage/mis-pricing
floor, not Ajv), auth-flow correctness (→ the JWT debug skills), broken links (→ `linkcheck`), and
HTML SEO (→ `seo-aeo`).

## Use it

Wire it in the **consumer** repo (the Astro/RN frontend), pointing at the WP/WC backend it reads.

```yaml
# .github/workflows/contract-check.yml
name: contract-check
on:
  workflow_dispatch: {}
  pull_request: {}                       # catch a contract drift before the consumer ships
  schedule: [{ cron: '30 3 * * 1' }]     # …and on a cadence to catch a backend-side change
permissions: { contents: read }
jobs:
  contract:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6        # brings your committed contract manifest
      - uses: mvalasis/ci-actions/contract-check@v1
        with:
          manifest: contract/wp-rest.json
          fail-on-critical: 'false'      # report first; enforce once clean
          # verify-token: ${{ secrets.VERIFY_HOMEPAGE_TOKEN }}   # WAF/CF-fronted origins
          # critical-checks: 'unexpected-field'                  # opt-in stricter, per caller
```

Or, for a quick transport+encoding floor without a manifest, pass an inline `endpoints` map:

```yaml
      - uses: mvalasis/ci-actions/contract-check@v1
        with:
          endpoints: |
            {"products":"https://cms.example.gr/wp-json/wc/store/products?per_page=1",
             "posts":"https://cms.example.gr/wp-json/wp/v2/posts?per_page=1"}
```

## Inputs

| Input | Default | Notes |
|---|---|---|
| `endpoints` / `manifest` | `''` | JSON name→URL map (transport+encoding floors only) **and/or** a path to a committed contract file (full validation). At least one required. |
| `fail-on-critical` | `false` | `true` = BLOCK on any CRITICAL (missing/retyped required field, money/encoding invariant, or a promoted check). |
| `max-endpoints` | `25` | Cap; deduped by URL, sampled from the front of the list. |
| `verify-token` | `''` | Sent as `X-Verify-Source` (+ a benign `_lscache_vary` cookie) **only to the configured endpoint hosts** — clears a Cloudflare/LiteSpeed bot-challenge. Re-scoped per redirect hop so it never rides a cross-host redirect. |
| `critical-checks` | `''` | Comma/space list of **T1** check IDs to elevate to CRITICAL for **this** caller. Unknown/advisory IDs are reported and ignored. Empty = never newly-blocked. |

## The manifest

The contract lives in the **consumer** repo (so it tracks what *that* frontend relies on). One file,
an array of endpoint contracts:

```json
{
  "endpoints": [
    {
      "name": "wc-product",
      "url": "https://cms.example.gr/wp-json/wc/store/products/412",
      "required": ["id", "name", "slug", "price", "currency", "stock_status"],
      "types": { "id": "number", "name": "string", "slug": "string", "price": "string", "images": "array" },
      "money": ["price", "regular_price"],
      "slug": ["slug"],
      "invariants": ["price>0", "incVat>=exVat:price_including_tax,price_excluding_tax", "currency"],
      "optional": ["sale_price"],
      "nonEmpty": true,
      "expectFields": ["id", "name", "slug", "permalink", "price", "regular_price", "sale_price", "currency", "stock_status", "images"],
      "allowExtra": false
    }
  ]
}
```

| Key | Meaning |
|---|---|
| `url` | The endpoint to fetch (required). A list endpoint returning a top-level array is validated against its **first** item. |
| `name` | Friendly label in the report (defaults to the URL). |
| `required` | Fields that MUST be present and non-null — missing/null ⇒ `required-present` CRITICAL. Dotted/bracketed paths supported (`a.b`, `images[0].src`). |
| `types` | `path → JS type` (`string`/`number`/`boolean`/`object`/`array`). A wrong type ⇒ `required-type` CRITICAL (money fields exempt the number↔string flip). |
| `money` | Fields that must be a number `> 0` (and trigger the currency-present check). Omit to auto-detect price-shaped keys for the encoding/ordering floors only. |
| `slug` | Slug/permalink fields that must be a non-empty string. Auto-detected from `*slug*`/`permalink` keys if omitted. |
| `invariants` | Declarative checks: `price>0`, `currency` (or `currency:<field>`), `incVat>=exVat:<incField>,<exField>`. The inc/ex pair auto-detects WC's `price_including_tax`/`price_excluding_tax` if not pinned. |
| `optional` | Fields tolerated absent; a present-but-null value ⇒ `optional-null` WARN. |
| `nonEmpty` | The endpoint must return a non-empty collection; `[]`/`{}` ⇒ `array-empty` WARN. |
| `expectFields` + `allowExtra` | When `expectFields` is set and `allowExtra` is not `true`, a top-level field outside the union of declared keys ⇒ `unexpected-field` WARN (backend added a field). |

A runnable example lives at [`example-manifest.json`](example-manifest.json).

## Promoting checks per-caller (without forking)

`critical-checks` lets a caller that has proven a clean run ratchet up its own gate while the shared
default stays conservative — and lets a report-mode caller **rehearse** a strict posture (set
`critical-checks` with `fail-on-critical: false` to see what *would* block, at zero risk):

```yaml
with:
  fail-on-critical: 'true'
  critical-checks: 'unexpected-field,array-empty'
```

Only the T1 IDs above are promotable. The CRITICAL core (transport + required-present/type + the
money/encoding invariants) is always on and cannot be disabled.

## Self-test

`node scripts/selftest.mjs` runs the engine against **offline JSON fixtures** (no network) and
asserts each defect class — a good WC payload passes clean, and payloads with a missing required
field / wrong type / negative price / inverted VAT / missing currency / empty slug / double-encoded
name each trip the right CRITICAL. It's the regression guard, and it runs in CI
(`.github/workflows/contract-check-selftest.yml`).

## Implementation

`scripts/checks.mjs` — pure, network-free validation engine (unit-tested by `selftest.mjs`).
`scripts/check.mjs` — CLI: builds the endpoint list (inline map + manifest file), fetches each as
raw JSON with one transient-retry + manual redirect re-scoping of the token, runs the engine, renders
a per-endpoint report to `GITHUB_STEP_SUMMARY`, and exits non-zero only on a CRITICAL under
`fail-on-critical`. No runtime dependencies.
