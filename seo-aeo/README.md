# seo-aeo

Technical **SEO + AEO/GEO** audit of live URLs from a **JS-disabled (raw `fetch`) view** —
the crawler's-eye. The served HTML is parsed with a **real DOM parser (cheerio)**, not
regex, so the whole false-positive/false-negative class of the old grep gate (multiline
tags, commented-out `<title>`, `<template>` h1, unparsed JSON-LD, soft-404 `llms.txt`) is
gone. Suits server-rendered WP and prerendered Astro alike. **Air-gapped:** it only fetches
the target site — no SaaS, no telemetry.

## Severity model — tiny CRITICAL core, deep WARN coverage

This is a **shared gate** behind `@v1`; two callers (EPN, lampakia) run it **enforcing**
and block deploys on a CRITICAL. So CRITICAL is kept small, config-free, and locale-independent —
everything else reports without ever blocking, and a clean caller can opt individual checks up.

| Tier | Behaviour | Checks |
|---|---|---|
| **T0 — CRITICAL** | blocks when `fail-on-critical: true` | `http-200` (page resolves to a real 2xx — a WAF 403/429/timeout is downgraded to infra-WARN, not a block), `title-present`, `h1-present` |
| **T1 — promotable WARN** | reports; a caller may elevate any of these to CRITICAL via `critical-checks` | `noindex`, `single-h1`, `canonical-present`, `canonical-valid`, `meta-description`, `html-lang`, `viewport`, `jsonld-valid`, `og-core`, `robots-txt`, `sitemap`, `redirect-consistency` |
| **T2 — advisory WARN/INFO** | reports only, never promotable | length bounds, `charset`, `mixed-content`, `canonical-resolve`, `hreflang`/`hreflang-reciprocity`, `jsonld-type`/`jsonld-fields`/`jsonld-present` (Microdata/RDFa-aware), `entity-sameas`, `twitter-card`, `img-alt`, duplicate title/meta, `search-engine-blocked`, `ai-crawler-allowlist`, `search-verification`, `llms-txt`/`llms-structure`, `trailing-slash`, `soft-404`, `semantic-landmark`, `heading-hierarchy`, freshness, `jsonld-retired` |

**Scope — this is a detector, not a generator.** It *flags* a missing/poor meta description, an
absent sitemap, a noindex, a dead canonical; it never *authors* copy or *creates* a sitemap —
remediation lives in each site's own code (theme/Yoast filter, `@astrojs/sitemap`, etc.).
Deliberately **out of scope:** Core Web Vitals/INP (needs a real browser → `lighthouse-ci`),
broken-link crawling (→ `linkcheck`), full schema.org validation, and content *quality* (→ the
advisory `seo-critic`). Search-engine **ownership** verification (GSC/Bing) is reported as INFO when
a meta token is present but never required — DNS-TXT/HTML-file verification is equally valid; the
*indexability* signals that actually matter (200, noindex, canonical, robots, sitemap, AI-crawlers)
are all checked.

> **Intentional stricter-than-regex behavior.** Because the gate now parses a real DOM, a few
> things the old grep gate passed are now correctly caught at T0: a whitespace-only `<title>`,
> a `<title>` that lives in `<body>` instead of `<head>`, and an `<h1>` whose only content is an
> alt-less image or inline SVG (textless to a crawler) → these fire `title-present`/`h1-present`
> CRITICAL. They don't occur on EPN/lampakia today (every h1 carries real heading text), but a
> future redesign that swaps a heading for a logo image inside `<h1>` would be blocked under
> enforcement — that's the gate working as intended, not a regression.

The CRITICAL core is exactly what a competent build always passes on every site/CMS/locale; a
failure there is *always* a real defect. Length, canonical-target, hreflang, structured-data
shape, AI-crawler policy, etc. are real signals but site-/locale-/editorial-variable, so they
**surface as WARN** and never block a shared deploy.

## Use it

```yaml
# .github/workflows/seo-aeo.yml
name: seo-aeo
on:
  workflow_dispatch: {}
  schedule: [{ cron: '40 2 * * 1' }]   # pick your own off-peak slot
permissions: { contents: read }
jobs:
  seo:
    runs-on: ubuntu-latest
    steps:
      - uses: mvalasis/ci-actions/seo-aeo@v1
        with:
          sitemap-url: https://www.example.com/sitemap_index.xml
          # urls: |                       # …or an explicit list instead of a sitemap
          #   https://www.example.com/
          #   https://www.example.com/shop/
          fail-on-critical: 'false'        # report first; enforce once clean
          # verify-token: ${{ secrets.VERIFY_HOMEPAGE_TOKEN }}   # WAF/CF-fronted origins
          # critical-checks: 'noindex,canonical-valid'           # opt-in stricter, per caller
```

## Inputs

| Input | Default | Notes |
|---|---|---|
| `urls` / `sitemap-url` | `''` | Pages to check (one required). A sitemap **index** is expanded one level. |
| `fail-on-critical` | `false` | `true` = BLOCK on any CRITICAL (HTTP non-2xx, missing title/h1, or a promoted check). |
| `max-urls` | `15` | Cap; sampled from the front of the list/sitemap. Partial coverage is noted in the report. |
| `verify-token` | `''` | Sent as `X-Verify-Source` (+ a benign `_lscache_vary` cookie) **only to the checked host** — clears a Cloudflare/LiteSpeed bot-challenge. |
| `critical-checks` | `''` | Comma/space list of **T1** check IDs to elevate to CRITICAL for **this** caller. Advisory (T2) / unknown IDs are reported and ignored. Empty = never newly-blocked. |

## Promoting checks per-caller (without forking)

`critical-checks` lets a caller that has proven a clean run ratchet up its own gate while the
shared default stays conservative — and lets a report-mode caller **rehearse** a strict posture
(set `critical-checks` with `fail-on-critical: false` to see what *would* block, at zero risk):

```yaml
with:
  fail-on-critical: 'true'
  critical-checks: 'noindex,single-h1,canonical-valid,meta-description,html-lang,viewport'
```

Only the T1 IDs in the table above are promotable. The CRITICAL core (`http-200`, `title-present`,
`h1-present`) is always on and cannot be disabled.

## AEO / GEO

AEO/GEO is first-class here, not a footnote:

- **`llms.txt`** — checked for *structure* against the [llmstxt.org](https://llmstxt.org) grammar
  (opening `# H1`, blockquote summary, `##` link sections), not just an HTTP-200 (a soft-404 HTML
  page at `/llms.txt` is caught).
- **AI-crawler allow-list** — robots.txt is resolved per RFC 9309; **answer-engine** bots blocked at
  the root (`OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`, `Bingbot`, `Googlebot`) cost AEO
  visibility → WARN, while **training** crawlers (`GPTBot`, `*-Extended`, `CCBot`, …) are reported as
  INFO only — blocking them is a legitimate policy choice, never a defect.
- **Structured data** is *parsed* (`@graph`/array/object flattened, types collected, key fields
  per `@type` validated) — `FAQPage`/`HowTo` are reported as **INFO** (valid schema, but no rich
  result since 2026-05-07 — never claimed, never penalised).
- **Entity & freshness** — `sameAs`/Organization-Person on the homepage, `dateModified`/`datePublished`
  on article pages, `<main>`/`<article>` semantics.

Content *quality* (quotable answers, entity-chain depth, render proof) stays the advisory
[`seo-critic`](../README.md) subagent's job, not this gate.

## Self-test

`node scripts/selftest.mjs` runs the engine against offline fixtures (no network) and asserts
each defect class — the regression guard. It also runs in CI (`.github/workflows/selftest.yml`).

## Implementation

`scripts/checks.mjs` — pure, network-free check engine (unit-tested by `selftest.mjs`).
`scripts/check.mjs` — CLI: builds the URL list (sitemap expansion + retry), fetches JS-disabled
with one transient-retry + manual redirect probes, renders a per-page report to
`GITHUB_STEP_SUMMARY`, exits non-zero only on a CRITICAL under `fail-on-critical`. `cheerio` is the
sole dependency (lockfile-pinned, installed with `npm ci --ignore-scripts`).
