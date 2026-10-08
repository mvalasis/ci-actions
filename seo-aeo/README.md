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
| **T1 — promotable WARN** | reports; a caller may elevate any of these to CRITICAL via `critical-checks` | `noindex`, `single-h1`, `canonical-present`, `canonical-valid`, `meta-description`, `html-lang`, `viewport`, `jsonld-valid`, `og-core`, `robots-txt`, `sitemap`, `robots-sitemap-directive`, `redirect-consistency`, `external-webfont`, and the agent-readiness four (v1.29.0): `agent-markdown`, `agent-skills-index`, `agent-ard`, `agent-content-signal` |
| **T2 — advisory WARN/INFO** | reports only, never promotable | length bounds, `charset`, `mixed-content`, `canonical-resolve`, `hreflang`/`hreflang-reciprocity`, `jsonld-type`/`jsonld-fields`/`jsonld-present` (Microdata/RDFa-aware), `entity-sameas`, `twitter-card`, `img-alt`, duplicate title/meta, `search-engine-blocked`, `ai-crawler-allowlist`, `search-verification`, `llms-txt`/`llms-structure`, `trailing-slash`, `soft-404`, `semantic-landmark`, `heading-hierarchy`, freshness, `jsonld-retired`, and agent readiness: `entity-fields`, `homepage-type-breadth`, `sitemap-lastmod`, `agent-link-headers`, `agent-webmcp`, `agent-markdown-404`, `agent-llms-guidance`, `agent-trust-pages` |

**`external-webfont` (v1.28.0)** flags, in the served JS-disabled HTML, any `<link>` (`rel` stylesheet / preload /
preconnect / dns-prefetch — the `media="print" onload=…` async loader is still a `rel=stylesheet` link) or inline
`<style>` `@import` / `url(…)` whose host is `fonts.googleapis.com`, `fonts.gstatic.com`, `use.typekit.net` or
`p.typekit.net` (a `<noscript>` copy counts: a visitor without JS loads it). The rule behind it is
HEADLESS-ASTRO §7d: webfonts are self-hosted, woff2 under the site's own origin, never an external font service —
each request hands the visitor's IP to a third party and puts a CSS→font chain on the critical path. One finding per
page: the reference count, the host(s), and up to 3 distinct URLs (sanitised like every page-controlled string).
Self-hosted `@font-face` and same-origin `/fonts/…` never fire. Default **WARN**, so a caller is never newly-blocked;
`critical-checks: external-webfont` makes it block once the caller's own pages are clean.

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

## Where to read the result — job log, annotations, step summary

Since **v1.18.0** the report is in three places, so "why did it block?" never needs a browser:

- **Job log** — the whole report, the same lines as the step summary, byte for byte:
  `gh run view <run-id> --log-failed` (or `--log`). Before v1.18.0 the log said only
  `Process completed with exit code 1`.
- **Annotations** — one per CRITICAL (a T0, or a T1 you promoted), at the end of the log:
  `::error title=seo-aeo <check>::<check> at <url>`, where `<url>` is the page, or the origin for a
  site-file check (`robots-txt`, `sitemap`, …). There is no `file=`: this gate grades live URLs, not
  files of your repo, so the location is in the message. `gh run view <run-id>` lists them under
  ANNOTATIONS; the API has them at `gh api repos/<owner>/<repo>/check-runs/<job-id>/annotations`. A
  report-only run (`fail-on-critical: false`) annotates at `::warning` instead. GitHub keeps 10 per
  step; past that, one log line counts the rest (the report lists every finding either way). A WARN or
  INFO finding is never annotated. A sitemap/URL list that resolves to nothing is the one CRITICAL
  without a check id; it annotates as `no-urls-resolved` (at the sitemap, when one was given).
- **Step summary** — unchanged: the same report, rendered.

Page text never reaches the start of a log line, where the runner would read it as a workflow
command: every page-controlled string (a title, a canonical, a `<loc>`, a fetch error) goes through
`safe()`, which strips CR/LF and the markdown and bracket characters (so neither `::…` nor the
legacy `##[…]` form can be spelled), and every report line starts with the gate's own text. An
annotation carries the check id and the URL (which may come from the site's own sitemap), never a
finding's message, and its values go through `safe()` and are escaped (`%`, CR, LF, and `:`/`,` in
properties). Off Actions (a local run) the report prints once to stdout, with no
annotations.

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

## Agent readiness (v1.29.0)

After the site files, each origin gets a `### Agent readiness` block: does a browsing agent (ChatGPT
agent, Gemini in Chrome, Claude in Chrome, Claude Code, Cursor) or an agent-readiness scanner find
what it looks for? Google Search ignores this layer: its AI-optimization guide says Markdown, extra
machine-readable files and special markup neither help nor hurt there. It serves agents. The entity
fields and the `Link:` header help classic SEO as well.

Three states, one contract:

- **absent → ℹ️ INFO.** Adopting a capability is a roadmap item, never a defect. INFO is never
  elevated, so promoting an id cannot block a site that has not adopted it.
- **present but broken → ⚠️ WARN.** An agent that finds it acts on a wrong answer: a digest that no
  longer matches its file, a catalog that is a soft-404, Markdown cached without `Vary: Accept`.
- **adopted →** listed on one `✅ in place:` line.

A leg that **could not look** (a 401/403/429 challenge, 408/425, a 5xx, a network error) is a ⚠️ WARN
under that leg's id, worded as "could not look … not a verdict about the site". It blocks only where
the caller promoted that id, because a promoted check never passes on a response it never got. Set
`verify-token` on a WAF-fronted origin.

| ID | Tier | What is fetched | ℹ️ absent | ⚠️ broken |
|---|---|---|---|---|
| `agent-markdown` | T1 | `/` with `Accept: text/markdown` | HTML or a non-2xx answer | `text/markdown` over an HTML or near-empty body; `Vary` without `Accept` |
| `agent-markdown-404` | T2 | a random nonexistent path, same `Accept` | an HTML 404 (graded once `/` negotiates) | a 2xx for a path that cannot exist (soft-404), adopted or not |
| `agent-content-signal` | T1 | robots.txt `Content-Signal:` lines | none declared | a key other than `search` / `ai-input` / `ai-train`, or a value other than `yes` / `no` |
| `agent-skills-index` | T1 | `/.well-known/agent-skills/index.json`, then each same-origin skill it lists (≤10, raw bytes) | 404 | soft-404, not JSON, not `application/json`, no agentskills.io `$schema`, an invalid entry, a listed skill that fails, a `SKILL.md` not served as `text/markdown`, a `digest` that is not the sha256 of the bytes served |
| `agent-ard` | T1 | `/.well-known/ard.json` and `/.well-known/ai-catalog.json` | neither (INFO too when only one name serves) | soft-404, not JSON, no entries, an entry whose `urn:air:<domain>:` identifier is malformed or names another domain, no `displayName`, no media `type`, not exactly one of `url` / `data` |
| `agent-link-headers` | T2 | `Link:` on `/` | none an agent follows: `sitemap`, `describedby`, a `text/markdown` alternate, `api-catalog`, `service-desc` / `service-doc`, `ard`, `ai-catalog` (WordPress's REST-discovery `api.w.org` link, `shortlink`, resource hints and a language alternate do not count) | — |
| `agent-webmcp` | T2 | `<form toolname>`, and `modelContext.registerTool` inline or in ≤6 same-origin bundles (`modulepreload` included) | no tool | — |
| `agent-llms-guidance` | T2 | an llms.txt `##` heading such as "When to use (for AI agents)" | none | — |
| `agent-trust-pages` | T2 | `/about`, `/contact`, `/privacy`, redirects followed (a page on another host counts as missing) | missing, or under 500 chars outside nav/header/footer | — |
| `sitemap-lastmod` | T2 | `<lastmod>` in the sitemap (of an index: its first child) | no entry dated | — |
| `entity-fields` | T2 | the homepage JSON-LD entity nodes (a field on any of them counts) | no address / contactPoint (never asked of a Person) | no `description` |
| `homepage-type-breadth` | T2 | the homepage JSON-LD types | only the entity and WebSite | — |

Every fetch stays on the checked origin, so the action stays air-gapped: about 25 extra GETs per
origin at most (`/` twice, ≤6 bundles, the 404 probe, the skills index and ≤10 skills, the two catalog
names, three trust pages, one child sitemap). A skill listed on another host is reported, never
fetched, so its digest is never claimed verified and the token never leaves the checked host. Once a
site has adopted one, lock it in:

```yaml
with:
  fail-on-critical: 'true'
  critical-checks: 'agent-markdown,agent-skills-index,agent-ard,agent-content-signal'
```

## Self-test

`node scripts/selftest.mjs` runs the engine against offline fixtures (no network) and asserts
each defect class — the regression guard. Its **end-to-end** leg runs the real `check.mjs` as a
process against a local `node:http` server (127.0.0.1 only) whose hostile page plants workflow
commands in `<html lang>` and a canonical. It asserts the job log carries the whole report byte for
byte, one annotation per CRITICAL (the promoted T1 included, none for a WARN), no planted command at
the start of a line, a local run printing once with no commands (stdout a socket, as node's
child_process gives it — the case that crashes an `appendFileSync('/dev/stdout')` fallback on Linux),
report-only annotating as `::warning`, an unwritable summary still reaching the log under the
caller's exit setting, and the two early exits that run before the first `await`. 21 targeted
mutants each turn it red. The agent-readiness layer (v1.29.0) adds offline cases per analyzer
(absent, broken and adopted, plus near-miss mutants), the tier contract (the four promotable ids; a
site that adopted none of them yields only INFO) and an end-to-end leg through the real `check.mjs`:
an adopting site is all ✅ with the four promoted, a broken one blocks on exactly those four (its 503
catalog reported as could-not-look), a site that adopted nothing never blocks, and the verify token
never leaves the checked host. 49 targeted mutants of that layer each turn it red. It runs in CI
(`.github/workflows/seo-aeo-selftest.yml`).

## Implementation

`scripts/checks.mjs` — pure, network-free check engine, plus the report's `safe()` and the
annotation encoding (all unit-tested by `selftest.mjs`).
`scripts/agent.mjs` — the agent-readiness analyzers, pure like `checks.mjs`; `check.mjs` fetches
each origin's agent-facing surface and feeds the responses in.
`scripts/check.mjs` — CLI: builds the URL list (sitemap expansion + retry), fetches JS-disabled
with one transient-retry + manual redirect probes, renders a per-page report to
`GITHUB_STEP_SUMMARY` and the job log, annotates each CRITICAL, exits non-zero only on a CRITICAL
under `fail-on-critical`. `cheerio` is the
sole dependency (lockfile-pinned, installed with `npm ci --ignore-scripts`).
