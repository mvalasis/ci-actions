# `verify-homepage` — structure + cross-viewport render gate

Renders each live page in **headless Chromium across a viewport matrix** and
BLOCKS on broken layout, plus a **nav-inventory assert**. This is the mechanical
half of the UI/UX discipline (`~/.claude/DISCIPLINES.md` → UI/UX): structure &
render are gateable; visual *taste* stays advisory (the `design-critic`
subagent). It closes the gap that let EPN ship a silently reordered/relabelled
menu and responsive breakage until they were caught by eye across four devices
(2026-06-29).

## What it checks

- **render** (per viewport) — for every URL × every viewport:
  - **horizontal overflow** — `scrollWidth − clientWidth > overflow-tolerance`
    (the canonical "page scrolls sideways / content cut off" test). Off-canvas
    drawers (fixed/absolute, `[inert]` / `aria-hidden`) are excluded so a slid-out
    mobile menu isn't a false positive.
  - **collapsed landmark** — a declared landmark selector present but 0-height.
  - **landmark overlap** — two **in-flow** landmarks (position `static`/`relative`)
    whose boxes intersect in both axes > `overlap-tolerance`. Fixed/sticky/absolute
    landmarks are excluded (a fixed header legitimately overlays `main`).
  - Both landmark findings **identify the element they resolved to** — see
    [Ambiguous landmark selectors](#ambiguous-landmark-selectors-report-only) below.
- **nav** (once per URL) — collect `textContent`+`href` of every `<a>` matched by
  the repo's `nav_selector` (read regardless of visibility, so it works at any
  breakpoint) and compare to the declared `items` — **count, order, label, href**.
  Catches a silently wrong / missing / reordered menu.
- **links** (optional) — the curl link-crawl (T1 tier). This action carries the
  **one canonical copy** (`scripts/link-crawl.sh`) of the per-repo
  `verify-homepage-t1.sh` (ci-actions roadmap: fold the duplicates here).

`render`+`nav` need a browser; `links` is pure curl. The browser matrix is the
costly part — **run it on the weekly schedule + at cutover, not per-push.**

## Use it (weekly + manual)

```yaml
name: Structure + cross-viewport render
on:
  schedule: [{ cron: '20 4 * * 1' }]   # weekly, off-peak; stagger vs siblings
  workflow_dispatch: {}                 # cutover / on-demand re-run
concurrency: { group: verify-render, cancel-in-progress: true }
permissions: { contents: read }
jobs:
  render:
    runs-on: ubuntu-24.04
    timeout-minutes: 12
    steps:
      - uses: actions/checkout@v6      # brings scripts/verify-nav.json
      - uses: mvalasis/ci-actions/verify-homepage@v1
        with:
          urls: |
            https://www.example.com/
            https://www.example.com/about/
          verify-token: ${{ secrets.VERIFY_HOMEPAGE_TOKEN }}
```

## Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `urls` | yes | — | Live URLs (production at cutover — **never a preview host**). |
| `nav-file` | no | `scripts/verify-nav.json` | Nav inventory + landmarks, read from your checkout. Missing = nav skipped (render still runs). |
| `viewports` | no | `desktop:1920x1080,laptop:1440x900,iphone:393x852,android:384x854` | `[name:]WxH`; width ≤600 emulates mobile. |
| `checks` | no | `render,nav` | Any of `render`, `nav`, `links`. |
| `fail-on-structure` | no | `true` | `true` = BLOCK; `false` = report-only (WARN). |
| `max-urls` | no | `12` | Cap the rendered URL count. |
| `verify-token` | no | `''` | `X-Verify-Source`, sent **only** to the target host (+ www/apex). |
| `wait-ms` | no | `1200` | Settle time after load+networkidle. |
| `overflow-tolerance` | no | `2` | Horizontal-overflow slack (px). |
| `overlap-tolerance` | no | `4` | Landmark-overlap slack (px). |

## `verify-nav.json` (per repo)

A tiny committed inventory — the menu is **intentional and declared in code**, so
drift (someone reorders/renames the WP menu, or edits the Astro `Header` nav
array) fails CI. Keep it in sync when the menu genuinely changes.

```json
{
  "nav_selector": "header nav[aria-label='Primary navigation'] a.epn-nav-link",
  "match": "exact-order",
  "items": [
    { "label": "Home", "href": "/" },
    { "label": "About", "href": "/about/" },
    { "label": "Articles", "href": "/blog/" }
  ],
  "landmarks": ["header.epn-header", "main", "footer"]
}
```

- `nav_selector` — must return EXACTLY the top-level nav `<a>` in order. Pick the
  canonical desktop list (read via `textContent`, so a `display:none`-at-mobile
  container is fine).
- `items` — `label` is whitespace-normalized; `href` compares by **path**
  (trailing slash / absolute-vs-relative tolerated).
- `landmarks` — selectors that must render with non-zero height on every page
  (default `["header","main","footer"]` if omitted). Read whenever the file
  exists, **independently of `checks`** — `checks: render` alone still honours
  your `landmarks` (before v1.8.0 it silently fell back to the defaults).

## Ambiguous landmark selectors (report-only)

Landmarks resolve with `document.querySelector` — **first match in document order
wins**. An unscoped selector therefore measures whatever comes first, which is not
always the landmark:

| shape | what `footer` resolves to |
|---|---|
| a mobile drawer whose chrome uses `<header>`/`<footer>`, placed before the real ones | the drawer's footer |
| `<blockquote><footer>— Author</footer></blockquote>` (the spec's citation pattern) | the citation |
| a rotating list that hides all but one item | a footer inside a `display:none` `<li>` |

Two things make that hard to see. The verdict named only the *selector*, and a
descendant of a `display:none` subtree keeps its **own** computed `display`
(`block`) while its rect collapses to `0×0` — so it trips the collapse test while
the element actually at fault is an ancestor nobody mentioned.

Since **v1.8.0** every landmark finding carries the resolution:

```
collapsed landmark footer (0-height) — resolved to ‹footer class="drawer-foot"›,
whose ancestor ‹aside id="mobile-menu"› is display:none — that ancestor is the
cause, not this element; 2 elements match "footer" (first match in document order
wins) — match 2 of 2 ‹footer class="site"› renders 120px tall
```

- Identifiers render as `‹tag id="…" class="…"›`, **not** `<tag …>`: page-derived
  text is stripped of `<`, `>` and `#` before it reaches the markdown summary (it
  must not be able to inject HTML), and entity-escaping would leave `&lt;` litter
  in the job-log mirror. Ordinals read `match 2 of 2` for the same reason.
- **Overlap gets the same treatment**, and needs it more: there, an ambiguous
  selector produces a *false FAIL*. `main ∩ footer` reads as broken layout when
  the truth is that `footer` resolved to a citation nested inside `main`, so of
  course the boxes intersect. Only the ambiguous side is annotated — two clean
  selectors that really do overlap keep the terse message.
- A run that saw an ambiguous or mis-nested resolution prints one **advisory
  block before the verdict, on PASS as well as FAIL** — a selector quietly
  measuring the wrong element is a latent false verdict in both directions, and a
  green run is when nobody goes looking. It never changes the verdict or the exit
  code.

### Selector precision vs. catching markup regressions

There is a real trade-off here, and it is worth knowing which side you are on.

lampakia shipped a drawer-chrome `<footer>` that the unscoped default flagged for
a month (2026-07-01 → 07-30). Its own **ENFORCING** gate never saw it, because
`verify-nav.json` scopes landmarks to `["body > header","main#main","body >
footer"]` — which is *correct*: `body > footer` names the real footer. Precision
bought a silent green; only the ci-actions self-test (no nav file → the loose
default) was looking at the shadowed element.

The tempting fix — assert the loose defaults too — does not hold up. Measured
2026-07-30 against the live fleet with default landmarks: homepages pass clean,
but on archive pages `header` already matches **two** elements on two of three
sites (epn `epn-archive-header`, lampakia a page-title `header.mb-8`). The first
match happens to be the site header today, so it passes; it is one markup reorder
away from asserting geometry on a page-title block. A loose selector is not a
stricter gate, it is a coin-flip gate.

**Recommendation — not yet ratified (open call for Manos, raised 2026-07-30):**
keep scoped selectors for the geometry asserts and let the advisory carry the
regression signal. The advisory reports ambiguity as data on green runs without
letting it decide anything — which is what would have surfaced the lampakia drawer
in a week instead of a month, and what today flags that prevedourou.gr is one
populated `author` field away from the same puzzle (`landmarks:
["header","main#main","footer"]`, gate ENFORCING, 23 quotes with empty authors).
The alternative on the table is a second, deliberately-loose landmark layer that
only ever WARNs. Nothing in v1.8.0 depends on which way this lands; when it lands,
this section records it and `~/.claude/HEADLESS-ASTRO-ARCHIVE.md` §14e gets the
same line.

Corollary for markup: don't use landmark elements for non-landmark chrome. A
drawer header/footer is a `<div>` (lampakia commit e2ff769). A citation `<footer>`
is legitimate — scope the selector instead.

## Self-test

`node scripts/selftest.mjs` (CI: `verify-homepage-selftest.yml`, ahead of the live
smoke) runs the entrypoint against committed `file://` fixtures in
`scripts/selftest/` — no network, real Chromium. The fixtures reproduce both
shapes above, at a desktop width (drawer hidden → collapse) and a mobile width
(drawer visible → overlap), and assert that scoped selectors stay silent on the
*identical* markup. Requires `npm ci && npx playwright install chromium`.

## Honest limits

Catches **structure + render breakage**, not visual taste. It does not judge
hierarchy, spacing rhythm, or brand fidelity (advisory `design-critic` + your
eye). Overlap detection is deliberately conservative (in-flow landmarks only) to
stay false-positive-free; it won't catch a sub-element z-index collision. The
landmark diagnostics explain a finding, they do not resolve landmarks *correctly*
— the tool still measures `querySelector`'s first match, by design (see above).
