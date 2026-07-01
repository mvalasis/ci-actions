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
  (default `["header","main","footer"]` if omitted).

## Honest limits

Catches **structure + render breakage**, not visual taste. It does not judge
hierarchy, spacing rhythm, or brand fidelity (advisory `design-critic` + your
eye). Overlap detection is deliberately conservative (in-flow landmarks only) to
stay false-positive-free; it won't catch a sub-element z-index collision.
