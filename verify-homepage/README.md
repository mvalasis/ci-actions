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
- **links** — **retired in v1.15.0** (2026-09-25); `checks: links` now fails the
  step. It was meant to fold the per-repo `verify-homepage-t1.sh` copies in, but
  no caller ever enabled it and its copy fell behind (serial, one exit code, the
  argument as its same-origin filter). The T1 crawl is each repo's own
  `scripts/verify-homepage-t1.sh`, kept byte-identical fleet-wide.

- **affordance** (opt-in, v1.26.0) — does a control look and behave like what it
  is? Checkbox/radio labelled, label-in-name, a click on the label text toggles
  it, computed `cursor: pointer` on clickable controls. Report-only until a caller
  sets `fail-on-affordance: true` — see [Affordance check](#affordance-check-opt-in-report-only-first).

- **focus**, **forms**, **target**, **motion**, **consent** (opt-in, v1.27.0) — the
  UX families added after the 2026-10-06 UI/UX review: a keyboard Tab-walk (skip link
  visible, focused element not covered, a focus indicator), form usability (visible
  label, `autocomplete`, 16px inputs on phones, a required cue), WCAG 2.5.8 target size
  (axe-core `wcag22aa`), reduced motion + layout shift, and the first-visit consent
  banner. Each report-only until its own `fail-on-<check>` is `true` — see
  [UX families](#ux-families-opt-in-report-only-first).

Every check but `nav` needs a browser. The browser matrix is the
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
| `checks` | no | `render,nav` | Any of `render`, `nav`, `affordance`, `focus`, `forms`, `target`, `motion`, `consent` (the last six are opt-in — not in the default). (`links` retired in v1.15.0 — fails the step.) |
| `fail-on-structure` | no | `true` | `true` = BLOCK; `false` = report-only (WARN). Governs `render` and `nav` only. |
| `fail-on-affordance` | no | `false` | Governs `affordance` only. `true` = BLOCK on any finding, or on a fault in the check itself; `false` = report-only (WARN + `::warning` annotations). The opposite default of `fail-on-structure`, on purpose: a new check reports first. |
| `fail-on-focus` | no | `false` | Governs `focus` only. Same contract as `fail-on-affordance`: `true` = BLOCK on a finding or a fault in the check; `false` = report-only. |
| `fail-on-forms` | no | `false` | Governs `forms` only. |
| `fail-on-target` | no | `false` | Governs `target` only. |
| `fail-on-motion` | no | `false` | Governs `motion` only (its `cls` rule included). |
| `cls-budget` | no | `0.1` | `motion` only: cumulative layout shift above this, per viewport, is a `cls` finding. |
| `fail-on-consent` | no | `false` | Governs `consent` only. |
| `consent-selector` | no | `''` | `consent` only: CSS selector of the banner, overriding detection. A selector that matches nothing is a note, not a finding. |
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

## Affordance check (opt-in, report-only first)

Added in v1.26.0 after EPN's `/contact/` and `/employers/` shipped (2026-10-06) with a
consent checkbox whose words were not inside a `<label>` (clicking them did nothing), whose
`aria-label` said something else than the words, and a submit button and checkbox with no
`cursor: pointer`. pa11y/axe flag a *missing* label but not a label-in-name mismatch or text
that merely sits beside a box, and nothing in the fleet read computed `cursor`. It runs on the
same page load as `render`, after the measurement, at every viewport.

```yaml
      - uses: mvalasis/ci-actions/verify-homepage@v1
        with:
          checks: render,nav,affordance   # opt-in: the default stays `render,nav`
          fail-on-structure: 'true'       # unchanged — governs render + nav only
          fail-on-affordance: 'false'     # report-only; flip to 'true' once the report is clean
```

| rule | fires when | notes |
|---|---|---|
| `label-missing` | a visible checkbox/radio has no `<label>` (wrapping, or `for=`), or has no accessible name at all | When plain text sits beside an unlabelled control (the EPN shape) it is quoted — those are the words that should have been the label. |
| `label-in-name` | the visible label text is not contained in the control's accessible name (WCAG 2.5.3) | Only an `aria-label` / `aria-labelledby` / `title` can break it: a name taken from the `<label>` contains its text by construction. With no `<label>`, the nearby visible text stands in for it. Compared case-folded with punctuation collapsed, Greek included. |
| `label-click` | a **real mouse click** on the label's own text does not toggle the checkbox / select the radio | Hit-tested, so an overlay or `pointer-events: none` is caught, and the finding names the element that took the click. Text inside a link/button in the label is never clicked (it would navigate). Disabled and not-rendered controls are skipped, and so is an already-checked radio (a click cannot flip it). State is restored afterwards — the checkbox by the same click, a radio by re-selecting the group's previous choice. If a click navigates the page the leg stops and says so. |
| `cursor` | computed `cursor` is not `pointer` on `button`, `input[type=submit\|button\|reset\|image]`, `a[href]`, `summary`, `[role=button]`, `select`, `input[type=checkbox\|radio\|file]`, or a `<label>` that wraps/targets a checkbox or radio | `not-allowed` / `default` are fine only when the control is disabled. A visually-hidden native checkbox/radio/file input (a custom control) is skipped — its `<label>` carries the cursor. `pointer-events: none` and `[inert]` are skipped. A `select` and a bare checkbox default to `cursor: default` in the user-agent sheet, so unstyled ones **will** be flagged: that is the rule. |

**Output.** Per URL: one line per finding *group* (one cause), `` `selector` ×N “quoted words” — what's wrong
_(viewports)_ ``. A group merges the same selector across viewports, and drops `:nth-of-type(n)` so fifty
identical cards read as one finding with a count. Behavioural rules list first (`label-click`,
`label-in-name`, `label-missing`, then `cursor`). The verdict is its own line — `affordance PASS` /
`affordance WARN (report-only)` / `affordance FAIL` — and **never moves the render/nav verdict or its
exit code**; the exit code is `fail-on-affordance` alone.

**Annotations** (unlike the render rows — see "No annotations" below): one `::warning` (`::error` when
enforcing) per finding group, `verify-homepage affordance <rule>`, with the rule, the page URL and the
selector in the message. Never a label's or a button's text (page-controlled). At most 10 per step; the
behavioural rules come first so a cap never cuts them off. Unlike a render row, an affordance finding *is*
one finding with an id (rule + selector + page), and the selector is a short tag/class/`:nth-of-type` path
restricted in-page to `[A-Za-z0-9_-]` tokens, so it is safe in a workflow command.

**A fault is a fault.** If the check cannot look (the page will not evaluate, a driver error) it says
`affordance could not look — a fault in the gate, not a verdict on the page`, never prints a PASS, never
files a finding, and exits `fail-on-affordance ? 1 : 0`. A crash in the whole entrypoint of an
affordance-only run is governed by `fail-on-affordance`, not `fail-on-structure`.

**Left out on purpose: a visible `:hover` / `:focus-visible` change.** Not cheap and not quiet: it needs a
pointer move, a style diff and a transition wait per element (hundreds of links per page × 4 viewports);
touch viewports have no hover at all; and the legitimate change is often on a parent, a pseudo-element or
an outline rather than the element's own computed style, so the diff would be mostly noise. The focus ring
is already gated (DISCIPLINES §7: focus-ring ≥2px/≥3:1, axe). Revisit only with a measured, narrow rule.

**Known limits, so a green run is not over-read.** The accessible name is an in-page approximation of the
accname algorithm for form controls (`aria-labelledby` > `aria-label` > `<label>` > `title`), not Chromium's
own AX tree. `label-in-name` with no `<label>` guesses the "visible label" from the nearest ancestor (≤5 up)
that holds this one control and some text, so a control inside a larger wrapper with other controls is
checked for a label but not for nearby-text contradiction. Only checkboxes and radios get the label rules;
text inputs/selects are axe's. State toggled by the click leg is restored by script, so a page whose handler
persists a toggle (a saved preference) will see it persisted — run it on pages you would not mind clicking.

## UX families (opt-in, report-only first)

Five more opt-in families, added in v1.27.0 after the 2026-10-06 UI/UX review
(`~/.claude/retros/UIUX-GAP-REVIEW-2026-10-06.md`): EPN's contact and employers forms had shipped with
defects no gate saw — no skip link a keyboard user could see, a cookie banner covering the focused
footer links, placeholder-only labels, no `autocomplete`, 15.2px inputs, motion that ignored
`prefers-reduced-motion`. They follow the [affordance](#affordance-check-opt-in-report-only-first)
template exactly:

- **Opt-in** through `checks`; the default stays `render,nav`.
- **Their own switch**, `fail-on-<check>`, default `false` — report-only first. A family never moves the
  render/nav verdict, nor another family's; the exit code is `fail-on-structure` for render/nav and each
  `fail-on-<check>` for its family, OR-ed.
- **A fault is a fault.** If a check cannot look (the page will not evaluate, axe-core is missing, a driver
  error) it says `<check> could not look — a fault in the gate, not a verdict on the page`, never prints a
  PASS, never files a finding, and exits `fail-on-<check> ? 1 : 0`. A crash of the whole entrypoint is
  governed by the switches of the checks that run: `fail-on-structure` for `render`/`nav`, each
  `fail-on-<check>` for an opt-in one — exit 1 only if one of them is `true`, and the note names which.
- **Same output**: per URL one line per finding *group* (one cause: the same rule + selector across
  viewports, `:nth-of-type` dropped), `` `selector` ×N “quoted words” — what's wrong _(viewports)_ ``; a
  verdict line `<check> PASS | WARN (report-only) | FAIL` with a one-line tally of what was looked at;
  `::warning` (`::error` when enforcing) annotations carrying family, rule, page URL and selector — never
  page text — at most 10 per level per step across ALL families, the rest counted.
- **Read-only.** None of them types into, submits or clicks anything. (`focus` presses Tab; `affordance`,
  separately, clicks a label and restores it.) The page-sharing families run after the `render`
  measurement on the same page load — `consent`, `forms`, `target`, then `focus`, then `affordance` last —
  so they add no page loads. `motion` needs its own browser contexts (below).

```yaml
      - uses: mvalasis/ci-actions/verify-homepage@v1
        with:
          checks: render,nav,affordance,focus,forms,target,motion,consent
          fail-on-structure: 'true'   # unchanged — governs render + nav only
          # every fail-on-<check> defaults to 'false': report first, flip one at a time once its report is clean
```

### `focus` — can a keyboard user see where they are?

A real Tab-walk (keyboard events, so `:focus-visible` matches) from the top of the page: at most 60 stops,
ending when focus returns to the first stop, leaves the document or stops moving. Before each reading the
element's own finite CSS transitions are awaited (≤250ms), so a skip link that slides in, or a ring that
fades in, is read where it ends up and not at its first frame.

| rule | fires when | notes |
|---|---|---|
| `skip-link-hidden` | the FIRST stop is an in-page `#anchor` link and, once focused, it has no real size (≤2px), sits outside the viewport, is transparent, or the point at the centre of its visible box hit-tests to something that is not the link or a descendant | EPN: the skip link sits at y 0–25 behind a 144px fixed header. Only the first stop is treated as a skip link; a page whose first stop is something else is not asked for one (`stats: no skip link`). |
| `focus-obscured` | a stop whose centre AND four inset corner points (those inside the viewport) are ALL covered by a foreign element — neither an ancestor nor a descendant | WCAG 2.4.11 fails only when the element is entirely hidden: **partly covered is not a finding**, it is counted (`N partly covered`). Needs the centre and ≥3 points in the viewport; an element scrolled mostly off-screen is counted, not judged. EPN: footer links on `/search/` and the 404 at desktop, under `div.epn-cookie-banner`. The fix is `scroll-padding-bottom` + room under the last link, not removing the banner. |
| `focus-no-indicator` | a stop with `outline-style: none` (or a 0 outline width) AND `box-shadow: none` | An input that draws its ring as a box-shadow (EPN's inputs) is fine. |

Ignored by all three: a stop that is, sits inside or contains an `<iframe>`, `.cf-turnstile`, `.g-recaptcha`
or `.h-captcha` (third-party; counted as `N third-party skipped`), and a box of ≤2px — the visually-hidden
native checkbox of a custom control, whose `<label>` carries the ring.

**Left out on purpose:** Tab *order* against visual order (WCAG 2.4.3 — a heuristic with real false
positives); a keyboard trap (the walk just ends); focus appearance size/contrast (2.4.13 is AAA); anything that
needs a click.
**False-positive notes:** an indicator drawn by a *background*, `border` or `text-decoration` change alone is
flagged (there is no outline or shadow to read) — add an outline; a ring drawn on a *different* element
(`:focus-within` on a wrapper, the label of a hidden native input) is not seen when the native input is >2px;
an overlay with `pointer-events: none` is not seen by the hit test; a page that moves focus in script on
`focus` can make the walk skip stops.

### `forms` — is the form usable before it is submitted?

One in-page scan per viewport of every visible `<form>` and its `<input>`/`<select>`/`<textarea>` — skipping
`type=hidden|submit|button|image|reset`, **honeypots** (`autocomplete=off` AND off-screen, ≤2px or transparent)
and **search** inputs (`type=search`, `role=searchbox`, inside `role=search`). Stats: forms and controls inspected.

| rule | fires when | notes |
|---|---|---|
| `label-not-visible` | no `<label for>` / wrapping `<label>` with *visible* text, and no `aria-labelledby` that points at visible text | A placeholder, an `aria-label` or a `title` alone is a finding, and so is a label that is visually hidden (sr-only) — the detail says which. Checkboxes and radios are `affordance`'s (`label-missing`) and are not repeated. |
| `autocomplete-missing` | a `text/email/tel/url/number` input whose `name`/`id`/`aria-label`/`type` reads as an identity field has no `autocomplete` token | Table: `name`, `given-name`, `family-name`, `email`, `tel`, `organization`, `street-address`, `postal-code`, `address-level2`, `country`, `username` — matched on whole tokens (`your-name`, `yourName`, `first_name`; not `nickname`, not `email-address` as a street). `off` counts as missing, and so does a form-level `autocomplete=off` with no attribute of the control's own. `on` and any other value do not (axe's `autocomplete-valid` judges the token). WCAG 1.3.5. |
| `input-font-size` | **viewport width ≤600 only**: computed `font-size` under 16px on a text-like input, select or textarea | iOS Safari zooms the page on focus below 16px. |
| `required-unmarked` | a `required` / `aria-required` control has no visible required cue | A cue is an `*` or the word required / mandatory / optional (Greek υποχρεωτικό / προαιρετικό too) in its label or placeholder, **or** a sentence in the form that states the convention ("fields marked * are required", "all fields are required"). |

**Left out on purpose:** how the form behaves when *submitted* — error summary, focus to the error, data
kept, double-submit, pending state. The check never types or submits, and those need a mocked POST in the
caller's own Playwright test (EPN's `/apply` held-button test is the model). Also `type`/`inputmode`
suitability and per-field validation messages.
**False-positive notes:** the identity table is name-based, so a field *named* `name` that is not a person's
(a pet's, a product's) is flagged — give it `autocomplete="off"` on purpose and it is still flagged, because
`off` is "missing": rename it, or leave the form out of the run; a visually-hidden label on a non-search field
is a finding by design; a required cue given only by colour or an icon is not read.

### `target` — WCAG 2.5.8, through axe-core

[axe-core](https://github.com/dequelabs/axe-core) **4.11.4** (a pinned second dependency — the version
`a11y-audit`'s pa11y already runs; `package-lock.json` hashes it, `npm ci --ignore-scripts`) is injected from
`node_modules/axe-core/axe.min.js` through the DevTools protocol (a page CSP cannot block it) and run with
`runOnly: { type: 'tag', values: ['wcag22aa'] }`. Only the `target-size` rule's violations are kept — one finding
per element, per viewport, naming axe's own measurement ("14px by 14px, should be at least 24px by 24px").
**axe decides the exceptions** (inline links in running text, the spacing exception, user-agent controls), so
an isolated 14px button with free space around it is *not* a finding. A target axe puts under "incomplete" is
a stat (`needs-review`), never a finding.

Stats only, **never a finding**: how many interactive targets render under 44px in either dimension (the
Apple HIG / Material guideline) — 15 on a typical desktop page of a content site, so a gate on it would be noise;
the count is there so a doubling is visible.

Why it exists: `a11y-audit` runs axe via pa11y without the `wcag22aa` tag, so `target-size` never ran in the
fleet. EPN measured 0 violations on 6 pages × 2 viewports on 2026-10-06 — this is regression insurance.
**Limits:** only what axe's `wcag22aa` set judges; 2.4.11 (focus not obscured) is `focus`'s, not axe's.

### `motion` — does the page hold still when it should?

The only family with its **own browser contexts**, per URL × viewport: (1) `reducedMotion: 'reduce'`;
(2) a fresh context with a `layout-shift` `PerformanceObserver` installed by `addInitScript` before the page's
own scripts, so a shift during load is not missed — plus 700ms of settle for a late banner or lazy image.

| rule | fires when | notes |
|---|---|---|
| `reduced-motion-animation` | under `reduce`, a CSS animation or transition from `document.getAnimations()` is still `running` and is infinite or longer than 5s | The finding names the animation and the element (and pseudo-element). EPN: `epn-hero-shine`, `epn-map-flow` on `/`. Short finite animations (≤5s) are never a finding. Opt out essential motion (a loading spinner, a video the user started) with `data-essential-motion` on the element or an ancestor. |
| `reduced-motion-smooth-scroll` | under `reduce`, the root's computed `scroll-behavior` is not `auto` | EPN: `smooth` on every page. |
| `cls` | the layout-shift sum after load + settle is over `cls-budget` (default `0.1`), per viewport | The sum over the whole load, a stricter reading than the worst 5s session window; the number is in the tally either way. |

**`hadRecentInput` is deliberately not used to discard shifts.** The context dispatches no input, and a
*mobile* emulation (`isMobile`) flags **every** entry `hadRecentInput: true` — measured on the pinned Chromium,
a shift 1.2s after load included — so honouring the flag reads 0 on every phone viewport. (EPN's "mobile 0"
in the review was very likely this blind spot.)

**Left out on purpose:** JS-driven animation (requestAnimationFrame, canvas, script-started Web Animations);
autoplay video; parallax; LCP/INP (Lighthouse is the tool). CLS is lab data from a headless run, so expect
variance near the budget — set `cls-budget` a little above where you are, and trend it.

### `consent` — is refusing as easy as accepting?

EDPB / CNIL practice for a first-visit cookie banner. A fresh context has no cookies, so the banner the check
sees *is* the first-visit banner. Read-only: it never clicks, ticks or types.

**Detection** (or the `consent-selector` input): a rendered element that is `position: fixed` or `sticky`, or a
`[role=dialog|alertdialog]` / `dialog[open]` / `[aria-modal=true]`, holding controls (`button`, `a[href]`,
`[role=button]`, input button/submit) whose text or aria-label reads as **accept** — accept / agree / allow /
ok / got it (Greek αποδοχή / συμφωνώ). One that holds an accept *and* a **reject** control is preferred (reject
/ decline / deny / refuse / "necessary only" / "essential only" / "do not accept"; Greek απόρριψη / μόνο
απαραίτητα — matched first, so "Accept necessary only" is a reject). One that holds only accept qualifies only if
its text, id or class talks about cookies / consent / privacy, so a fixed "Allow notifications" widget is not a
banner. Smallest wins. "Manage / settings / preferences" is not a reject.

| rule | fires when |
|---|---|
| `consent-no-reject` | an accept control is on the first layer and no reject is (the detail adds "refusing sits behind a settings control" when there is one) |
| `consent-reject-smaller` | reject's width **or** height is under 80% of accept's (the largest accept and the largest reject are compared) |
| `consent-prechecked` | an optional-category checkbox (`input[type=checkbox]`, `[role=checkbox|switch][aria-checked=true]`) in the banner is checked and not disabled. Always-on boxes — a label/name/id mentioning necessary / essential / required / strictly — are exempt, and so is a disabled one. One in a collapsed preferences panel inside the banner counts (the detail says so): a pre-ticked box is invalid wherever the user meets it. |

**Visual weight** (filled vs outline, colour) is an `ℹ️ INFO` note and a stat, **never a finding** — whether a
gold button beside an outline one "nudges" is a judgement call; size and position are not.
**No banner found** → a stat (`no banner found`) and an INFO note, never a finding: a site with none, one that
appears after `wait-ms`, or one inside a cross-origin iframe is not something this check can judge. Say
so with `consent-selector` when you know where the banner is.
**Left out on purpose:** what happens after a click (does rejecting stop the trackers — that needs the network
and a cookie jar), the wording, reject being *behind* a second click beyond the first layer, whether the site
needs a banner at all.
**False-positive notes:** the 80% rule compares *boxes*, so "Accept all" next to a short "Reject" can trip it
on label length alone — make the buttons the same width; a banner whose text is rendered by an unusual
script, or controls that are not buttons/links/`[role=button]`, are not recognised.

## Where the report goes

The report goes to the **job log** (stdout) on every run, and to the **step
summary** when there is one. A run with no `GITHUB_STEP_SUMMARY` (a local run), or
with `GITHUB_STEP_SUMMARY=/dev/stdout`, prints it once, to stdout. Before v1.19.1
it printed twice there: the old fallback appended the report to `/dev/stdout`,
which is the log again. A crash note goes to the step summary and to stderr; on a
local run, stderr is the only copy.

### No annotations (decision, 2026-09-25)

`verify-homepage` does not emit `::error` / `::warning` annotations for its FAIL
rows, unlike the gates that gained them in v1.16.0 and v1.18.0. Decided while
fixing v1.19.1:

- **The gap they closed is not here.** Those gates wrote their report only to the
  step summary, so a blocked run's log said `Process completed with exit code 1`
  and nothing else. v1.18.0 ported annotations to exactly the gates in that state.
  This one has printed its whole report to the job log since v1.7.1, so
  `gh run view --log-failed` already names the page, the viewport and the problem.
- **A FAIL row is not one finding with an id.** It is a page × viewport bundle of
  problems whose detail comes from the page (class names, element identifiers),
  and page text never goes into an annotation. What would be left is
  `render at <url> @ <viewport>`: the report line with its content removed.
- **The rows fan out.** One stylesheet or template regression fails every URL at
  every viewport. epn-astro's 7 URLs × 4 viewports are 28 render rows, so the 10
  annotations per level that GitHub keeps for a step would repeat one cause.
- **No surface for them.** All six callers (measured 2026-09-25) run it on a weekly
  cron plus manual dispatch, never on a pull request, so there is no checks tab
  for annotations to appear in, and the run page already shows the step summary.

**Exception — `affordance` (v1.26.0) and the v1.27.0 families do annotate**, because none of those four
reasons holds for them: a finding is one finding with an id (rule + selector + page), its text is restricted
to identifiers, and its groups are already de-duplicated across viewports and repeated siblings. The ten
per level that GitHub keeps are shared by all of them, behavioural rules first, the remainder counted.

Revisit if the gate is wired to pull requests or pushes, or if something that
reads only annotations becomes how failures get triaged. The shape then: one
annotation per failing page × viewport, titled by problem kind (`overflow`,
`collapsed-landmark`, `missing-landmark`, `overlap`, `load-error`,
`nav-inventory`), `::error` when enforcing and `::warning` in report-only, at
most 10 per step.

## Self-test

`node scripts/selftest.mjs` (CI: `verify-homepage-selftest.yml`, ahead of the live
smoke) runs the entrypoint against committed `file://` fixtures in
`scripts/selftest/` — no network, real Chromium. The fixtures reproduce both
shapes above, at a desktop width (drawer hidden → collapse) and a mobile width
(drawer visible → overlap), and assert that scoped selectors stay silent on the
*identical* markup. Requires `npm ci && npx playwright install chromium`.

It also runs the entrypoint the way a local run does, with no step summary and
with `GITHUB_STEP_SUMMARY=/dev/stdout`, and asserts the report prints exactly
once. Each of those cases runs with stdout as a socket (what `spawnSync` hands a
child) and as an `O_APPEND` file. The file is the load-bearing one: on Linux,
opening `/dev/stdout` fails (ENXIO) when stdout is a socket, so a socket-only leg
would pass against the pre-v1.19.1 double print on the CI runner.

The `affordance` fixtures are `affordance-bad.html` (every rule must fire: the EPN pre-fix shape, a
contradicting `aria-label`, an overlay on the label, a swallowed click, unlabelled radios, one wrong-cursor
control per kind) and `affordance-good.html` (must stay silent, enforcing: a link inside a label, a custom
checkbox with a hidden native input, a pre-checked radio, disabled and not-rendered controls, a Greek
label). They also pin the exit codes in both modes, that the switch is independent of
`fail-on-structure`, that annotations carry identifiers only and stop at 10, that the click leg restores
every state it toggled, and — by stubbing `playwright` — that a fault inside the check is reported as one
(never a PASS) and exits under `fail-on-affordance`.

The v1.27.0 families each have a BAD and a GOOD fixture in the same directory (`focus-`, `forms-`,
`target-`, `motion-`, `consent-` + `bad|good`; consent also `consent-smaller` and `consent-none`). BAD must fire
every rule *and* hold every exclusion (a honeypot, a search box, a third-party iframe, a link only partly
under the banner, an essential spinner, an isolated small button, an always-on checkbox); GOOD must stay silent,
enforcing, *and prove it looked* (Tab stops, controls, targets, animations seen under `reduce`, the banner
found and not mistaken for a fixed "Allow notifications" widget). Per family: report-mode with the switch
unset exits 0, enforcing exits 1, independence from `fail-on-structure` both ways, annotations carry
identifiers only, and a fault in the check — an unevaluable page for all five, a missing `axe-core` for
`target` — is reported as one. Two mutants are pinned on purpose: `focus` run without its transition wait must
flag GOOD's fading rings (so the fixture really exercises the wait), and a `motion` CLS leg must read the
phone viewport too (the `hadRecentInput` trap above).

The crash-guard block at the end of the same file needs **neither** — it stubs
`playwright` in a temp dir, so it runs on a bare checkout. It asserts the same
exactly-once rule for a local crash note.

## A gate fault is not a page verdict

If `render-check.mjs` itself faults — Chromium failing to launch, a malformed
`verify-nav.json`, a driver timeout escaping an await — it reports
**`verify-homepage crashed`** into the step summary and the job log (stderr; on a
local run, the only copy), says in as many words that this is *not a verdict on
the page*, and exits
`fail-on-structure ? 1 : 0`. A report-mode caller is therefore never newly-BLOCKED
by a bug in this action. Before v1.12.0 any throw exited 1 regardless, with a bare
stack and nothing in the summary.

Two implementation notes, both load-bearing:

- The handler is registered **above every other top-level statement**. This is a
  top-level-await module whose terminal paths are bare `process.exit()` calls, so
  it gets none of the ordering-immunity the sibling
  `(async () => {…})().catch(…)` entrypoints have for free.
- It reads `FAIL_ON_STRUCTURE` from **`process.env`**, not from the `FAIL` const.
  The likeliest crash site is const initialisation itself, and at that moment
  `FAIL` is in the **temporal dead zone** — reading it there throws
  `ReferenceError` *inside the crash handler*, so node exits 7 having written
  nothing, losing the diagnostic and the exit code together. `typeof` is no
  escape; it throws in the TDZ too. `scripts/selftest.mjs` pins this with a fault
  injected into the const block, and that case goes red under exactly that
  "tidy-up" — verified by mutation, so the env read cannot be refactored away as
  a redundant spelling of `FAIL`.

## Honest limits

The opt-in families are *rendered, read-only probes* — each README section above lists what it does not
judge. Across all of them: they read the page as a fresh, cookie-less visitor on the weekly runner's network,
so a banner that appears after `wait-ms`, a flow behind a login, or anything that needs a click is not seen;
a green run means "nothing here tripped these rules", not "accessible" (axe catches roughly a third of WCAG
issues; the critics and a keyboard are the rest).

Catches **structure + render breakage**, not visual taste. It does not judge
hierarchy, spacing rhythm, or brand fidelity (advisory `design-critic` + your
eye). Overlap detection is deliberately conservative (in-flow landmarks only) to
stay false-positive-free; it won't catch a sub-element z-index collision. The
landmark diagnostics explain a finding, they do not resolve landmarks *correctly*
— the tool still measures `querySelector`'s first match, by design (see above).
