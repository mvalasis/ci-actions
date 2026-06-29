# a11y-audit

WCAG 2.2 AA audit of live URLs via **pa11y-ci** (axe-core + HTML_CodeSniffer). Audits the
rendered page, so it fits server-rendered WordPress and deployed Astro alike. **Report-mode
by default** — flip `fail-on-violations: true` to BLOCK once a page's backlog is clean.

```yaml
# .github/workflows/a11y-audit.yml
name: a11y-audit
on:
  workflow_dispatch: {}
  schedule: [{ cron: '20 2 * * 1' }]
permissions: { contents: read }
jobs:
  a11y:
    runs-on: ubuntu-latest
    steps:
      - uses: mvalasis/ci-actions/a11y-audit@v1
        with:
          urls: |
            https://example.com/
            https://example.com/about/
          fail-on-violations: 'false'   # report first; enforce once clean
```

| input | default | notes |
|---|---|---|
| `urls` / `sitemap-url` | — | the pages to audit (one required) |
| `standard` | `WCAG2AA` | or `WCAG2AAA` |
| `runner` | `axe htmlcs` | pa11y runners |
| `fail-on-violations` | `false` | `true` = hard BLOCK |
| `max-urls` | `25` | cap |

Rollout: start `fail-on-violations: false` (surface the backlog), fix it, then flip to `true`.

## Notes

- **Modern browser.** Uses `pa11y-ci@4` (pa11y 9 / puppeteer 24, current Chromium). The
  earlier `@3` pin shipped Chromium 91, which predates CSS cascade layers (`@layer`, Chrome
  99+); on any layered stylesheet — e.g. **Tailwind v4** — the utilities block was dropped,
  so the page rendered unstyled and axe reported **bogus contrast failures** (text fell back
  to the UA link colour). The current engine renders the page as real users see it.
- **`needsReview` is advisory, not blocking.** axe "incomplete" findings (where it can't
  auto-determine pass/fail — text over a `position:fixed` overlay, gradients, background
  images) are capped to *warning* (`levelCapWhenNeedsReview`), so they don't BLOCK. Confirmed
  axe violations + HTML_CodeSniffer errors still block. Per DISCIPLINES.md: mechanical → hard
  gate, judgment → advisory.
- **`verify-token` scope.** The token (`X-Verify-Source`) is injected via pa11y-ci's
  `defaults.headers`, which pa11y@9 applies with **first-request-only** Puppeteer request
  interception — *not* `setExtraHTTPHeaders`. So it rides only the **navigation request** to
  each audited URL (and the sitemap fetch, which uses no `-L`), never a cross-origin
  subresource (fonts/CDNs/analytics) or a cross-origin redirect target. It's still a secret
  sent to the audited origin: point the action only at first-party origins you trust, and
  prefer an origin-bound / IP-allowlisted WAF rule over a portable bearer token. The
  no-broadcast guarantee is a property of pa11y@9's interception code, so the `pa11y-ci@4`
  pin is a security control — re-audit before a major bump.
- **Desktop viewport only** (pa11y default 1280×1024). Elements hidden at desktop width
  (e.g. a `md:hidden` mobile nav) are not exercised; audit a mobile URL separately if needed.
- **Reload-on-load resilience.** Pages that navigate a beat after first load — **LiteSpeed
  Guest Mode** (`window.location.reload`), splash/intro overlays — can race pa11y's runner
  injection and throw `Execution context was destroyed, most likely because of a navigation`
  → a flaky *Failed to run*. Primary guard is deterministic: a dummy `_lscache_vary` cookie
  makes Guest Mode skip the reload entirely (plus a 3 s settle `wait`). As defense-in-depth,
  a **single retry** kicks in only on a *run* error and only when **no** URL reported real
  violations — so the retry can never mask a WCAG failure. The decision is keyed off pa11y's
  per-URL summary lines (`> <url> - …`, ANSI-stripped), not the page's own HTML, so page
  content can't spoof it. A URL that still *Fails to run* after the retry stays non-zero and
  blocks in enforce mode.
