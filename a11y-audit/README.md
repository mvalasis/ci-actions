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
- **Desktop viewport only** (pa11y default 1280×1024). Elements hidden at desktop width
  (e.g. a `md:hidden` mobile nav) are not exercised; audit a mobile URL separately if needed.
