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
