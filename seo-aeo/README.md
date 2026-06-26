# seo-aeo

Technical SEO + AEO/GEO checks over live URLs, from a **JS-disabled (raw `curl`) fetch** —
the crawler's-eye view. `title` + `h1` are crawlability-critical (BLOCK when
`fail-on-critical: true`); `meta description`, `canonical`, `JSON-LD`, and the AEO
artifact (`llms.txt`) are WARN. Suits server-rendered WP and prerendered Astro.

```yaml
# .github/workflows/seo-aeo.yml
name: seo-aeo
on:
  workflow_dispatch: {}
  schedule: [{ cron: '40 2 * * 1' }]
permissions: { contents: read }
jobs:
  seo:
    runs-on: ubuntu-latest
    steps:
      - uses: mvalasis/ci-actions/seo-aeo@v1
        with:
          urls: |
            https://example.com/
            https://example.com/about/
          fail-on-critical: 'false'   # report first; enforce once clean
```

| input | default | notes |
|---|---|---|
| `urls` / `sitemap-url` | — | pages to check (one required) |
| `fail-on-critical` | `false` | `true` = BLOCK on missing title/h1 |
| `max-urls` | `15` | cap |

AEO/GEO is bundled here on purpose (first-class with SEO). The deterministic artifact
checks live here; content *quality* (quotable blocks, entity chains) is the advisory
`seo-critic` subagent's job, not this gate.
