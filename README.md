# ci-actions

Shared GitHub Actions for the `mvalasis/*` site ecosystem. One canonical
copy of cross-cutting CI tooling, referenced by each repo with a thin
caller workflow — so the logic lives **here**, not duplicated per repo.

> Public on purpose: these actions carry **no secrets** (env-var *names*
> only; sitemap URLs, hosts, and tokens come from each caller). GitHub
> Actions `uses:` needs a runner-reachable repo, and the local-tooling
> canonical (`~/.claude`, private — infra playbooks) can't serve that role.

## `linkcheck` — full-site broken-link / image / outbound crawl

Curl-based (not lychee — lychee 0.24.2 hard-panics on CF/Kinsta edges that
close a connection without a TLS `close_notify`). Expands a Rank Math
`sitemap_index.xml`, fetches every page, checks every `<a href>` and
`<img src>` once. A broken **internal** link/image or a clearly-dead
**outbound** (404/410) fails the run; flaky externals (timeout / 5xx /
bot-block) are reported but non-fatal. Optionally opens and auto-closes a
GitHub issue with the report.

### Use it

```yaml
name: Weekly link & image check (full site)
on:
  schedule: [{ cron: '0 2 * * 1' }]      # pick your own off-peak slot
  workflow_dispatch: {}
concurrency: { group: linkcheck-weekly, cancel-in-progress: true }
permissions:
  contents: read
  issues: write                          # only needed if manage-issue (default) is on
jobs:
  linkcheck:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v6        # brings your scripts/linkcheck-allow.txt
      - uses: mvalasis/ci-actions/linkcheck@v1
        with:
          sitemap-url: https://www.example.com/sitemap_index.xml
          host: example.com
          verify-token: ${{ secrets.VERIFY_HOMEPAGE_TOKEN }}
```

### Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `sitemap-url` | yes | — | Rank Math `sitemap_index.xml` to expand. |
| `host` | yes | — | Internal host; links here (+ subdomains) are fatal if broken. |
| `verify-token` | no | `''` | `X-Verify-Source` WAF-bypass token, sent **only** to `host`. |
| `allow-file` | no | `scripts/linkcheck-allow.txt` | Per-repo baselined-URL list, read from the caller checkout. |
| `workers` | no | `10` | Concurrent curl workers. |
| `manage-issue` | no | `true` | Open/auto-close a GitHub issue on failure/clean (needs `issues: write`). |

### Per-repo baseline

Keep a `scripts/linkcheck-allow.txt` in each caller repo (one URL per line,
`#` comments). Any URL listed is treated as OK — use it only to silence
genuinely-low-value legacy cruft, never to hide a real outage. It is read
from **your** checkout, not from this action.

## Adding the action to a new repo

1. Drop in the caller workflow above (set `sitemap-url` + `host`).
2. Commit an empty `scripts/linkcheck-allow.txt`.
3. (If using a WAF token) add the `VERIFY_HOMEPAGE_TOKEN` secret.

## Roadmap

- `verify-homepage` — fold the per-repo `verify-homepage-t1.sh` copies into a
  shared action here (same duplication, same fix).
