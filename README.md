# ci-actions

Shared GitHub Actions for the `mvalasis/*` site ecosystem. One canonical
copy of cross-cutting CI tooling, referenced by each repo with a thin
caller workflow — so the logic lives **here**, not duplicated per repo.

> Public on purpose: these actions carry **no secrets** (env-var *names*
> only; sitemap URLs, hosts, and tokens come from each caller). GitHub
> Actions `uses:` needs a runner-reachable repo, and the local-tooling
> canonical (`~/.claude`, private — infra playbooks) can't serve that role.

## Versioning & releasing (all actions)

Callers pin the **floating major tag** `@v1` — the standard GitHub-Actions
convention (`actions/checkout@v4` works the same way). **Never pin `@main`:**
`main` is bleeding-edge, and `security-baseline` is a *blocking* PR/push gate
across the whole fleet — a bad commit on `@main` would lock merges everywhere.
`@v1` gives every caller a vetted release plus instant rollback.

- **`v1`** — floating; moved forward on every backward-compatible release. This
  is the only ref callers reference.
- **`v1.x.y`** — immutable point tags; cut one per release as a changelog marker
  and rollback anchor. Optional/lazy — cut when a release is worth naming, not
  per push.
- **`v2`** — only ever for a **breaking** change (removed/renamed input, or a
  default that breaks existing callers). Callers opt in by editing `@v1`→`@v2`;
  that's the *only* time caller repos get touched after the initial wiring.

**Release ritual** (after merging compatible work to `main`):

```bash
git tag -a v1.2.0 -m "v1.2.0 — <what changed>"   # optional immutable anchor
git push origin v1.2.0
git tag -f v1 HEAD && git push -f origin v1       # move the floating major
```

**Rollback:** `git tag -f v1 v1.1.0 && git push -f origin v1` (point callers
back at the last-good release; they pick it up on their next run).

A normal release = **one tag move**, not a commit in any caller repo. As of
2026-06-29 every caller (`a11y-audit`, `seo-aeo`, `security-baseline`,
`linkcheck`) pins `@v1`; current line is **v1.2.0** (seo-aeo rebuilt as a
parsed Node+cheerio gate — T0/T1/T2 severity + the additive `critical-checks`
input; backward-compatible, no-regression on the enforcing callers).

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
