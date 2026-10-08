# agent-benchmark

What two public agent-readiness scanners say about a site: **ora.ai**'s score (0-100, a letter
grade, four layers — Discovery, Access, Usability, Payments — and its top fixes with their estimated
gain) and Cloudflare's **isitagentready.com** level (its name, the checks per category, and what the
next level needs).

`seo-aeo` grades the same layer itself, air-gapped, in its `### Agent readiness` block (v1.29.0):
that block is what a caller promotes and blocks on. This action is the second opinion, for the
trend and the order of work. **Report-only:** it always exits 0, and a scanner that could not look
is listed as such, never as a score.

## Use it

```yaml
# .github/workflows/agent-benchmark.yml
name: agent-benchmark
on:
  workflow_dispatch: {}
  schedule: [{ cron: '50 3 * * 1' }]   # weekly; pick your own off-peak slot
permissions: { contents: read }
jobs:
  bench:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - id: bench
        uses: mvalasis/ci-actions/agent-benchmark@v1
        with:
          url: https://www.example.com/
          # ora: 'false'   # a host that must not appear on ora's public leaderboard
      - if: steps.bench.outputs.json != ''
        uses: actions/upload-artifact@v4
        with:
          name: agent-benchmark
          path: ${{ steps.bench.outputs.json }}
          retention-days: 90
```

Weekly is enough: a score moves when the site or the scanner's checks change, and ora serves a
result younger than 6 h from its cache anyway. The artifact keeps the full answers, so a later run
can be compared with an earlier one.

## Inputs

| Input | Default | |
|---|---|---|
| `url` | (required) | The homepage URL. A bare host gets `https://`. Credentials and the fragment are stripped before anything is sent. |
| `ora` | `'true'` | Ask ora.ai. `'false'` skips it. |
| `isitagentready` | `'true'` | Ask isitagentready.com. `'false'` skips it. |

## Outputs

| Output | |
|---|---|
| `ora-score` | ora's score; empty when ora was off or could not look. |
| `ora-grade` | ora's letter grade; empty likewise. |
| `isitagentready-level` | isitagentready's level; empty when it was off or could not look. |
| `json` | Path of `agent-benchmark.json` under `RUNNER_TEMP`, both answers in full; empty when nothing was asked or it could not be written. |

The report goes to the job log and the step summary: ora's score with where it came from (a fresh
scan, ora's cache and its age, or its last stored result), the layers, the status counts, the top
fixes, and every failing or warning check in a collapsed table (the required tier first, then by
estimated gain; a layer with a maximum of 0, Payments on a site ora does not read as a store, is
named unscored and left off the list); then isitagentready's level, what the next level needs, and
one line per category. One `::notice` carries both headlines.

## What leaves the runner

**The URL, and nothing else.** No token, no cookie, no header of the caller's. It goes to two
third parties:

- **ora.ai lists every scan on its public leaderboard.** Set `ora: 'false'` for a host that must
  not appear there (a staging host, a client who has not agreed to it).
- **isitagentready.com** does not document how long it keeps a scan. Treat it as public.

Both scanners fetch the site from their own servers, so a site behind a WAF challenge reads to them
as it reads to an agent. `seo-aeo`'s `verify-token` has no counterpart here.

## Quotas, the cache and a 202

- **ora allows 10 requests a minute and 30 scans a day per IP.** GitHub-hosted runners share IPs,
  so the daily quota can be someone else's. The action sends only `url`: never `force` (6 a day) and
  never `ephemeral` (refused for a domain ora already stores). A stored result younger than 6 h comes
  back as is and costs nothing.
- **A 429** with a short `Retry-After` (60 s or less: the burst cap) is retried once. Otherwise the
  action reads ora's last stored result (`GET /api/score/<domain>?format=audit`) and labels it as
  such, with its age. A domain ora has never scanned, rate-limited, is could-not-look.
- **A 202** means scored, deeper analysis still running. The action polls the stored result every
  20 s for up to 4 min. That GET is served through a CDN that caches a 200 for an hour, so an answer
  OLDER than the scan in hand is a cached copy of an earlier scan and is ignored. At the deadline the
  report says the score may still move. This path is exercised offline only: no live 202 has been
  observed yet.
- **isitagentready** answers a POST with the finished scan; nothing is polled.

## A scanner that could not look

A network error, a timeout (120 s per request), a body over 5 MB, an HTTP status other than 200
(202 for ora), a body that is not JSON, or JSON without the score/level is **could not look**: named
on its own line as "not a verdict about the site", its outputs left empty, the other scanner still
reported. Every scanner string (check ids, recommendations, level names, error messages) is
sanitised before it reaches the log or the summary: no workflow command, table cell, HTML or link
can be planted. A fault in the action itself is reported as `❌ agent-benchmark crashed: …` and
still exits 0.

## Lighthouse, by hand

Lighthouse 13.5 has an `agentic-browsing` category (agent-accessibility-tree, the three WebMCP
audits, cumulative-layout-shift, llms-txt, ard-schema). It is not a leg of this action: a pinned
`lighthouse` lock is about 150 packages under osv and `deps-currency` for good, and the WebMCP audits
need Chrome flags a stock runner does not set. Run it locally when the WebMCP layer is being built:

```bash
npx lighthouse@13.5.0 https://www.example.com/ --only-categories=agentic-browsing --view
```

## Self-test

`node agent-benchmark/scripts/selftest.mjs` (no network) stands both scanners up on 127.0.0.1 and
runs the real `benchmark.mjs` against them (the bases and the poll timing are env-overridable for
exactly this; `action.yml` passes none of them). It asserts what reaches the job log, the step
summary, `GITHUB_OUTPUT` and the JSON for a complete scan, a cache-served one, a 202 polled to
completion, a CDN copy older than the scan in hand, a stuck analysis, the 429 paths, every
could-not-look shape, hostile scanner strings, the input switches and URL clean-up, unwritable
sinks, and the `action.yml` → script wiring; and that every case exits 0. 27 targeted mutants of
`benchmark.mjs` each turn it red. CI runs it, then a live
smoke run against lampakia (`.github/workflows/agent-benchmark-selftest.yml`).

## Implementation

`scripts/benchmark.mjs` — the whole action: node's own `fetch`, no npm dependency. `action.yml`
runs it in one composite step and maps its four outputs.
