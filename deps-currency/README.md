# deps-currency

The **TIME-axis** dependency check for the `mvalasis/*` fleet — the scheduled complement to
`security-baseline`'s diff-scoped osv. `security-baseline` answers *"did THIS change introduce a
vuln?"* on every PR/push; `deps-currency` answers *"is the committed dependency tree carrying a
known-vuln or abandoned dep RIGHT NOW?"* on a schedule — scanning the **full** committed lockfiles,
not a diff. Because advisories land **after** code does (a CVE is published against a version you
already shipped), a diff gate alone can never catch them; this sweep does.

**Report-mode-first:** `fail-on-vuln` defaults **false**, so wiring a caller never newly-blocks a
green repo. It surfaces findings in the job summary and a tracking issue; a caller flips to
blocking only after it has cleared its backlog.

## What it does

- Discovers the **full committed lockfiles** under `working-directory` (recursively, skipping
  `node_modules` / `vendor` / `dist` / `.git`): npm (`package-lock.json`, `pnpm-lock.yaml`,
  `npm-shrinkwrap.json`, `yarn.lock`, `bun.lock(b)`) and composer (`composer.lock`).
- Runs **osv-scanner** (`scan source --recursive`) over them — the **same tool**
  `security-baseline` uses, here over the WHOLE tree rather than the diff.
- Buckets each advisory by CVSS (`CRITICAL ≥9 · HIGH ≥7 · MODERATE ≥4 · LOW >0`; **no CVSS →
  HIGH**, conservative) and filters against a **severity floor**.
- Also flags **unpinned third-party GitHub Actions that consume secrets** — a step that `uses:` an
  `owner/repo@<mutable-tag>` (not a 40-hex SHA) *and* references `secrets.*` in the same workflow.
  A mutable tag can be re-pointed upstream at code that exfiltrates the secret — a time-axis
  supply-chain risk that belongs in a currency sweep. **WARN-only — never blocks.**
- Renders one report to the job summary, and (if `manage-issue`) opens/updates a single
  **`deps-currency: dependency advisories`** tracking issue, auto-closing it when the next run is
  clean — the same issue lifecycle as `linkcheck`.
- Exits non-zero **only** when `fail-on-vuln: true` **and** an advisory at/above the floor exists.

## Use it — on a SCHEDULE (this is a cron action)

This action is meant to run on a **scheduled cron**, not per-PR (that's `security-baseline`'s job).
Pick an **off-peak** slot. **Stagger across hulk siblings** (epn, hlektrologos, prevedourou-wp share
one origin box — but note this action does NOT hit the WP origin; the only network is osv.dev, so the
stagger here is purely to avoid bunching GitHub-Actions minutes / issue churn, far softer than
`linkcheck`'s crawl-load concern — see HULK.md §7). lux is on Kinsta (its own origin); CF-Pages
Astro callers (lampakia, prevedourougr) are independent.

```yaml
# .github/workflows/deps-currency.yml
name: deps-currency
on:
  schedule: [{ cron: '0 4 * * 1' }]      # pick your own off-peak slot; stagger vs hulk siblings
  workflow_dispatch: {}
concurrency: { group: deps-currency, cancel-in-progress: true }
permissions:
  contents: read
  issues: write                          # only if manage-issue (default) is on
jobs:
  deps:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: mvalasis/ci-actions/deps-currency@v1
        with:
          severity-floor: HIGH           # CRITICAL | HIGH | MODERATE | LOW
          # ecosystems: 'npm composer'   # default 'auto' (detect by lockfile presence)
          # fail-on-vuln: 'false'        # default false (report-only); flip after backlog clears
```

> **`@v1`, never `@main`** — see the root [`README.md`](../README.md) §Versioning. A normal release
> is one tag move, not a commit in any caller.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `working-directory` | `.` | Directory scanned recursively (skips `node_modules`/`vendor`/`dist`/`.git`). |
| `ecosystems` | `auto` | `auto` (enable npm/composer by lockfile presence) or an explicit `npm`/`composer`/`"npm composer"`. Unknown values are reported + ignored. |
| `severity-floor` | `HIGH` | Minimum advisory severity that counts toward the issue / optional block (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`; CVSS-bucketed, no-CVSS → HIGH). |
| `manage-issue` | `true` | Open/auto-close the `deps-currency: dependency advisories` issue (needs `issues: write`). |
| `fail-on-vuln` | `false` | `true` = BLOCK when a ≥floor advisory exists. Default `false` (report-only). Unpinned-action advisories never block regardless. |
| `issue-title` | `deps-currency: dependency advisories` | Stable title so the same issue is reused / closed. |
| `osv-version` | `v2.4.0` | Pinned osv-scanner release (mirrors `security-baseline`). |

## Report-mode-first → flip to blocking

Wire it report-only first (the default). Once a repo's tracking issue is clean (or only carries
advisories you've consciously accepted), raise the gate for **that** caller:

```yaml
with:
  severity-floor: CRITICAL    # block only on the worst
  fail-on-vuln: 'true'
```

`fail-on-vuln` is per-caller, so one repo can enforce while the shared default stays conservative —
the same ratchet pattern as `security-baseline`'s `critical-checks`.

## Sovereignty — honest egress enumeration

The selling point is air-gapped, EU-runner-safe operation. To be precise rather than overclaim
"zero egress": **your lockfile body NEVER leaves the runner.** What *does* leave, and how to remove
it (mirrors `security-baseline`'s SCA honesty):

| Egress | What is sent | Remove it by |
|---|---|---|
| osv-scanner release download | nothing of yours — fetching the tool at install | mirror the binary on a self-hosted runner |
| osv-scanner scan | package **coordinates** (`name@version`) to **osv.dev** — never your lockfile body or source | run with an offline OSV DB on a self-hosted runner (roadmap) |
| `gh issue` ops | the issue body is **your own report** (already-redacted advisory ids + package names), on `github.token` | `manage-issue: 'false'` |
| unpinned-action scan | nothing — a **local text scan** of `.github/workflows/*` | — (already offline) |

## Honest limits

- **No reachability.** osv-scanner is present-in-tree, not exploitable-in-tree — there is no
  dataflow-reachability (a Pro/cloud feature, air-gap-forbidden). A dep CVE means "present", not
  "exploitable" — the report says so.
- **WordPress.org plugin CVEs are out of scope** (same as `security-baseline`) — osv.dev does not
  index WP plugin versions; that needs WPScan/Patchstack (paid + plugin-inventory egress). This
  covers composer/npm/pnpm transitive deps only.
- **Abandoned/unmaintained** detection is best-effort — surfaced when an advisory id carries a
  `MAL-`/`UNMAINTAINED` marker; it is additive report context, not a separate gate.
- **Unpinned-action scan is file-level**, not step-level dataflow: it flags an unpinned third-party
  `uses:` when *any* `secrets.*` appears in the **same** workflow file (conservative — it can
  over-report within a file, never across files). First-party `actions/*` / `github/*`, local
  `./...`, `docker://`, and SHA-pinned refs are excluded.
- **This is the time-axis half of SCA.** The diff-scoped half ("did this PR add a vuln?") stays in
  `security-baseline`. Run both: the diff gate on every PR, this sweep on a cron.

## Self-test

`node scripts/selftest.mjs` — **offline**, network-free regression guard. Feeds a saved
osv-scanner JSON fixture (one CRITICAL, one LOW, one MODERATE) + workflow-text fixtures to the pure
engine and asserts: CVSS→bucket mapping, severity-floor filtering, the issue open/close decision
(open on findings, close when clean), the block decision (`fail-on-vuln`, report-mode-first), the
unpinned-secret-consuming-action detection, and the report-spoofing/disclosure guard. No network,
no osv-scanner, no `gh` — the parse/filter/decision engine only (like `security-baseline`'s
`selftest.mjs`). Runs in CI on `deps-currency/**`.

## Implementation

`scripts/engine.mjs` — pure, network-free engine (CVSS bucketing, floor filter, issue/block
decisions, unpinned-action text scan, spoof-safe report rendering; unit-tested by `selftest.mjs`).
`scripts/scan.mjs` — CLI: discovers lockfiles, runs osv-scanner over the full tree, normalizes its
output into findings, filters + decides via the engine, renders to `GITHUB_STEP_SUMMARY`, manages
the tracking issue, exits non-zero only on a ≥floor advisory under `fail-on-vuln`. **Zero npm
dependencies** (pure Node 22). osv-scanner is a pinned binary installed in `action.yml`.
