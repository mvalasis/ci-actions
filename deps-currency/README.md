# deps-currency

The **TIME-axis** dependency check for the fleet — the scheduled complement to
`security-baseline`'s diff-scoped osv. (Deliberately no owner glob here: the callers span two
GitHub owners since the 2026-08 split, and the set is resolved at runtime, not written down —
see §Who counts as "first-party".) `security-baseline` answers *"did THIS change introduce a
vuln?"* on every PR/push; `deps-currency` answers *"is the committed dependency tree carrying a
known-vuln or abandoned dep RIGHT NOW?"* on a schedule — scanning the **full** committed lockfiles,
not a diff. Because advisories land **after** code does (a CVE is published against a version you
already shipped), a diff gate alone can never catch them; this sweep does.

**Report-mode-first:** `fail-on-vuln` defaults **false**, so wiring a caller never newly-blocks a
green repo. It surfaces findings in the job log, the job summary and a tracking issue; a caller flips to
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
  supply-chain risk that belongs in a currency sweep. **WARN-only — never blocks.** *Third-party*
  means "outside the **first-party owner set**" — see below; our own `@v1`-pinned shared actions are
  first-party by policy and are not flagged.
- Renders one report to the job log and the job summary (see
  [Where to read the result](#where-to-read-the-result--job-log-annotations-step-summary)), and (if
  `manage-issue`) opens/updates a single
  **`deps-currency: dependency advisories`** tracking issue, auto-closing it when the next run is
  clean — the same issue lifecycle as `linkcheck`. What happened to the issue (opened, updated,
  closed, or the error that stopped it) follows the report in both places; a run that cannot look
  the open issue up opens, updates and closes nothing.
- Exits non-zero **only** when `fail-on-vuln: true` **and** an advisory at/above the floor exists.
- **A scanner fault is not a finding.** If the scan itself crashes, the report says so
  (`❌ deps-currency crashed: …` in the job log and the job summary) and the exit code follows the same
  report-mode-first rule: **0** under the default, **1** only under `fail-on-vuln: true`. A broken
  scanner therefore never newly-blocks a report-mode caller — matching every sibling action. (This
  guard was dead code from the action's first commit until 2026-08-05: it was registered *below* the
  `main()` IIFE, which exits, so it never ran. `.github/workflows/lint.yml` now blocks that ordering
  statically, and `scripts/selftest.mjs` asserts it by crashing the real scanner.)

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
| `manage-issue` | `true` | Open/auto-close the `deps-currency: dependency advisories` issue (needs `issues: write`). A failed issue call never fails the run; the `ℹ️ issue lifecycle` block after the report says what happened. |
| `fail-on-vuln` | `false` | `true` = BLOCK when a ≥floor advisory exists. Default `false` (report-only). Unpinned-action advisories never block regardless. |
| `issue-title` | `deps-currency: dependency advisories` | Stable title so the same issue is reused / closed. |
| `osv-version` | `v2.4.0` | Pinned osv-scanner release (mirrors `security-baseline`). |
| `first-party-owners` | *(empty)* | **Extra** owners to treat as first-party in the unpinned-action scan, space/comma separated. The caller's owner and this action's own owner are already included — see below. Only needed for a third account you also control. |

## Who counts as "first-party" (the owner set)

The unpinned-action scan exempts `actions/*`, `github/*`, and every owner in the **first-party owner
set**, which is the union of:

1. the **caller's** owner — from `github.repository`;
2. **this action's own** owner — from `github.action_repository` (`mvalasis`, for `mvalasis/ci-actions`);
3. anything listed in **`first-party-owners`**.

Owners are matched case-insensitively. The report prints the resolved set, so an unexpected row can
be diagnosed without re-deriving it by hand.

> **Why (2) exists.** It used to be (1) alone — "first-party == whoever owns the caller" — which held
> only while one account owned everything. In **2026-08** 11 repos moved from the personal account
> `mvalasis` into the org `creme-ypsilon` while `mvalasis/ci-actions` stayed put, and every
> `mvalasis/ci-actions/<action>@v1` ref in an org-owned caller immediately read as an unpinned
> *third-party* action: `lampakia-astro` 2 → 6 rows, `prevedourougr` 2 → 5. Nothing blocked (this
> signal is WARN-only), but the tracking issue only auto-closes at **zero** advisories, so the noise
> would have pinned it open forever — and an issue that can never close is a signal people stop
> reading. Deriving trust from the *caller's* owner is the bug; the action's own owner is the fix.

For a **local `./` invocation** (this repo's own selftest workflows) `github.action_repository` is
empty; it then contributes nothing and the set degrades to the caller's owner — it never becomes an
empty owner that would match everything.

The action's own owner is read from **two** sources — `${{ github.action_repository }}`, passed by
`action.yml` as `ACTION_REPOSITORY`, and the runner's ambient `GITHUB_ACTION_REPOSITORY` as the
fallback. They mean the same thing, but GitHub documents that meaning only as *"for a step executing
an action, the owner and repository name of the action"* — it says nothing about whether either is
populated inside a **composite** action's own steps, which is the only shape this action ever runs
in. `action.yml` therefore avoids the `GITHUB_`-prefixed name on purpose: writing the context value
there would shadow the runner's copy and stake the fix on a single undocumented behaviour, failing
silently (a shorter owner list on a weekly cron) if it were wrong. Reading both can only add an
owner, never remove one.

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

## Where to read the result — job log, annotations, step summary

Since **v1.18.0** the report is in three places, so a scheduled run's findings never need a browser:

- **Job log** — the whole report, the same lines as the step summary, byte for byte:
  `gh run view <run-id> --log-failed` (or `--log`). Before v1.18.0 the log carried none of it.
- **Annotations** — one per advisory at/above the floor (exactly what `fail-on-vuln` blocks on), at
  the end of the log: `::error file=<lockfile>,title=deps-currency <SEVERITY>::<SEVERITY>
  <package>@<version> <advisory ids> at <lockfile>`. `<lockfile>` is relative to the workspace (the
  repository root) — osv-scanner reports absolute runner paths, and `file=` means a file of your
  repo — and a lockfile outside the workspace gets no `file=`. No `line=`: osv-scanner reports none.
  `gh run view <run-id>` lists them under ANNOTATIONS; the API has them at
  `gh api repos/<owner>/<repo>/check-runs/<job-id>/annotations`. Report-mode (the default,
  `fail-on-vuln: false`) annotates at `::warning`; `fail-on-vuln: true` at `::error`. GitHub keeps
  10 per step; past that, one log line counts the rest (the report lists every advisory either way).
  Below-floor advisories and unpinned-action advisories are never annotated.
- **Step summary** — unchanged: the same report, rendered.
- **Issue lifecycle** — with `manage-issue` on, a `### ℹ️ issue lifecycle` block follows the report
  in the job log and the step summary, before the annotations: `opened tracking issue`,
  `updated tracking issue #N`, `closed tracking issue #N — the sweep is clean`, or what stopped it,
  with gh's own error — `failed to open tracking issue: …` carrying GitHub's 403 *Resource not
  accessible by integration* when the workflow lacks `permissions: issues: write`. A failed issue
  call never changes the exit code. Before v1.18.1 these lines were computed but never printed: a
  workflow without `issues: write` got a green run, no issue, and no word why.
- **A failed issue lookup leaves the issue alone.** Each run first finds the open issue with `gh
  issue list`. If gh refuses (a 403, an outage) or prints no JSON list, the block reads `failed to
  look up the tracking issue: <gh's error> — nothing opened or updated` after a dirty sweep, or
  `… — nothing closed` after a clean one, and the run touches no issue. A clean sweep cannot close
  an issue whose number it did not get. A dirty one could still open one, and deliberately does
  not: with an issue already open that is a duplicate, and a lookup that keeps failing would open
  another on every dirty run, none of which a clean run could find to close. A transient failure
  therefore costs one run — whose report and annotations still carry every advisory — and the next
  run (or a `workflow_dispatch` re-run) looks again; a persistent one says so on every run. Before
  v1.19.2 a failed lookup read as "no issue open": a clean sweep left the issue open without a
  word, and a dirty one went on to create one, a duplicate whenever an issue was open and the
  create went through. `linkcheck` already stopped there: its lookup runs under
  `bash -eo pipefail`, so a failed `gh issue list` ends the step before it creates or closes.

Tool output never reaches the start of a log line, where the runner would read it as a workflow
command: every osv-scanner string (a package name, a version, an advisory id, a path) and gh's
error text goes through `safe()`, which strips CR/LF and the markdown and bracket characters, and
every report line starts with the action's own text. The one bracket `safe()` writes back, in its
`[:]//` URL defang, can spell `##[:]`, which the runner's legacy `##[…]` parser reads as a command
named `:` — none exists.
Annotation values are escaped (`%`, CR, LF, and `:`/`,` in properties), so a hostile path cannot
rewrite one. Off Actions (a local run) the report prints once to stdout, with no annotations.

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
  over-report within a file, never across files). `actions/*` / `github/*`, every owner in the
  [first-party owner set](#who-counts-as-first-party-the-owner-set), local `./...`, `docker://`, and
  SHA-pinned refs are excluded. The exemption is by **owner**, not by ref: a first-party owner's
  action is trusted at whatever tag it is pinned to, which is the deliberate trade for the fleet's
  floating-`@v1` policy.
- **This is the time-axis half of SCA.** The diff-scoped half ("did this PR add a vuln?") stays in
  `security-baseline`. Run both: the diff gate on every PR, this sweep on a cron.

## Self-test

`node scripts/selftest.mjs` — **offline**, network-free regression guard. Feeds a saved
osv-scanner JSON fixture (one CRITICAL, one LOW, one MODERATE) + workflow-text fixtures to the pure
engine and asserts: CVSS→bucket mapping, severity-floor filtering, the issue open/close decision
(open on findings, close when clean), the block decision (`fail-on-vuln`, report-mode-first), the
unpinned-secret-consuming-action detection, the **first-party owner-set derivation** (caller ∪
action ∪ declared extras, empty-`action_repository` fallback, case-insensitivity), and the
report-spoofing/disclosure guard. It also runs `scan.mjs` **end-to-end** with a synthetic env and
stub `osv-scanner`/`gh` paths — still offline — because the owner-set unit tests cannot see a name
drift between `action.yml`'s `env:` block and the keys `scan.mjs` reads, and that drift alone would
restore the 2026-08 defect with every other assertion green. A second **end-to-end** leg runs
`scan.mjs` against a stub `osv-scanner` that answers, as v2 does, with absolute paths — one advisory
planting a workflow command in its package name, one outside the workspace, one below the floor —
and asserts the job log carries the whole report byte for byte, one annotation per at/above-floor
advisory with a workspace-relative `file=` (none for the LOW or the unpinned action, none outside
the workspace), no planted command at the start of a line, a local run printing once with no
commands (stdout a socket, as node's child_process gives it — the case that crashed the old
`appendFileSync('/dev/stdout')` fallback on Linux), report-mode annotating as `::warning`, and an
unwritable summary still reaching the log under the caller's exit setting. 23 targeted mutants each
turn it red. The same leg then drives the tracking issue through a stub `gh`: opened, updated and
closed, each also refused with a 403 whose second line plants a workflow command; the lookup
itself refused after a dirty and after a clean sweep, and answered with no JSON list, each with an
issue open; plus no `gh`, no `GITHUB_REPOSITORY`, and a clean run with nothing to close. Each note
must reach the log and the summary exactly once, after the report and before the annotations, with
the report byte-identical to a `manage-issue: false` run, the same exit code and no new
command-shaped line, and each row pins the `gh` verbs the run called: a failed lookup must stop at
`list`. A summary made unwritable while the issue opens must still leave the block in the log. 16
targeted mutants turn that part red, and 16 more the lookup rows and the verb column; two of those,
a `create` after the lookup note and a close without its resolving comment, only the verb column
catches. Dropping one of the two `safe()` passes a note goes through is equivalent (the other still
flattens it). Runs in CI on `deps-currency/**`.

> The owner-set fixtures deliberately use **different** literals for the caller's owner and the
> action's owner (`creme-ypsilon` vs `mvalasis`). The original fixture used the same literal for
> both, so it passed no matter which one the engine consulted — which is exactly why it stayed green
> through the ownership split. When a fixture models a relationship between two values, the two
> values have to differ.

## Implementation

`scripts/engine.mjs` — pure, network-free engine (CVSS bucketing, floor filter, issue/block
decisions, first-party owner-set resolution, unpinned-action text scan, spoof-safe report rendering;
unit-tested by `selftest.mjs`).
`scripts/scan.mjs` — CLI: discovers lockfiles, runs osv-scanner over the full tree, normalizes its
output into findings, filters + decides via the engine, renders to `GITHUB_STEP_SUMMARY` and the
job log, manages the tracking issue and reports the outcome to both, annotates each ≥floor advisory
(`annotations()` in `engine.mjs`),
exits non-zero only on a ≥floor advisory under `fail-on-vuln`. **Zero npm
dependencies** (pure Node 22). osv-scanner is a pinned binary installed in `action.yml`.
