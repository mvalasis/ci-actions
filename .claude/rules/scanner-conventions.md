---
paths:
  - "*/scripts/*.mjs"
  - "*/scripts/*.py"
  - "*/scripts/*.sh"
---
# Scanner entrypoint conventions

A fault in an entrypoint's own tooling is a fault in the gate, never a finding about the
caller's site. Report it as a fault and exit `FAIL_ON_<X> ? 1 : 0` — a bug here must never
newly-block a report-mode caller, and must never be laundered into a verdict about their code.

**Arm a crash guard before any statement that can fault**, and read the enforcement setting
from the environment, never from program state:

| language | guard | why the env read matters |
| --- | --- | --- |
| `.mjs` | `process.on('uncaughtException'/'unhandledRejection', …)` hoisted above the main invocation | a crash during const init leaves module consts in the temporal dead zone — reading one inside the handler throws `ReferenceError`, which loses the diagnostic and the exit code together (node then exits 7) |
| `.py` | `try/except` around `main()` under `if __name__` | `SystemExit` is not an `Exception`, so a deliberate verdict exit is never relabelled a crash |
| `.sh` | `trap … EXIT` on the first executable line, paired with a sentinel a deliberate exit sets | never `trap … ERR`: `set -u` aborts *without* firing `ERR`, and with errexit off `ERR` fires on non-fault commands too |

**Exempting an entrypoint from the guard is judged by misattribution, not by the exit code.**
An entrypoint with no report-mode input can still skip the guard when its own wrapper already
reports a failure for what it is; conversely, guard an entrypoint even with no report-mode input
the moment a bare wrapper failure would misattribute the fault to the caller (e.g. open an issue
blaming their site for a crawl that never ran). Mark a deliberate exemption with
`lint-allow-no-crash-guard: <reason>` (`#` in `.py`/`.sh`, `//` in `.mjs`) on the entrypoint — a
reason is required, and a bare pragma does not count.

**One level down: a scanner that could not look is not a PASS.** A crash guard only covers the
entrypoint itself dying. Anything that shells out to a scanner must also read that scanner's exit
status and report shape — "it printed nothing" and "it found nothing" look identical to a JSON
parser. Classify every run as *looked* or *could-not-look*, and grade a could-not-look leg as a
fault under the same `FAIL_ON_<X> ? 1 : 0` rule whenever that leg could have produced a blocking
finding (a WARN-only leg that could not look is listed, never treated as a fault).

**Every git path listing reads `-z`** (`diff --name-only`, `ls-files`, `grep -l`), split on `\0`.
Without it git's default `core.quotePath` C-quotes a non-ASCII path, `"app/\317\203….php"`: no
extension test matches and no file exists by that name, so the leg drops it and still passes
(v1.24.2). A new leg with its own listing also joins the Greek-path case in
`security-baseline/scripts/selftest.mjs` (a Greek-named file it must grade), as `wp-rest-gate-case`
did in v1.25.0.

**Output that grows with the caller's site is capped below GitHub's limits.** A step summary over
1 MiB is dropped (the upload fails with an error annotation, so the run shows none), and an issue
or comment body over 65,536 characters is refused. A report with one row per page or per finding
gets a byte cap: whole rows, worst first, the verdict line kept, then how many rows were left out
and the run URL; under the cap it stays byte-identical. Pin the cap with an executed selftest at
exactly the cap and one byte over. Current implementations: `linkcheck/scripts/fit-report.py`
(issue body at 60,000 bytes since v1.29.2, step summary at 900,000 since v1.29.3),
`deps-currency/scripts/engine.mjs` `capIssueBody()` (issue body at 60,000 bytes since v1.29.4)
and `capSummary()` (step summary at 900,000 since v1.29.6), and `fitReport()` in
`seo-aeo/scripts/checks.mjs`, `form-protection/scripts/checks.mjs` and
`verify-homepage/scripts/ux-report.mjs` (step summary at 900,000 since v1.29.6), and
`test-suite/scripts/detect.mjs` (step summary at 900,000 since v1.29.9: the `isolate-files` table
has a row per test file that fails alone, ≤99 files on any caller today, unbounded by its code).
The other six are bounded by construction and stay uncapped (the latest run on each of the 13
callers, 2026-10-12): `a11y-audit` a fixed ~6 lines (pa11y-ci's per-URL output goes to the log
only), `pull-tier` one line, `latin-urls` at most 20 rows and a `…and N more` row × 3 audits,
`security-baseline` at most 15 rows per check id × the 40 ids a scanner emits (≤3 KB on every
caller), `contract-check` rows bounded by the caller's manifest, a response checked on its first
item only, × `max-endpoints` 25 (≤2.7 KB), `agent-benchmark` one URL and a table of at most 80
rows (14.8 KB). A bound that grows with the code gets a selftest that renders its worst case and
holds it under 900,000: `security-baseline`'s `reportBody()` in `tiers.mjs`, every emittable id
at `safe()`'s caps (883,556 bytes at v1.30.0, the two trufflehog legs carrying their 20-line log; each
new id adds ~20.3 KB, so the next fails it: lower a cap first).

**A path the report names is relative to the workspace, as an annotation's `file=` is** — never
the scanner's own spelling. osv-scanner v2 prints each lockfile by its absolute runner path, and a
60-character report cell cut `/home/runner/work/<r>/<r>/apps/web/package-lock.json` to
`…/apps/web/pac` until v1.29.5. Locate each finding once with `repoRelative()`
(`deps-currency/scripts/engine.mjs`) and hand that one path to both the table and the annotation;
a path outside the workspace keeps the tool's own spelling. Resolve the workspace's symlinks before
comparing: osv prints real paths, and an unresolved workspace holds none of them. Current
implementations: `security-baseline/scripts/scan.mjs` `collectOsv()` (since v1.29.7, with
`repoRelative()` restated in `tiers.mjs` so the action stays dependency-free; its selftest holds the
two copies to the same answers) and `deps-currency/scripts/scan.mjs` (since v1.29.5; its workspace
and working directory resolved since v1.29.7).

**Known limit, not papered over:** for bash the crash-guard check matches any `trap … EXIT`, so a
pure cleanup trap reads as a guard. A behavioural self-test that actually crashes the real
entrypoint — not a static check — is what proves the guard fires. Mutation-test every new
self-test assertion: revert the fix (or neuter the condition) and confirm the assertion goes red;
one that survives its own bug reintroduced is worthless.

Mechanized (rules 2–3 of five) in `.github/scripts/lint-entrypoint-output.mjs`, scoped to the
scripts an `action.yml` actually executes.
