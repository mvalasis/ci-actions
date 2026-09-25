# security-baseline

Air-gapped **security gate** for the fleet — the one CI check that **blocks on
every repo** (the callers span two GitHub owners since the 2026-08 split, so this line names
none; ownership is resolved at runtime — see §First-party ownership). Rebuilt from a 2-tool script (semgrep + gitleaks) into a **tiered** gate that adds
verified-live secrets, dependency/SCA, custom WordPress & Astro/TS rules, and GitHub-Actions
supply-chain auditing — while keeping the **blocking core tiny** so a strict upgrade never
newly-blocks a currently-green repo. **No source ever leaves the runner** (see §Sovereignty for
the exact, opt-out-able egress).

## Severity model — tiny CRITICAL core, deep WARN coverage

Like `seo-aeo`, the model is **T0/T1/T2 + per-caller promotion**. Unlike `seo-aeo`, it is
**BLOCK-BY-DEFAULT** — this is the fleet's always-on gate, so turning it report-only would
silently un-enforce every repo.

| Tier | Behaviour | Checks |
|---|---|---|
| **T0 — CRITICAL** | always blocks (when `fail-on-critical`, the default) | `sast-critical` (semgrep community ERROR on the diff — *today's block, unchanged*); `secret-pattern` (gitleaks pattern on the diff — *today's block, unchanged*); `secret-verified` (trufflehog `--only-verified` on the **diff range** — NEW; a provider just authenticated it → ~zero FP) |
| **T1 — promotable WARN** | reports; a caller ELEVATES any id to CRITICAL via `critical-checks` | `sca-critical`, `sca-high` (osv-scanner); the custom **WP/PHP** rules (`wp-nonce-missing`, `wp-cap-missing`, `wp-sql-unprepared`, `wp-unserialize`, `wp-file-include`, `wp-rest-error-detail`, `wp-rest-error-detail-laundered`, `wp-weak-crypto`, `turnstile-test-key`); the custom **Astro/TS/RN** rules (`ts-dangerous-html`, `ts-eval`, `ts-child-process`, `ts-public-secret-leak`, `ts-ssrf`, `ts-open-redirect`, `ts-secret-in-log`, `rn-insecure-storage`, `rn-cleartext-http`); the **GitHub-Actions** rules (`gha-unpinned-action`, `gha-script-injection`, `gha-pr-target`); `dockerfile-lint`; `argv-secret` (a secret spelled into a child's argv — §argv-secret) |
| **T2 — advisory** | reports (WARN/INFO); never promotable | `sca-moderate`/`sca-low` (INFO); `wp-unescaped-output` (syntactic XSS — too FP-heavy to promote); `wp-rest-wp-error-detail` (`WP_Error::get_error_message()` in a REST/AJAX body — usually the *intended* client message, so advisory-only); `ts-cors-wildcard`; `secrets-history` (full-history baseline — clearing needs a history rewrite, so it can **never** be a merge precondition) |

The CRITICAL core is exactly what a clean repo always passes; **a failure there is always a real
defect.** Everything else is real signal but site-/dependency-/editorial-variable, so it
**surfaces as WARN** and never blocks a shared deploy. The default `critical-checks` is empty,
so **adding a new check or moving `@v1` can never newly-block a caller** — proven against all
8 repos (CRITICAL = 0 on every one).

> **`secret-verified` is the only ADDED blocking signal, and it is safe by construction.** It is
> scoped to the diff range (`--since-commit`), so it fires only on a **newly-committed** live
> credential — never on pre-existing state — and a verified hit is a true positive (the
> credential's own provider authenticated it). It does **not** replace the gitleaks pattern floor
> (which still blocks unverifiable shapes like a private key or a dead-host DB string).

## Use it

```yaml
# .github/workflows/security-baseline.yml
name: security-baseline
on:
  pull_request:
  push: { branches: [main] }
  workflow_dispatch: {}
permissions: { contents: read }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }       # diff scope + history secrets need git history
      - uses: mvalasis/ci-actions/security-baseline@v1
        with:
          scan-scope: diff               # changed files vs base-ref
          semgrep-severity: ERROR        # community-rule block severity
          # critical-checks: 'sca-critical,wp-sql-unprepared'   # opt-in stricter, per caller
          # verified-secrets: off        # fully air-gapped runner (no provider probe)
```

The 8 existing callers pass only `scan-scope: diff` + `semgrep-severity: ERROR` — **the rebuild
keeps those working with zero edits**; the new WARN tiers ride along automatically.

## Inputs

| Input | Default | Notes |
|---|---|---|
| `scan-scope` | `diff` | `diff` (changed files vs base) or `full` (whole tree). Keep `diff` — `full` re-scans vendored WP core / deps and can newly-block. |
| `base-ref` | _(auto)_ | PR base → push `event.before` (full pushed range) → `HEAD~1`. |
| `fail-on-critical` | `true` | `true` = BLOCK on any CRITICAL (T0 or a promoted T1), and FAULT when a scanner leg that could have found one could not look (§When a scanner cannot look). |
| `critical-checks` | `''` | Comma/space list of **T1** ids to elevate to CRITICAL for **this** caller. T0 ids are already critical; T2/unknown ids are reported and ignored. |
| `first-party-owners` | `''` | **Extra** owners exempt from `gha-unpinned-action`. Already exempt with no config: `actions`/`github`, the caller's own owner, and **this action's own owner**. Only needed for a *third* owner (a second org whose actions you also control). |
| `report-mode` | `false` | Onboarding escape hatch: report even T0 without blocking (loud banner). Must stay `false` for an enforcing caller. Pair with `report-mode-reason`. |
| `semgrep-config` | `p/security-audit` | Community SAST ruleset (registry id or a vendored local path for full air-gap). The custom rule packs are always vendored-local. |
| `semgrep-severity` | `ERROR` | Community-rule severity that blocks. |
| `verified-secrets` | `auto` | `auto`/`on` = trufflehog `--only-verified` (provider test-auth egress); `off` = air-gap mode (gitleaks pattern floor still blocks), and the way to run without trufflehog. |
| `enable-sca` | `true` | osv-scanner dependency audit (WARN; package-coordinate egress to osv.dev). `false` runs without osv-scanner. |
| `enable-secrets-history` | `true` | Full-history secret baseline (WARN). Set `false` on huge repos to save CI minutes. |
| `*-version` | _(pinned)_ | `gitleaks` / `trufflehog` / `osv` / `hadolint` / `semgrep` release pins. |

## Promoting checks per-caller (without forking)

```yaml
with:
  fail-on-critical: 'true'
  critical-checks: 'sca-critical,wp-sql-unprepared,wp-rest-error-detail,gha-unpinned-action'
```

A caller that has eyeballed a clean run ratchets up its own gate while the shared default stays
conservative. A report-mode caller can **rehearse** a strict posture (`critical-checks` +
`fail-on-critical: false`) to see what *would* block, at zero risk. Only the **T1** ids are
promotable; the CRITICAL core is always on and cannot be disabled.

## Where to read the result — job log, annotations, step summary

Since **v1.16.0** the report is in three places, so "why did it block?" never needs a browser:

- **Job log** — the whole report, the same lines as the step summary, byte for byte:
  `gh run view <run-id> --log-failed` (or `--log`). Before v1.16.0 the log said only
  `Process completed with exit code 1`.
- **Annotations** — one per CRITICAL (a T0, or a T1 you promoted), at the end of the log:
  `::error file=<path>,line=<n>,title=security-baseline <check>::<check> <rule> at <path>:<n>`.
  `gh run view <run-id>` lists them under ANNOTATIONS; the API has them at
  `gh api repos/<owner>/<repo>/check-runs/<job-id>/annotations`. A run that does not enforce
  (`report-mode`, `fail-on-critical: false`) annotates at `::warning` instead. GitHub keeps 10 per
  step; past that, one log line counts the rest (the report lists every finding either way). A
  WARN or INFO finding is never annotated. Since v1.19.0 a scanner leg that could not look, and
  could have blocked, gets one too, listed first:
  `::error title=security-baseline could not look::<leg> could not look — <why>`.
- **Step summary** — unchanged: the same report, rendered.

A secret finding names the commit it was found in: `generic-api-key **** in commit 2bc10a3`, and
` in commit 2bc10a3` on its annotation. gitleaks reads commit patches, so its `file:line` is the line
in that commit, which under `scan-scope: full` is often not the tip's.

No secret value reaches any of them. The log carries the summary's own lines: gitleaks runs with
`--redact` (a finding reads `generic-api-key ****`; if gitleaks ever returned the value anyway,
`redact()` would keep first4…last4), and trufflehog's raw credential is never read — a verified
secret is detector + `file:line`. An annotation names a secret by rule id only, never by its
message. Every tool-controlled string is `safe()`-stripped and every report line starts with
code-controlled text, so a hostile path cannot reach line-start and forge a workflow command;
annotation values are escaped (`%`, CR, LF, and `:`/`,` in properties) so it cannot rewrite one.
Off Actions (a local run) the report prints once to stdout, with no annotations.

## When a scanner cannot look — FAULT, not PASS

Since **v1.19.0** a scanner that failed is not a scanner that found nothing. Until then every
adapter read a failure as "no findings": semgrep's exit status and `errors[]` went unread, a
gitleaks run that died before writing its report parsed as `[]`, and a failed trufflehog or
osv-scanner run read as empty output. A registry outage for `p/security-audit`, a rule pack that
did not load or a gitleaks config it rejected all ended in **`PASS — no critical findings`** about
code nothing had scanned. Only "not installed" reached the report, as a note
under the same PASS.

`scripts/outcome.mjs` now answers three ways for every scanner run: it looked and found something,
it looked and found nothing, or it **could not look**:

| Scanner | Could not look |
|---|---|
| any | not installed; killed or timed out; output over the 64 MB cap; its collector crashed. A run of 10 s or more says how long it took: a registry stall leaves no other trace. |
| semgrep | exit 2 or higher, or 1 with no results (without `--error`, which this gate never passes, 1 is not "findings"); no JSON report; an `errors[]` entry at `level: "error"`: a rule or config that did not load, or semgrep's engine failing on a file (an AST builder or fatal error, which semgrep itself exits 2 for). A per-file `warn` (a file it could not fully parse or finish) is listed under scanner notes and is not a fault. |
| gitleaks | exit other than 0 (it runs with `--exit-code 0`); exit 0 with no report written; a report that is not a JSON array; no git history to read, checked before it runs, because outside a repository gitleaks exits 0 with `[]` |
| trufflehog | exit other than 0 — it runs with `--fail-on-scan-errors`, since without it a `--since-commit` it cannot resolve exits 0 having scanned nothing; a JSON result line cut short |
| osv-scanner | exit other than 0, 1 or 128 (128 = no package manifest in the tree, so nothing to audit); exit 1 with no results |
| hadolint | no JSON array; exit other than 0 or 1 (1 = a rule fired) |
| git | the diff that lists the changed files failed: a `base-ref` or PR base that does not resolve, which gitleaks would read as an empty range and exit 0 on; `git ls-files` failed |

Each failure belongs to a **leg** (one scanner pass: semgrep's community, rule-pack and GitHub-Actions
runs are three legs), and a leg is judged by the checks it could have found:

- **❌ it could have blocked**: a T0 leg (semgrep community SAST, gitleaks, trufflehog on the diff,
  the changed-file list), or a T1 leg with a check this caller promoted. The five callers that
  promote `wp-rest-error-detail` fault when the WP/PHP pack does not load. Under `fail-on-critical`
  (the default) the run **FAULTs**: exit 1, the verdict `FAULT — … No verdict: a tool fault in
  security-baseline, not a finding about this repository.`, and one `::error` annotation per leg.
  Under `report-mode` or `fail-on-critical: false` it exits 0, the verdict says it would FAULT, and
  the annotation is a `::warning`. A run that also has criticals is `BLOCKED` and names the legs.
- **⚠️ its checks only warn here**: listed the same way, never a fault. `PASS` stands and says how
  many legs could not look. A T2 leg (a history baseline) can never block, so it is always this kind.

A fault is never counted as a finding: the tally keeps `critical: N` and adds `· could not look: N`,
and "✅ no findings across …" prints only when every leg looked. To run without a scanner, say so:
`verified-secrets: off` (trufflehog), `enable-sca: false` (osv-scanner), `enable-secrets-history:
false`. A missing binary is a fault, not an opt-out. The reason quotes the tool's own error line
after `scrub()`: URL userinfo is dropped and any 20+-character run of letters and digits is cut to
first4…last4. trufflehog's stderr is never quoted, since a live credential must not reach the log
even redacted.

Measured on the pinned tools (semgrep 1.178.0, gitleaks 8.30.1, trufflehog 3.95.6, osv-scanner
2.4.0) before release, not taken from their docs: the gitleaks and trufflehog exit-0 cases above,
and semgrep's own shapes (a registry config that will not download exits 7 with the reason in
`errors[]`; no network exits 2 with no JSON at all; its exit code follows only the last error it
recorded, which is why `errors[]` is read in full).

## Sovereignty — honest egress enumeration

The gate's selling point is air-gapped, EU-runner-safe operation. To be precise rather than
overclaim "zero egress": **your repository source NEVER leaves the runner.** What *does* leave,
and how to remove it:

| Egress | What is sent | Remove it by |
|---|---|---|
| `pip install semgrep`, release downloads (gitleaks/trufflehog/osv/hadolint) | nothing of yours — fetching the tools at install | mirror the tools on a self-hosted runner |
| semgrep `p/security-audit` registry fetch | rule **definitions** (no code) | set `semgrep-config` to a vendored local path |
| **custom rule packs** (`rules/*.yaml`) | nothing — **vendored-local, zero fetch** | — (already offline) |
| trufflehog `--only-verified` | a **test-auth** to the credential's OWN provider (only when a candidate secret is found) | `verified-secrets: off` |
| osv-scanner | package **coordinates** (`name@version`) to osv.dev — never your lockfile body | (offline OSV DB — roadmap) |
| gitleaks / hadolint | nothing — self-contained binaries | — |

`SEMGREP_SEND_METRICS=off` + `--metrics=off` + `--disable-version-check`: no telemetry, no
update pings. trufflehog runs `--no-update`.

## Custom rule packs (vendored semgrep)

`rules/wp-php.yaml`, `rules/astro-ts.yaml`, `rules/gha.yaml` model the real vuln classes the
community pack barely covers. Each rule is `severity: WARNING` (never blocks at the ERROR cut),
carries a stable `metadata.checkId`, and is **FP-disciplined** against the real fleet:

- **WP/PHP** rules exclude committed `wp-admin/`/`wp-includes/`/`vendor/`/`*.phar`, require request
  data to reach a sink directly (low FP), and treat a guard call (`check_admin_referer`,
  `current_user_can`) in **any** position (statement, `if`, `||`) as present.
- **Astro/TS** rules match only **request/props-derived** / non-constant operands — a
  `set:html={JSON.stringify(schema)}`, a fixed-origin `fetch`, `createSecureStore()` do not fire.
  `child_process` is receiver-constrained so `RegExp.exec` doesn't false-fire. The
  `PUBLIC_*_SITE_KEY` (a Turnstile *site* key is public by design) is excluded.
- **GHA** rules audit the fleet's own CI: a third-party `uses:` not SHA-pinned, `github.event.*`
  in a `run:` block, the `pull_request_target` trigger. An action ref may carry **subdirectory
  segments** (`gradle/actions/setup-gradle@v4` is one action, not two path components); the
  original pattern stopped at `owner/repo@`, so every three-segment ref was **invisible** — a false
  NEGATIVE that silently unflagged a genuine mutable-tag third-party action in
  `luxairport-frontend`. Fixed; the `actions/*` and `github/*` exemptions now cover their
  three-segment forms too (`github/codeql-action/analyze@v3`).

### First-party ownership (why the rule flags your own actions, and what removes them)

`rules/gha.yaml` is **static YAML evaluated by semgrep** — no inputs, no env, no workflow context —
so it cannot know whose actions these are, and it flags the caller's own shared actions along with
everything else. Hard-coding an owner into the rule is not an option: it becomes a lie the day that
owner changes. So ownership is decided at **runtime** by `scripts/firstparty.mjs`, which drops
`gha-unpinned-action` findings whose `uses:` ref belongs to the union of:

1. the **caller's** owner (`github.repository`),
2. **this action's own** owner (`github.action_repository`),
3. any owners named in **`first-party-owners`**.

Clause 2 is what survives an ownership split. On 2026-08-02..04 eleven repos moved from `mvalasis`
into the org `creme-ypsilon` while `mvalasis/ci-actions` stayed put — deriving "first-party" from
the caller alone would report all 32 `mvalasis/ci-actions/<action>@v1` refs on those six callers as
unpinned third-party actions. Owner comparison is lowercased. `github.action_repository` is **empty**
for a local `./` invocation (this repo's own smoke job): empty owners are dropped rather than
admitted as an `''`-owner that would match everything. Every uncertain branch — unrecoverable ref,
unparseable owner, empty owner set — **keeps** the finding: a spurious warning is a nuisance, a
silently dropped supply-chain finding defeats the rule.

The packs already surface **real findings** the old gate missed — e.g. exception detail leaked in
hlek-headless REST 500s (`wp-rest-error-detail`), a request-derived `fetch` in lampakia's
newsletter route (`ts-ssrf`), and the fleet's unpinned `webfactory/ssh-agent` / `wrangler-action`
/ `pnpm/action-setup` — joined in v1.10.0 by `gradle/actions/setup-gradle@v4` in
`luxairport-frontend`, which the pre-v1.10.0 two-segment pattern could not see at all
(`gha-unpinned-action`) — all as **WARN**. A 2026-06-30 dataflow re-audit of
lux-main found two **laundered** CWE-209 leaks the plain accessor-grep called clean —
`array_merge($payload, $err->get_error_data())` normalized into a REST 502 (flight-confirm), and a
provider `error_description` reflected via `add_query_arg`/`wp_safe_redirect` on the public `/login/`
page — now caught by **`wp-rest-error-detail-laundered`** (see §Honest limits for the four shapes).

## argv-secret — a secret spelled into a child's argv

A `-H` / `--header` whose **value expands a variable named like** `TOKEN`, `SECRET`, `KEY` or `PASS`
(a substring, any case): `$VAR`, `${VAR}`, a Python f-string `{VAR}`, a GitHub Actions
`${{ secrets.X }}`, a JS template `${…}`, or `"Name: " + VAR`. argv is world-readable — `ps` and
`/proc/<pid>/cmdline` show it to every process on the machine (on a runner: the caller's other steps
and every action they use), and an argv-logging wrapper first on `PATH` records it verbatim. No green
run shows it. The fix is always the same: hand curl the header from a mode-600 file (`-H @file`),
the shape `a11y-audit` (v1.15.1) and `linkcheck` (v1.15.2) moved to.

- **What it grades.** Shell (`.sh`/`.bash`/`.zsh`, or an extensionless file by its shebang), Python,
  and the JS/TS a build or CI step runs (`.mjs`/`.cjs`/`.js`/`.ts`) — on the **diff** (the whole tree
  under `scan-scope: full`), like the rule packs. `.github` YAML (workflows, local composite actions)
  on **every run**, like `gha.yaml`: a workflow is rarely edited, so a diff-only pass would never
  report a leak that predates the check. Not prose (a README's `curl` example is a one-off on a
  person's own machine, not a script re-running under whatever `PATH` it inherits), not UI
  components, not vendored or minified code, and not `selftest*` / `fixtures/` corpora, which must
  spell the banned form to test it (unlike the rule packs' fixtures, which the self-scan grades on
  purpose — §Self-test — a hit on one proves nothing: the end-to-end leg of `selftest.mjs` is this
  check's proof that it runs through `scan.mjs`). Only tracked files are read; a tree it cannot
  list or a file it cannot read is a scanner note, never a silent clean.
- **One matcher, two gates.** `scripts/argv-secret.mjs` is also rule 4 of this repo's own lint
  (`.github/scripts/lint-entrypoint-output.mjs`, over the action entrypoints here), which imports it.
- **Waive a non-secret, with a reason:** `# lint-allow-argv-secret: <why this is not a secret>`
  (`//` in JS) on the flagged line or the line above; a bare pragma does not count. The known false
  positive is a value that merely looks like a secret — `$CACHE_KEY`, an idempotency key.
- **Not seen** (stated, not implied): a header built on an earlier line and passed as `-H "$hdr"`
  (that is dataflow); `.format()` / `%` formatting; other argv spellings (`-u user:$PASS`,
  `-d token=…`, a query string, `--api-token $T`); a secret held in a variable not named like one
  (`$AUTH`). A trailing `#` comment on a code line is scanned, so it can fire.
- **Measured before it shipped (2026-09-25),** over every caller's tree and full history and this
  repo's: every hit on non-fixture code was a real secret in argv — the WAF token in shell arrays,
  Python argv lists and workflow `--header` flags, and a workflow expanding `${{ secrets.* }}` inside
  a `-H` — and nothing else fired.
- **Promote** it with `critical-checks: argv-secret` once a run is clean.

## Honest limits

- **No reachability.** OSS semgrep + osv-scanner are syntactic / present-in-tree; there is no
  dataflow-reachability (a Pro/cloud feature, air-gap-forbidden). A dep CVE means "present", not
  "exploitable" — the report says so.
- **WordPress.org plugin CVEs are out of scope.** osv.dev does not index WP plugin versions;
  catching those needs WPScan/Patchstack (paid + plugin-inventory egress). SCA covers
  composer/npm/pnpm/bun transitive deps only.
- **Intraprocedural taint.** A request value laundered through a helper in **another file** is a
  documented false-negative (semgrep OSS taint is intraprocedural). The inline `wp-rest-error-detail`
  rule fires only when the accessor is *inline* in the sink body (`WP_REST_Response`,
  `rest_ensure_response`, `wp_send_json`/`_error`/`_success`, `wp_die()`). The **laundered** CWE-209
  shapes — detail routed through an intermediate object/array/redirect *within a function* before the
  sink, which the inline grep reports "clean" — are now caught by the separate
  **`wp-rest-error-detail-laundered`** id (T1, promotable; **not** auto-promoted with
  `wp-rest-error-detail`, so a strict caller opts in once verified): (a) a `WP_Error::get_error_data()`
  value flowing (semgrep **taint** mode, through `array_merge`/an intermediate var) into a response;
  (b) a debug-labeled array key (`detail`/`debug`/`trace`/`sql`/…) set to a raw accessor
  (`$e->getMessage()`, `$wpdb->last_error`, `$wpe->get_error_message()`); (c) a `get_error_message()` /
  exception accessor interpolated into a `wp_safe_redirect()`/`wp_redirect()`/`add_query_arg()` URL;
  (d) `new WP_Error('code', $body['error_description'] ?? $body['error'])` wrapping unsanitized
  upstream/provider text. Admin-gated handlers (`current_user_can` in-function) are exempt, and the
  in-sink case is left to the inline rule (no double-report). FP discipline (proven against the
  fleet, 2026-06-30): (b) matches only clearly-DEBUG keys — a plain `'error'`/`'message'` key is
  **not** matched (it is the dominant idiom and usually the intended client string; ~70 of 98 raw
  hits), and `error_log()`/`trigger_error()` builders are excluded. Residual FP: a labeled detail
  passed to a **custom-named** logger (`my_plugin_log(['detail' => …])`) still fires — obvious on
  review, WARN-only. Still **not** covered (genuine FNs): cross-*file* laundering, a bare
  `return new WP_Error('code', $e->getMessage())` whose message is a plain accessor (not the
  upstream-body fallback shape), and `echo` of exception HTML.
- **Reserved checkIds (defined, not yet emitted by a scanner):** `secret-worktree` (a working-tree
  gitignored-`.env` scan — primarily a *local* pre-push concern; in CI the gitignored file isn't
  checked out), `license-denied`, `lockfile-integrity`, `iac-misconfig`. They are wired into the
  tier engine so a future collector emits them with no engine change. **SBOM is deliberately
  deferred** — generating one with no diff/attestation consumer is write-only theatre.
- **The live-probe class is a separate gate.** Turnstile/server-reject end-to-end checks need a
  live HTTP probe of the deployed site → the proposed `form-protection` action, NOT this
  air-gapped static scan. `turnstile-test-key` here only catches a literal test key in *source*.
- **Could-not-look is only as honest as each tool's exit status.** A scanner that exits cleanly
  after quietly skipping part of its work still reads as having looked: osv-scanner passing over a
  lockfile it cannot parse, trufflehog unable to reach a provider for one candidate (it reports it
  unverified, which `--only-verified` drops), and semgrep's per-file parse failures, which are
  listed but not faulted.
- **First-party exemption is by OWNER, not by ref.** `gha-unpinned-action` trusts *every* action
  under a first-party owner at *whatever* tag it is pinned to — not just `ci-actions`. That is the
  deliberate trade for the fleet's floating-`@v1` policy (the whole point of `@v1` is that it
  moves), and it is the one place v1.10.0 made the gate weaker rather than stronger: a compromised
  action published under one of your own owners is not caught here. Keep the set as small as the
  fleet actually needs — the two derived owners cover it today, and `first-party-owners` exists for
  a third account you control, not as a general silencer.

## Self-test

- `node scripts/selftest.mjs` — offline tier-engine test (block-by-default, never-newly-block,
  promotion, T2-not-promotable, report-mode, redaction) **plus** first-party owner resolution, the
  `gha-unpinned-action` post-filter, and the `rules/gha.yaml` `uses:` regex — the last read **live
  out of the rule file**, so the three-segment behaviour is provable on a machine with no semgrep
  installed (CI still runs the real `semgrep --test`). It also asserts the ownership **wiring**
  (`scan.mjs`'s three clauses + the `action.yml` env) against those files' source, because
  `firstparty.mjs` can be perfect while the CLI feeds it the caller's owner alone — which is the
  2026-08 bug restored, with every unit assertion still green. The regression guard.
  Its **end-to-end** leg runs the real `scan.mjs` as a process against stub scanners on a two-commit
  fixture repo: a gitleaks that ignores `--redact` and a trufflehog whose `Raw` carries the value,
  both planting values minted at run time. It asserts the job log carries the whole report byte for
  byte, one annotation per CRITICAL (none for a WARN), no 8-character run of a planted value in the
  log, the summary or stderr, `--redact` on every gitleaks call, a local run printing once with no
  commands (stdout a socket, as node's child_process gives it — the case that crashed the old
  `/dev/stdout` fallback on Linux), report-mode annotating as `::warning`, and an unwritable summary
  still reaching the log under the caller's exit setting. 19 targeted mutants each turn it red.
  Its **argv-secret** leg asserts that every shape the fleet shipped fires and the `-H @file` fix,
  comment lines and a reasoned pragma do not; the file selection (languages, the always-on `.github`
  pass, the skipped corpora); and, end to end, an untouched workflow reported on a diff run, an
  untouched script only under full scope, a selftest fixture never, and a promoted finding
  annotating `header ← variable` with no value. 20 targeted mutants each turn it red.
  Its **could-not-look** legs (v1.19.0) feed `outcome.mjs` canned scanner processes (every exit code,
  signal and report shape in §When a scanner cannot look, both ways) and pin every rule pack's
  `metadata.checkId` to its leg. End to end, on a stub set where every scanner is clean (asserted
  first, so no FAULT can pass for the wrong reason), each case breaks one scanner: semgrep exiting 2
  on a registry outage, gitleaks exiting 1 without a report, a rule pack that does not load
  (unpromoted and promoted), trufflehog exiting 1, osv-scanner exiting 128, 1 and 127, semgrep not
  installed, an unresolvable diff base, a collector that crashes and a scanner killed by a signal.
  Each asserts the note, the verdict and the exit under `fail-on-critical`, `report-mode` and
  `fail-on-critical: false` as it applies, and that a value in a tool's error text never reaches an
  output whole (trufflehog's, not even redacted). 52 targeted mutants each turn it red.
- `bash scripts/selftest-rules.sh` — `semgrep --test` over every rule pack (each bad fixture
  fires, each good fixture stays silent).

Both run in CI (`.github/workflows/security-baseline-selftest.yml`) plus a report-mode self-scan,
after which the same job runs `scan.mjs` over this repo with the real scanners the action just
installed, in both scopes, and fails if any leg could not look: the one place real scanner output,
not a stub's, goes through `outcome.mjs` before a release.

The self-scan (`scan-scope: full`) covers this repo's whole tree, the rule fixtures included,
and should report **critical: 0**. The fixtures' T1/T2 findings are expected: they are the
only run of the real vendored packs through `scan.mjs` (`selftest-rules.sh` calls semgrep
directly), so they are left in, not excluded. Three waivers keep the T0 count at zero, and
each is scoped to named findings:

- `rules/selftest/astro-ts.ts` carries a `nosemgrep` for the community `react-insecure-request`
  rule on its cleartext-`fetch` fixture line only. The pack's own rule still fires there.
- `linkcheck/scripts/sitemap-urls.py` carries one for `use-defused-xml` on its `xml` imports.
  That rule flags the import itself and cannot see the parse under it, which refuses any
  DOCTYPE before ElementTree runs (linkcheck v1.16.1).
- The repo-root `.gitleaksignore` pins two historical gitleaks lookalikes to the commits that
  added them. In full scope the T0 gitleaks leg reads all of history, where reshaping a file
  cannot reach.

A new critical in the self-scan is therefore a real one.

## Implementation

`scripts/tiers.mjs` — pure, network-free tier engine (the `CHECKS` map is the single source of
truth; unit-tested by `selftest.mjs`). `scripts/firstparty.mjs` — pure first-party owner resolution
and the `gha-unpinned-action` post-filter (see §First-party ownership); kept out of `tiers.mjs`
because it is an ownership question, not a severity one. `scripts/argv-secret.mjs` — the pure
`argv-secret` matcher and file selection, shared with the repo lint; `scripts/js-scrub.mjs` — the
JavaScript comment/literal scrubber it and the lint run (both moved out of the lint in v1.17.0, so a
change to either is a release). `scripts/outcome.mjs` — pure classification of each finished
scanner process (looked, or could not look and why) and the map of legs to the checks each can emit
(§When a scanner cannot look). `scripts/scan.mjs` — CLI: resolves the diff base, runs the
scanners, normalizes their output into `{checkId, rule, file, line, msg}` findings, tiers + promotes
via the engine, renders a per-check report to `GITHUB_STEP_SUMMARY` and the job log, annotates each
CRITICAL (`annotations()` in `tiers.mjs`), exits non-zero under `fail-on-critical` only on a
CRITICAL or on a FAULT. Zero npm dependencies (pure Node 22). Tools are pinned binaries installed
in `action.yml`.
