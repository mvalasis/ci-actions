# security-baseline

Air-gapped **security gate** for the `mvalasis/*` fleet — the one CI check that **blocks on
every repo**. Rebuilt from a 2-tool script (semgrep + gitleaks) into a **tiered** gate that adds
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
| **T1 — promotable WARN** | reports; a caller ELEVATES any id to CRITICAL via `critical-checks` | `sca-critical`, `sca-high` (osv-scanner); the custom **WP/PHP** rules (`wp-nonce-missing`, `wp-cap-missing`, `wp-sql-unprepared`, `wp-unserialize`, `wp-file-include`, `wp-rest-error-detail`, `wp-weak-crypto`, `turnstile-test-key`); the custom **Astro/TS/RN** rules (`ts-dangerous-html`, `ts-eval`, `ts-child-process`, `ts-public-secret-leak`, `ts-ssrf`, `ts-open-redirect`, `ts-secret-in-log`, `rn-insecure-storage`, `rn-cleartext-http`); the **GitHub-Actions** rules (`gha-unpinned-action`, `gha-script-injection`, `gha-pr-target`); `dockerfile-lint` |
| **T2 — advisory** | reports (WARN/INFO); never promotable | `sca-moderate`/`sca-low` (INFO); `wp-unescaped-output` (syntactic XSS — too FP-heavy to promote); `ts-cors-wildcard`; `secrets-history` (full-history baseline — clearing needs a history rewrite, so it can **never** be a merge precondition) |

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
| `fail-on-critical` | `true` | `true` = BLOCK on any CRITICAL (T0 or a promoted T1). |
| `critical-checks` | `''` | Comma/space list of **T1** ids to elevate to CRITICAL for **this** caller. T0 ids are already critical; T2/unknown ids are reported and ignored. |
| `report-mode` | `false` | Onboarding escape hatch: report even T0 without blocking (loud banner). Must stay `false` for an enforcing caller. Pair with `report-mode-reason`. |
| `semgrep-config` | `p/security-audit` | Community SAST ruleset (registry id or a vendored local path for full air-gap). The custom rule packs are always vendored-local. |
| `semgrep-severity` | `ERROR` | Community-rule severity that blocks. |
| `verified-secrets` | `auto` | `auto`/`on` = trufflehog `--only-verified` (provider test-auth egress); `off` = air-gap mode (gitleaks pattern floor still blocks). |
| `enable-sca` | `true` | osv-scanner dependency audit (WARN; package-coordinate egress to osv.dev). |
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
  in a `run:` block, the `pull_request_target` trigger.

The packs already surface **real findings** the old gate missed — e.g. exception detail leaked in
hlek-headless REST 500s (`wp-rest-error-detail`), a request-derived `fetch` in lampakia's
newsletter route (`ts-ssrf`), and the fleet's unpinned `webfactory/ssh-agent` / `wrangler-action`
/ `pnpm/action-setup` (`gha-unpinned-action`) — all as **WARN**.

## Honest limits

- **No reachability.** OSS semgrep + osv-scanner are syntactic / present-in-tree; there is no
  dataflow-reachability (a Pro/cloud feature, air-gap-forbidden). A dep CVE means "present", not
  "exploitable" — the report says so.
- **WordPress.org plugin CVEs are out of scope.** osv.dev does not index WP plugin versions;
  catching those needs WPScan/Patchstack (paid + plugin-inventory egress). SCA covers
  composer/npm/pnpm/bun transitive deps only.
- **Intraprocedural taint.** A request value laundered through a helper in another file is a
  documented false-negative.
- **Reserved checkIds (defined, not yet emitted by a scanner):** `secret-worktree` (a working-tree
  gitignored-`.env` scan — primarily a *local* pre-push concern; in CI the gitignored file isn't
  checked out), `license-denied`, `lockfile-integrity`, `iac-misconfig`. They are wired into the
  tier engine so a future collector emits them with no engine change. **SBOM is deliberately
  deferred** — generating one with no diff/attestation consumer is write-only theatre.
- **The live-probe class is a separate gate.** Turnstile/server-reject end-to-end checks need a
  live HTTP probe of the deployed site → the proposed `form-protection` action, NOT this
  air-gapped static scan. `turnstile-test-key` here only catches a literal test key in *source*.

## Self-test

- `node scripts/selftest.mjs` — offline tier-engine test (block-by-default, never-newly-block,
  promotion, T2-not-promotable, report-mode, redaction). The regression guard.
- `bash scripts/selftest-rules.sh` — `semgrep --test` over every rule pack (each bad fixture
  fires, each good fixture stays silent).

Both run in CI (`.github/workflows/security-baseline-selftest.yml`) plus a report-mode self-scan.

## Implementation

`scripts/tiers.mjs` — pure, network-free tier engine (the `CHECKS` map is the single source of
truth; unit-tested by `selftest.mjs`). `scripts/scan.mjs` — CLI: resolves the diff base, runs the
scanners, normalizes their output into `{checkId, file, line, msg}` findings, tiers + promotes via
the engine, renders a per-check report to `GITHUB_STEP_SUMMARY`, exits non-zero only on a CRITICAL
under `fail-on-critical`. Zero npm dependencies (pure Node 22). Tools are pinned binaries installed
in `action.yml`.
