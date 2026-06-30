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
`linkcheck`) pins `@v1`; current line is **v1.4.4** — `security-baseline`'s
**`wp-rest-exception-detail` now also catches the WordPress AJAX leak path**:
`wp_send_json_error($e->getMessage())`, `wp_send_json_error(['message'=>$e->getMessage()], 500)`,
`wp_send_json_success(['debug'=>$e->getMessage()])`, `wp_send_json([...$e->getTraceAsString()...])`
— the common companion to the REST `WP_REST_Response` / `rest_ensure_response` leak it already
caught (`getLine()`, already named in the rule message, is now matched too). Backward-compatible — catches strictly **more** under the
same `wp-rest-error-detail` **T1** id, so the `@v1` move newly-blocks nobody. Also adds a separate
**T2 advisory** `wp-rest-wp-error-detail` for `WP_Error::get_error_message()` reaching those sinks —
**never promotable**, since that string is usually the *intended* client-facing message (folding it
into the promotable T1 rule would risk false CRITICALs). The EPN custom plugins leak via exactly
this AJAX pattern (a companion task fixes the EPN code); the clean WP repos can promote
`wp-rest-error-detail` once released. **v1.4.3** — `security-baseline` hardened the `hadolint`
install (`curl -f` fail-closed + a post-install `--version` smoke check, mirroring the v1.4.2 osv
fix). **v1.4.2** — **critical osv-scanner
install fix**: both `deps-currency` and `security-baseline` downloaded the
*versioned* asset name (`osv-scanner_2.4.0_linux_amd64`), but osv-scanner v2.x
dropped the version from its release-asset filename — the URL 404'd, `curl -sSL`
(no `-f`) silently saved the error page as the "binary", and the SCA scan was
**skipped → false clean, fleet-wide**. Fixed: unversioned asset name (version
still pinned by the release tag), `curl -fsSL` so a missing asset fails the step
red, + an `osv-scanner --version` smoke check. Surfaced by the `deps-currency`
lux-pm pilot (osv.dev had 6 advisories / 4 ≥HIGH for its phpspreadsheet, gate
reported 0). **v1.4.1** — `deps-currency`'s
unpinned-action scan now excludes the repo's **own org** (`mvalasis/*`) as
first-party (it was flagging the fleet's own `mvalasis/ci-actions@v1` callers,
which are deliberately floating-tag-pinned by policy — pure noise on every
caller; surfaced by the EPN pilot). **v1.4.0** — three NEW actions for the
disciplines rethink (the 8 software-house lifecycle lenses): **`test-suite`**
(per-stack node/php test runner; a repo with no tests stays green),
**`contract-check`** (live WP/WC REST JSON probe vs a committed manifest —
required fields + types + money/encoding invariants; `seo-aeo`-shaped live
probe), and **`deps-currency`** (scheduled full-lockfile osv scan — the TIME
axis `security-baseline`'s diff scan misses — + unpinned-action flag, with a
linkcheck-style auto-issue). All three **report-mode-first** (`fail-on-*`
defaults `false`), each ships an **offline selftest** (run green: 50 / 36 / 47
assertions). **Purely additive** — no existing action or caller changes, so the
`v1` move newly-blocks nobody; not yet wired to any caller (a separate deploy
step pins `mvalasis/ci-actions/<action>@v1`).
History: **v1.3.0** was the **`security-baseline`
rebuild**: the 2-tool air-gapped script (semgrep + gitleaks) becomes a tiered
gate — a tiny **T0 CRITICAL** core that still blocks exactly what it blocked
before (semgrep community ERROR on diff + gitleaks pattern on diff) plus a NEW
diff-scoped trufflehog `--only-verified` live-secret check, and a deep
**T1 promotable-WARN** layer (osv-scanner SCA + 22 vendored WP/PHP & Astro/TS
semgrep rules + GitHub-Actions supply-chain) elevated per-caller via the additive
`critical-checks` input. **Backward-compatible** (the callers' `scan-scope` +
`semgrep-severity` inputs are unchanged) and **validated against all 9 checkouts —
CRITICAL=0 everywhere, so the tag move newly-blocks nobody.** Offline guards:
`security-baseline/scripts/selftest.mjs` (tier engine) + `selftest-rules.sh`
(`semgrep --test`). Full detail: [`security-baseline/README.md`](security-baseline/README.md).
History: **v1.2.1** was a `linkcheck` verify-token cross-origin leak fix
(redirects followed manually, `X-Verify-Source` re-scoped per hop); **v1.2.0**
was the `seo-aeo` parsed Node+cheerio rebuild (T0/T1/T2 + `critical-checks`).

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
| `verify-token` | no | `''` | `X-Verify-Source` WAF-bypass token, sent **only** to `host` (+ subdomains), re-scoped per redirect hop so it never rides a cross-host redirect. |
| `allow-file` | no | `scripts/linkcheck-allow.txt` | Per-repo baselined-URL list, read from the caller checkout. |
| `workers` | no | `10` | Concurrent curl workers. |
| `manage-issue` | no | `true` | Open/auto-close a GitHub issue on failure/clean (needs `issues: write`). |

### Per-repo baseline

Keep a `scripts/linkcheck-allow.txt` in each caller repo (one URL per line,
`#` comments). Any URL listed is treated as OK — use it only to silence
genuinely-low-value legacy cruft, never to hide a real outage. It is read
from **your** checkout, not from this action.

### Token scoping & self-test

The WAF-bypass token is attached **only** to requests on `host` and its
subdomains, and redirects are followed **manually** (re-evaluating the host at
every hop) so the token is never carried to a cross-origin redirect target —
`curl -L` would otherwise re-send a custom `-H` across hosts (it strips only
`Cookie`/`Authorization`). `scripts/selftest.py` is an offline, network-free
regression guard: it stands up two loopback servers on different hostnames and
asserts the token never reaches the external host across a redirect chain
(`python3 linkcheck/scripts/selftest.py`; also runs in CI on `linkcheck/**`).

## Adding the action to a new repo

1. Drop in the caller workflow above (set `sitemap-url` + `host`).
2. Commit an empty `scripts/linkcheck-allow.txt`.
3. (If using a WAF token) add the `VERIFY_HOMEPAGE_TOKEN` secret.

## Roadmap

- `verify-homepage` — fold the per-repo `verify-homepage-t1.sh` copies into a
  shared action here (same duplication, same fix).
