# ci-actions

Shared GitHub Actions for the fleet's site ecosystem — whose callers span
**more than one GitHub owner** since the 2026-08 split (see v1.10.0), so no
line here names an owner as if it were the only one. One canonical copy of
cross-cutting CI tooling, referenced by each repo with a thin caller
workflow — so the logic lives **here**, not duplicated per repo.

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
`linkcheck`, `verify-homepage`) pins `@v1`; current line is **v1.12.0**.

**v1.12.0** — the three entrypoints that had **no crash guard at all** now have
one, closing the split v1.11.0 left open. A fault in a scanner is a fault in the
GATE, and it must not arrive in a caller's repo dressed as a finding about their
site:

| entrypoint | language | before | after |
| --- | --- | --- | --- |
| `verify-homepage/scripts/render-check.mjs` | top-level-await ESM | any throw → exit 1 | reports the fault, exits `fail-on-structure ? 1 : 0` |
| `linkcheck/scripts/linkcheck.py` | plain `main()` | traceback → exit 1, **and a false "broken links found" issue filed** | exit **2** = "no verdict", distinct from 1 = "links are broken"; issue steps key on the crawler's rc, so no issue is filed or closed on a crash |
| `a11y-audit/scripts/audit.sh` | bash | abort → exit 1; any non-zero `pa11y-ci` rc reported as **"WCAG errors found"** | reports the fault, exits `fail-on-violations ? 1 : 0`; a scanner that never produced a per-URL result is no longer reported as accessibility debt |

**Caller-visible:** a report-mode caller whose scanner crashes now goes green
instead of red; an enforcing caller still blocks. `linkcheck` is unchanged in
exit-code terms (it has no report mode — it is structurally always-enforcing);
what changed there is **attribution**, which is what actually bit: a crashed
crawler used to open a bug report blaming the caller's site for links that were
never checked, with the body "(report unavailable — open the run log)".

Three languages, so three behavioural regression suites — each injects a fault
into the **real** entrypoint and runs it, never grepping the source for a
handler's position (a textual assertion goes vacuous the moment the file is
restructured, and cannot tell a live guard from a dead one):
`verify-homepage/scripts/selftest.mjs` (two faults — one at `chromium.launch`,
one inside the const block, which is what pins the handler to reading
`process.env` instead of a TDZ const), `linkcheck/scripts/selftest.py`, and the
new `a11y-audit/scripts/selftest.sh` + `a11y-audit-selftest.yml` (a11y-audit had
no self-test at all before this; the workflow runs it on **bash 5 and bash 3.2**,
because the guard is built out of `trap … EXIT` and `set -u` abort semantics).

Statically, `lint-entrypoint-output.mjs` grew **rule 3** — crash-guard presence
across `.mjs` / `.py` / `.sh`, scoped to the scripts an `action.yml` actually
executes (pure library modules cannot set an exit code, so a guard in one would
be noise). Two entrypoints carry a documented `lint-allow-no-crash-guard:`
exemption: `linkcheck/scripts/sitemap-urls.py` and
`verify-homepage/scripts/link-crawl.sh`. **The test for the exemption is
misattribution, not the exit code** — both are wrapped by steps that already
report their failure for what it is, so there is nothing to realign; `linkcheck.py`
is guarded despite equally having no report mode precisely because its wrapper
did misattribute.

**v1.11.0** — `deps-currency`'s crash guard was **dead code** from the action's
first commit until 2026-08-05: `process.on('uncaughtException', …)` sat *below*
the `main()` IIFE, which is evaluated at module load and exits, so the handler
was never registered. A scanner fault therefore exited 1 regardless of
`fail-on-vuln` **and** wrote nothing to the step summary (the report is appended
at the end of `main`), losing the intended exit code and the diagnostic
together. Hoisted, so a scanner fault now reports itself and exits
`fail-on-vuln ? 1 : 0` — the report-mode-first rule the other five JS
entrypoints already got for free from their `(async () => {…})().catch(…)`
shape. **Caller-visible:** a report-mode caller whose scan crashes goes green
instead of red; an enforcing caller is unchanged. The sibling sweep found the
pattern was never copied — `deps-currency` was the only instance —
and `verify-homepage` / `linkcheck` / `a11y-audit` keep no guard at all, which
is honest rather than dead. Now blocked statically by `.github/workflows/lint.yml`
(rule 2) and asserted behaviourally by `deps-currency/scripts/selftest.mjs`,
which crashes the real scanner rather than grepping it for a line position.
_(Superseded by **v1.12.0**: "honest rather than dead" was the right call about
the COMMENT and the wrong call about the BEHAVIOUR — an absent guard still
blocks a report-mode caller, and in `linkcheck`'s case still filed a false issue.
All three are guarded as of v1.12.0.)_

**v1.10.0** — `deps-currency` + `security-baseline` stop deriving "first-party"
from the **caller's** owner, because the action's owner and the caller's owner
are no longer the same account (2026-08-05). On **2026-08-02..04** eleven fleet
repos moved from the personal account `mvalasis` into the org `creme-ypsilon`;
`mvalasis/ci-actions` did **not** move. Both actions read first-party off
`github.repository` alone — a definition that was only ever right while one
account owned everything — so from the moment of the split every
`mvalasis/ci-actions/<action>@v1` ref inside an org-owned caller scanned as an
unpinned **third-party** action: `deps-currency` would have gone 2 → 6 rows on
`lampakia-astro` and 2 → 5 on `prevedourougr` at the next Monday cron.
`security-baseline` was spared that symptom only by a SECOND defect: its `uses:`
pattern could not match a three-segment ref at all (below), so all **32** of our
own refs across the six migrated callers stayed **invisible** rather than
mis-reported — measured, the pre-widening pattern matches **0 of 55**. Its
ownership filter is therefore PREVENTIVE, and has to ship in the same release as
the widening, which would otherwise surface every one of those 32 as third-party
noise on the first push. (Every number here measured by replaying the shipped
engine and the live rule over those repos' default-branch workflows, not
estimated.) Nothing blocks — both signals are WARN — but
`deps-currency`'s tracking issue only auto-closes at **zero** advisories, so the
noise pins it open permanently, and an issue that can never close is one people
stop reading. **First-party is now the union of** the caller's owner, **the
action's own owner** (`github.action_repository` — the clause that survives an
ownership split), and a new optional **`first-party-owners`** input (space/comma
separated) for a third account you also control. Matching is lowercased;
`actions/*` and `github/*` stay exempt as before; both reports now print the
resolved owner set, because the defect was undiagnosable from a report that just
looked like four extra rows of real debt.
**A real false NEGATIVE closes in the same release.** An action ref may carry
**subdirectory segments** — `gradle/actions/setup-gradle@v4` is one action in a
subdirectory, not two path components — and `gha-unpinned-third-party-action`'s
`uses:` pattern stopped at `owner/repo@`. Since `[A-Za-z0-9._-]` cannot consume
a second `/`, a three-segment ref never reached the `@` and was never tested for
a SHA pin at all: not exempt, **invisible**, from the day the rule shipped in
v1.3.0. That silently unflagged `gradle/actions/setup-gradle@v4` at
`mvalasis/luxairport-frontend` `.github/workflows/e2e.yml:76` — a genuine
third-party action on a mutable tag — for the rule's **entire life**: the ref
landed 2026-06-24 (363dde6), five days *before* the rule that was supposed to
catch it, so there is no window in which it was ever seen. The widened pattern and
the ownership filter ship **together** on purpose: widening alone would have
added 55 of our own refs as noise, which is how a fix becomes the reason the
signal gets ignored.
**Newly-blocks nobody — verified, not argued.** Both signals are WARN
(`deps-currency`'s unpinned rows never feed its block decision;
`gha-unpinned-action` is T1 and, checked live across all ten callers, promoted
by none — the only `critical-checks` anywhere in the fleet are
`wp-rest-error-detail` ×4 and `robots-sitemap-directive` ×2, the latter on
`seo-aeo`); the new input defaults empty, so **no caller workflow changes**; and
the exemption set can only ever GROW, so a row count can only shrink. Replayed
over every live caller's default-branch workflows: `deps-currency` (**7**
callers — four `creme-ypsilon`, three `mvalasis`) 6 → 2 and 5 → 2 on two of the
org callers, byte-identical on the other five;
`security-baseline` suppresses 55 first-party refs, loses **zero** existing
warnings, and adds exactly **one** — the gradle ref above. Two traps are
recorded in the code rather than left to be rediscovered: (1) the action's own
owner is read from **both** `${{ github.action_repository }}` (passed as
`ACTION_REPOSITORY`, deliberately **not** the `GITHUB_`-prefixed name, which
would *shadow* the runner's ambient copy) and the ambient
`GITHUB_ACTION_REPOSITORY` — GitHub documents neither for a **composite**
action's own steps, the only shape these ever run in, and a single-source read
that turned out wrong would revert to the pre-split defect silently, on a weekly
cron, with nothing red; reading both can only add an owner, never remove one.
(2) `github.action_repository` is **empty** for a local `./` invocation (this
repo's own selftest workflows), so empties are dropped rather than admitted as
an `''`-owner that would match every ref. **36** and **45** new offline
self-test assertions respectively, each mutation-checked — and the owner
fixtures deliberately use **different** literals for the caller and the action,
since the original fixture used the same literal for both, which is exactly why
it stayed green straight through the split.
**v1.9.0** — `contract-check` gains a THIRD presence tier, **`requiredNullable`**
(2026-08-01). The manifest could say "present and non-null" (`required`) or
"tolerated absent" (`optional`), but not **"the producer always sends this key,
and null is a legitimate value"** — the shape a consumer schema writes as
`z.number().nullable()`, *nullable but not optional*, where an outright key
omission fails its parse while null is expected. Both existing tiers mis-model
it, and the failure is asymmetric: `optional` fires `optional-null` on **every
healthy run** (a full-catalogue probe found lampakia's `sale_cents` null on
**1712 / 1712** live products — a weekly WARN nobody can action, which trains the
gate to be ignored), while the `types`-only workaround callers were using
type-checks a non-null value but catches **neither the null nor the omission**,
leaving the field silently unchecked for presence. That was live exposure, not a
hypothetical: lampakia's `sale_cents` / `stock_qty` / `image` are hard-required
by its content-collection schema, so the backend could have dropped any of them
with the ENFORCING gate green and the break surfacing as a failed Zod parse
mid-content-pull. An absent key now reports under the **existing**
`required-present` id (the consumer breaks identically, so the documented T0 core
neither grows nor changes meaning); a null is silent; a non-null value is still
type-graded via `types`. `optional-null` is suppressed for any path also declared
`requiredNullable`, and `required` wins — reported once — if a manifest
contradicts itself by naming a path in both. **Additive and verdict-neutral:** a
manifest without the key is graded identically, asserted in `selftest.mjs` and
verified empirically by running the old and new engines over both live callers
(`lampakia-astro`, `prevedourougr`) for **byte-identical** reports. Twelve new
self-test assertions, each mutation-checked against a deliberately broken engine.
Picking the tier is the part that goes wrong — see contract-check's README
["Which presence tier?"](contract-check/README.md#which-presence-tier), including
why *over*-tiering a field the consumer tolerates (lampakia's `short`) is its own
false block.
**v1.8.0** — `verify-homepage` **self-diagnosing landmark resolution** (2026-07-30).
A landmark verdict named the *selector* and nothing else, which cost a month:
lampakia's weekly run reported `collapsed landmark footer (0-height)` at desktop
+ laptop, PASS at mobile, from 2026-07-01 to 07-30, and nothing in that message
said the flagged element was a mobile drawer's chrome `<footer>` (first in
document order) rather than the site footer. Landmarks resolve with
`document.querySelector` — first match wins — and at ≥1024px the drawer's
`lg:hidden` ancestor went `display:none`, collapsing the descendant's rect to
`0×0` while the descendant's **own** computed display stayed `block`, so it tripped
`display !== 'none' && h <= 0`. Fixed at the source in lampakia (e2ff769, drawer
chrome → `<div>`); fixed *here* so the next one is a two-minute read. Landmark
findings now carry (1) the element the selector resolved to, (2) the `display:none`
ancestor that is the actual cause, or the drawer/blockquote/article container it is
nested in, (3) the match count and the runner-up match that actually renders. The
**overlap** path gets the same annotation and needs it more — there an ambiguous
selector yields a *false FAIL* (`main ∩ footer` when `footer` resolved to a
`<blockquote><footer>` citation nested inside main; prevedourou.gr is one populated
`author` field away from exactly that, gate ENFORCING). A run that saw an
ambiguous resolution also prints one advisory block **before the verdict, on PASS
too** — the regression signal the scoped-selector callers were structurally unable
to see (full reasoning + the measured fleet data + the standing call:
`verify-homepage/README.md` → "Selector precision vs. catching markup
regressions"). Plus one latent trap disarmed: the nav file is now read whenever it
exists, not only when `nav` is in `checks` — `checks: render` alone had been
silently falling back to the DEFAULT `header/main/footer` selectors instead of the
caller's declared `landmarks` (no fleet caller sets `checks:`, so no live verdict
moves). **Report-only, verdict-neutral** — no input changed, and the new
`scripts/selftest.mjs` pins exit `1` unscoped-and-enforcing, exit `0` scoped, on
the same fixture. First offline fixture layer for this action (real Chromium,
`file://` fixtures) — necessary because the live site that carried the defect has
since been fixed and can no longer exercise the path.
**v1.7.1** — `verify-homepage` **report-output plumbing**, surfaced by the sibling
audit after v1.7.0 (2026-07-29). (1) When the step-summary write threw, the `catch`
printed the whole report *and* the unconditional line below printed it again — a
doubled report in the job log on exactly the run you are trying to read; the catch
is now a no-op, since the unconditional mirror already covers it. (2) Every terminal
path was a `console.log`/`console.error` immediately followed by `process.exit()`:
`process.stdout`/`stderr` writes are **async on macOS pipes** (synchronous on
Linux/Windows) and `process.exit()` does not drain a pending write, so a piped local
run truncated at the 65,536-byte pipe buffer. Reachable, not theoretical, and worst
exactly where it hurts: a 12-URL run against a badly-wrong nav puts every mismatch
on one line, and that 78,083-byte report arrived on a Mac pipe as 65,536 bytes —
the lost tail included the `---` verdict. Both paths (the report, and the `no URLs
provided` diagnostic that is the *only* output of the `exit 2` path) now go through
the same `fs.writeSync` helper `test-suite` adopted in v1.7.0. CI is Linux, so this
was latent rather than live — the point is that the two actions no longer disagree
about how a verdict reaches the log. **No gutter prefix here, deliberately:** every
`verify-homepage` line starts with code-controlled markdown (`### `, `- **`, `| `)
and page-derived strings are `safe()`-stripped and embedded mid-line, so a hostile
page title cannot reach line-start to forge a workflow command — re-verify that
property if you ever change how a `note()` line is composed. **Behavior-compatible**
— no input, verdict or exit code changed.
**v1.7.0** — `test-suite` **job-log mirror + the false-green documented**, both
surfaced wiring the action to a new caller (2026-07-28). (1) The action captured
the test command's stdout and reported ONLY to `$GITHUB_STEP_SUMMARY`, echoing a
tail solely on FAIL — so a green run left the job log **empty** and
`gh run view --log` could not answer "did my tests actually run?" (fleet-wide: all
six callers). Now every terminal path prints one `test-suite: … status=…` line with
the resolved command, mode and parsed counts, and the output tail is echoed on
**success as well as failure**. Captured output keeps the existing `safe()`
defanging **and** gains a `│ ` gutter — GitHub parses a log line as a workflow
command only at line-start, so a hostile test name can't forge an `::error::`
annotation or fire `::stop-commands::` now that runner output reaches stdout
(selftest pins it). (2) The **auto-detect false-green** is now in
`test-suite/README.md` instead of only in two callers' workflow headers: with no
`test-command` and no root `package.json`/`composer.json` the action reports
"PASS — no stack to test" and exits `0` **even under `fail-on-fail: 'true'`** —
`test-command:` is load-bearing for repos whose suites are plain scripts rather
than a framework. The two nothing-ran paths now render `⚠️ … NOTHING RAN …` in the
log and name `test-command`, so the trap is visible at the point of failure.
**Behavior-compatible** — no input added or changed, no verdict or exit code
changed; callers get strictly more log output, so the `v1` move newly-blocks
nobody. Intervening patch line: **v1.6.3** `seo-aeo` robots-sitemap-directive
T2→T1, **v1.6.2**/**v1.6.1** `test-suite` bun-native count parsing + bun PM
detection.
**v1.6.0** — NEW action **`form-protection`**: bot-gate enforced-END-TO-END gate
(the DISCIPLINES.md §Security "no-op class" — a test/placeholder sitekey shipped to
prod, or a server that skip-verifies the token; both shipped silently on EPN 2026-06).
Per wired form page: CRITICAL `sitekey-real` (missing/empty/known-test `data-sitekey`;
built-in Turnstile `1x/2x/3x` + `0x000…0`, reCAPTCHA `6LeIxAcT…`, hCaptcha test keys;
client-rendered widgets classified via the inline-script sitekey literal) + CRITICAL
`server-rejects` (tokenless + junk-token POST must hard-reject; `form-endpoints`
map takes `mode=json token=<field> expect=<reject-signature>` so a field-validation
4xx can't mask a skip-verifying JSON endpoint — probes send a minimal body, read-safe
by design). Offline selftest incl. a local-http-server e2e of the real CLI + exit
codes. **Purely additive** — no existing action or caller changes, so the `v1` move
newly-blocks nobody. First callers (report-mode): epn-astro contact+employers,
lampakia-astro checkout.
**v1.5.0** — NEW action **`verify-homepage`**: multi-viewport structure/render +
nav-inventory gate (Playwright/Chromium) + the canonical copy of the per-repo
`verify-homepage-t1.sh` link crawl (`checks: links`). Ships with a live-smoke
selftest workflow; validated locally against lampakia (nav 6-in-order, 4 clean
viewports, 24-link T1 green). **Purely additive** — no existing action or
caller changes, so the `v1` move newly-blocks nobody.
**v1.4.7** — docs only: `test-suite`
gitignored-phar `test-command` override note (WP-on-hulk repos; no action-behavior change).
**v1.4.6** — `security-baseline` now catches the
**laundered CWE-209** error-detail shapes the inline accessor-grep MISSES (a 2026-06-30 dataflow
re-audit of epn-billing/lux-main/hlektrologos found real public-unauth leaks reported "clean"
because the detail is routed through an intermediate object/array/redirect before the sink). Four
new vendored WP/PHP rules under a **separate** `wp-rest-error-detail-laundered` **T1** id (so
promoting the inline `wp-rest-error-detail` does not auto-promote — and possibly newly-block on —
these heuristics; a caller opts in independently): (a) a `WP_Error::get_error_data()` value flowing
(semgrep **taint** mode, through `array_merge`/an intermediate var) into a `WP_REST_Response` /
`rest_ensure_response` / `wp_send_json*` body; (b) a debug-labeled array key
(`detail`/`debug`/`trace`/`sql`/…) set to a raw accessor (`$e->getMessage()`, `$wpdb->last_error`,
`$wpe->get_error_message()`); (c) an exception/`get_error_message()` accessor reflected into a
`wp_safe_redirect()`/`wp_redirect()`/`add_query_arg()` URL; (d)
`new WP_Error('code', $body['error_description'] ?? $body['error'])` wrapping upstream/provider text.
Admin-gated (`current_user_can`) handlers are exempt and the in-sink case is left to the inline rule
(no double-report). New `wp-rest-error-detail-laundered` is **WARN** and promoted by no caller, so the
`@v1` move newly-blocks nobody; `semgrep --test` (14 wp-php rules) + `selftest.mjs` green.
**v1.4.5** — `security-baseline`'s
`wp-rest-exception-detail` (T1) + `wp-rest-wp-error-detail` (T2) now **also cover the `wp_die()`
sink**: `wp_die($e->getMessage())` / `wp_die($e->getTraceAsString(), …)` (plus the WP_Error
`wp_die($wpe->get_error_message())` advisory variant) — the frontend/admin terminator that leaks
raw exception detail exactly like the AJAX/REST sinks (a request the v1.4.4 work named but did not
wire). Additive under the same `wp-rest-error-detail` **T1** id (still `WARNING`), so the `@v1` move
newly-blocks nobody; `semgrep --test` + `selftest.mjs` green. **v1.4.4** — `security-baseline`'s
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
caller; surfaced by the EPN pilot). *(Historical, and **superseded by v1.10.0**
— do not read it as current behaviour: "own org" here meant the **caller's**
owner, which stopped being the action's owner at the 2026-08 split. First-party
is now an owner **set**.)* **v1.4.0** — three NEW actions for the
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

## A tool fault is never a finding about the caller's site

**Rule:** when an action's own scanner faults, it reports the fault **as a
fault** and exits under the caller's own enforcement setting —
`FAIL_ON_<X> ? 1 : 0`. Our bug must never newly-BLOCK a caller who asked for
report mode, and must never arrive dressed as a verdict about their site.

The six JS entrypoints that use `(async () => {…})().catch(…)` get this shape for
free. Everything else has to arm a guard explicitly, and **before any statement
that can fault** — which in practice means reading the enforcement setting from
the *environment* rather than from the program's own state:

| language | guard | why the env read matters |
| --- | --- | --- |
| `.mjs` | `process.on('uncaughtException'/'unhandledRejection', …)` hoisted above the main invocation | a crash during const init leaves module consts in the **temporal dead zone**; reading one there throws `ReferenceError` *inside the handler*, which loses the diagnostic and the exit code together (node then exits 7) |
| `.py` | `try/except` around `main()` under `if __name__` | `SystemExit` is not an `Exception`, so deliberate verdict exits pass through untouched and are never relabelled a crash |
| `.sh` | `trap … EXIT` on the **first** executable line + a sentinel that deliberate exits set | **not `trap … ERR`**: `set -u` aborts *without* firing `ERR`, and with errexit off `ERR` fires on commands that are not faults |

Mechanized as **rule 3** of the entrypoint lint (below) and asserted
behaviourally by each action's self-test, which crashes the real entrypoint
rather than grepping it for a handler. An entrypoint may opt out with
`lint-allow-no-crash-guard: <reason>`, but the test is **misattribution, not the
exit code**: `sitemap-urls.py` and `link-crawl.sh` are exempt because their
wrapper steps already report their failure for what it is, while `linkcheck.py`
is guarded despite equally having no report-mode input, because its wrapper
filed a false "broken links found" issue on a crawler crash.

## Repo hygiene — action entrypoints never write to stdout asynchronously

**Rule:** inside an action entrypoint (`<action>/scripts/*.mjs`, except
`selftest.mjs`), all output goes through a **synchronous** write — a
`say`/`sayErr` helper over `fs.writeSync`, or `fs.appendFileSync(summaryFile, …)`.
No `console.*(…)`, no `process.std{out,err}.write(…)`.

**Why:** those writes are ASYNC when the fd is a pipe on macOS (synchronous on
Linux/Windows), and `process.exit()` does **not** drain a pending async write —
so the report truncates at the 65,536-byte pipe buffer, silently, with a zero
exit code. CI is Linux, so the bug is **latent** in CI and only bites on local
runs; that is why it shipped twice. `test-suite` **v1.7.0** introduced the fix,
and `verify-homepage` **v1.7.1** had to apply it again (a measured 78,083-byte
report arrived as 65,536 bytes, losing the `---` verdict) — caught only because
a sibling audit happened to look.

```js
const say    = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };
const sayErr = (s = '') => { try { fs.writeSync(2, `${s}\n`); } catch { console.error(s); } };
```

Mechanized by [`.github/scripts/lint-entrypoint-output.mjs`](.github/scripts/lint-entrypoint-output.mjs),
run as a **blocking** job on every push and PR
([`lint.yml`](.github/workflows/lint.yml)); its own fixture suite
(`lint-entrypoint-output.selftest.mjs`) runs first, because a scrubber bug would
fail permissively. Entrypoints are discovered from `action.yml` presence, so a
new action is covered the day it lands. The lint flags **any** raw call, not just
one adjacent to a `process.exit()` — in the v1.7.1 case the two sat lines apart.
Two allowances: the `catch` fallback of an `fs.writeSync` on the same line, and
`// lint-allow-raw-output: <reason>` (a reason is required).

It carries **three** rules, all of the same shape — defects a green run cannot
distinguish from correct code:

1. **raw async stdout writes** (above) — `.mjs` only.
2. **crash guards registered after `main` runs** — dead code that has never run;
   `.mjs` only. Added v1.11.0 after `deps-currency` shipped one for its whole life.
3. **no crash guard at all** — `.mjs` / `.py` / `.sh`, added v1.12.0. Scoped to
   the scripts an `action.yml` actually **executes** (`discoverExecuted`), since a
   pure library module cannot set an exit code. Both discovery passes fail
   **closed** on an empty result: a rule that has silently switched itself off
   looks exactly like a rule with nothing to report.

Known limit, stated rather than papered over: for bash, rule 3 matches any
`trap … EXIT`, so a pure **cleanup** trap reads as a guard. That is why
`link-crawl.sh` carries an explicit pragma instead of relying on detection, and
why the behavioural self-tests — not this lint — are the load-bearing layer.

The seven `*/scripts/selftest.mjs` are **exempt on purpose** — they do end in
`console.log(…)` then `process.exit(…)`, but emit 1375–4117 bytes, an order of
magnitude under the pipe buffer, so they cannot truncate. Don't "fix" them.

Repo-internal only: no caller consumes this lint, so changing it needs **no
version bump and no `v1` tag move**.

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

The same self-test also pins the **crash-guard attribution** added in v1.12.0.

### Exit codes, and why the issue lifecycle keys on them

`linkcheck` has no report mode — a broken internal link is always fatal — so
there is no exit code to soften when the crawler faults. What matters is telling
a **verdict** apart from a **fault**:

| exit | meaning | issue lifecycle |
| --- | --- | --- |
| `0` | crawled clean | close the tracking issue |
| `1` | crawled, found broken links | open / comment on it |
| `2` | **could not crawl** — the tool faulted, or `LINKCHECK_HOST` is unset | do **neither** |

Before v1.12.0 the issue steps keyed on `failure()`, which cannot see the
difference: a crashed crawler filed a "Weekly link check: broken links found"
issue against the caller's repo, blaming their site for links that were never
checked, with the body `(report unavailable — open the run log)`. The crawl step
now publishes its own `rc` as a step output and the issue steps key on that, so a
fault leaves the tracking issue untouched in **both** directions — it is not
opened on a crash, and just as importantly not *closed*, because a run that never
checked the links is not evidence that they are healthy.

## Adding the action to a new repo

1. Drop in the caller workflow above (set `sitemap-url` + `host`).
2. Commit an empty `scripts/linkcheck-allow.txt`.
3. (If using a WAF token) add the `VERIFY_HOMEPAGE_TOKEN` secret.

## `verify-homepage` — structure + cross-viewport render gate

Renders each live page in headless Chromium across a viewport matrix
(desktop/laptop/mobile) and BLOCKS on broken layout (horizontal overflow,
collapsed / overlapping landmarks) + a **nav-inventory assert** (the primary-nav
items present, in declared order, against a per-repo `scripts/verify-nav.json`) —
so a silently wrong / missing / reordered menu fails the gate. The mechanical
half of the UI/UX discipline (`~/.claude/DISCIPLINES.md`); visual taste stays
advisory. Also carries the **one canonical copy** of the per-repo
`verify-homepage-t1.sh` link crawl (`checks: links`). Full inputs +
`verify-nav.json` schema: [`verify-homepage/README.md`](verify-homepage/README.md).

The browser matrix is the costly tier — wire it on the **weekly schedule +
manual dispatch only, never per-push** (a standalone `verify-render.yml` per
caller). Report-mode-first (`fail-on-structure: false`), then flip to BLOCK once
clean. Wired 2026-06-29; status as of 2026-07-30: **ENFORCING** — epn-astro
(pilot), lampakia-astro, hlektrologos, prevedourougr (the last three flipped
2026-07-07); **report-only** — lux-main + lux-dev (responsive debt outstanding).

Landmark selectors resolve **first-match-wins**, so a precise selector and a gate
that catches markup regressions pull against each other — the reasoning, the
measured fleet data, and the standing call are in
[`verify-homepage/README.md`](verify-homepage/README.md) →
"Selector precision vs. catching markup regressions". Open call as of 2026-07-30;
the recommendation there is to keep scoped selectors and let the v1.8.0 advisory
carry the regression signal.

## Roadmap

- ~~`verify-homepage` — fold the per-repo `verify-homepage-t1.sh` copies into a
  shared action~~ **DONE 2026-06-29** (`verify-homepage`, `checks: links`). The
  per-repo copies can migrate to `uses: …/verify-homepage@v1` with `checks:
  links` incrementally; the per-deploy crawls still use the local copy for now.
