# a11y-audit

WCAG 2.2 AA audit of live URLs via **pa11y-ci** (axe-core + HTML_CodeSniffer). Audits the
rendered page, so it fits server-rendered WordPress and deployed Astro alike. **Report-mode
by default** — flip `fail-on-violations: true` to BLOCK once a page's backlog is clean.

```yaml
# .github/workflows/a11y-audit.yml
name: a11y-audit
on:
  workflow_dispatch: {}
  schedule: [{ cron: '20 2 * * 1' }]
permissions: { contents: read }
jobs:
  a11y:
    runs-on: ubuntu-latest
    steps:
      - uses: mvalasis/ci-actions/a11y-audit@v1
        with:
          urls: |
            https://example.com/
            https://example.com/about/
          fail-on-violations: 'false'   # report first; enforce once clean
```

| input | default | notes |
|---|---|---|
| `urls` / `sitemap-url` | — | the pages to audit (one required) |
| `standard` | `WCAG2AA` | or `WCAG2AAA` |
| `runner` | `axe htmlcs` | pa11y runners |
| `fail-on-violations` | `false` | `true` = hard BLOCK |
| `max-urls` | `25` | cap |

Rollout: start `fail-on-violations: false` (surface the backlog), fix it, then flip to `true`.

## Notes

- **Every package from a vendored lockfile** (v1.22.0). `scripts/install.sh` copies
  `package.json` and `package-lock.json` into a private dir under `$RUNNER_TEMP` and runs `npm ci
  --omit=dev --ignore-scripts --no-audit --no-fund` there: pa11y-ci 4.1.1 and the 161 packages
  it pulls install at the lock's versions, each tarball checked against its sha512 integrity,
  and no lifecycle script runs (puppeteer's postinstall, the only one, would download a browser
  of its own). The audit step gets a bin dir that holds `pa11y-ci` alone on its `PATH`; nothing
  lands in the action's dir or on the job's `PATH`. Until v1.22.0 the step was `npm install -g
  pa11y-ci@4.1.1` (v1.21.0; the floating `@4` before): the top package was pinned, but pa11y,
  puppeteer, cheerio, lodash and the rest resolved within their ranges on every caller run, so
  a compromised patch release of any of them reached every caller at its next run.
- **Chromium: Chrome for Testing, pinned by SHA-256** (v1.22.0). The browser is the build
  puppeteer-core in the lock launches (148.0.7778.97 for puppeteer 24.43.1), installed by
  `security-baseline/scripts/install-pinned.sh` from its line in `security-baseline/tool-pins.txt`:
  downloaded from Google's bucket (the URL puppeteer's own download uses) to a temp dir, and
  extracted only when the zip hashes to the pin. puppeteer finds it through
  `PUPPETEER_EXECUTABLE_PATH` and downloads nothing. Chosen over puppeteer's postinstall and over
  `npx puppeteer browsers install <build>`, which pin the same build and check nothing: both
  download and unzip without a digest (and unzip with extract-zip, below). **What cannot be
  checked:** Google publishes no checksum or signature for Chrome for Testing, so the pin is
  trust-on-first-use. It proves every runner gets the bytes first downloaded on 2026-09-28, which
  matched the md5 the bucket records for the object, whose generation shows it was never replaced
  since its 2026-04-28 upload; it cannot prove those bytes are what Google built. Likewise the
  lock's integrity hashes prove every runner gets the tarballs first resolved, not that they were
  benign when published; the week-old rule and the advisory check below are what stand between the
  two. Node, npm, and the system libraries Chrome loads are the runner image's.
- **Advisories, weekly.** `a11y-audit-selftest.yml` runs every Monday as well as on every change:
  its `advisories` job runs this repo's own `deps-currency` over the lock, failing on an advisory
  of any severity. `osv-scanner.toml` beside the lock carries the reviewed exceptions, each with a
  reason and an `ignoreUntil` at most 100 days out (`selftest-pins.sh` fails an entry without
  them), so an exception is looked at again when it expires. Today: extract-zip 2.0.1 (two
  symlink path-traversal advisories, no fixed release), reached only through `@puppeteer/browsers`'
  `install()`, which a11y-audit never runs; it leaves the tree once a pa11y-ci release moves to
  pa11y 10 (puppeteer 25 dropped it).
- **Modern browser.** pa11y-ci 4.1.1 → pa11y 9.1.1 → puppeteer 24.43.1, driving Chrome for
  Testing 148. The earlier `pa11y-ci@3` shipped Chromium 91, which predates CSS cascade layers (`@layer`, Chrome
  99+); on any layered stylesheet — e.g. **Tailwind v4** — the utilities block was dropped,
  so the page rendered unstyled and axe reported **bogus contrast failures** (text fell back
  to the UA link colour). The current engine renders the page as real users see it.
- **`needsReview` is advisory, not blocking.** axe "incomplete" findings (where it can't
  auto-determine pass/fail — text over a `position:fixed` overlay, gradients, background
  images) are capped to *warning* (`levelCapWhenNeedsReview`), so they don't BLOCK. Confirmed
  axe violations + HTML_CodeSniffer errors still block. Per DISCIPLINES.md: mechanical → hard
  gate, judgment → advisory.
- **`verify-token` scope.** The token (`X-Verify-Source`) is injected via pa11y-ci's
  `defaults.headers`, which pa11y@9 applies with **first-request-only** Puppeteer request
  interception — *not* `setExtraHTTPHeaders`. So it rides only the **navigation request** to
  each audited URL (and the sitemap fetch, which uses no `-L`), never a subresource or a
  fetch, first- or third-party (fonts/CDNs/analytics), and never a redirect target. It's still
  a secret sent to the audited origin: point the action only at first-party origins you trust,
  and prefer an origin-bound / IP-allowlisted WAF rule over a portable bearer token. The
  no-broadcast guarantee is a property of pa11y's interception code, so the lock's pa11y is a
  security control. **Measured, not only read** (v1.22.0): the real-install self-test
  (`scripts/selftest-install.sh`, `scripts/selftest-fixtures.mjs`) drives the real pa11y-ci and
  Chrome at two loopback origins, one audited and one a third party and redirect target, and
  fails if the token reaches any request but the sitemap fetch and the audited navigations, or if
  any of the page's subresources, fetches or the redirect's landing was never requested (so the
  absence was observed). It runs on every change to the lock and weekly, and the action itself
  runs the same check end to end. A pa11y with its first-request guard removed fails it (14 stray
  requests, the redirect target among them). `selftest-pins.sh` fails while the versions named in
  `audit.sh`'s TOKEN SCOPE note are not the ones the lock installs.
- **`verify-token` on the runner** (v1.15.1). The token never appears in a process's argv,
  in the environment `pa11y-ci`, Chromium and their npm dependencies inherit, or in a file
  another user can read. `audit.sh` writes everything into a private `mktemp -d` dir (0700),
  which the crash guard's EXIT handler removes on every path: the sitemap `curl` reads the
  header from a mode-600 file there (`-H @file`), the pa11y-ci config (which carries the
  token) is written there under `umask 077`, and `export -n VERIFY_TOKEN` follows. Before
  that, the token was in curl's argv (`ps` shows argv to every process on the runner) and in
  `/tmp/pa11y-ci.json`, world-readable and never removed. `scripts/selftest.sh` cases H–I
  pin each of these properties with stand-ins for `curl`, `pa11y-ci` and `mktemp`.
- **A scanner fault is not accessibility debt** (v1.12.0). If the audit itself breaks —
  `pa11y-ci` missing, an unwritable config, Chromium failing to start, or an abort inside
  `audit.sh` — the step reports **`a11y-audit crashed`** and exits
  `fail-on-violations ? 1 : 0`. So a report-mode caller is never newly-BLOCKED by a bug in
  this action, and an enforcing caller still stops (conservatively) rather than going green
  on an audit that never ran. Previously *any* non-zero `pa11y-ci` exit was reported as
  **"WCAG errors found"**, which blocked enforcing callers under a verdict the tool had
  never actually reached; a run where no URL produced a per-URL reporter line is now
  reported as a fault, not as debt. The guard is a `trap … EXIT` armed on the first
  executable line — **not** `trap … ERR`, because `set -u` aborts *without* firing `ERR` —
  plus a sentinel so deliberate verdicts pass through untouched. Regression-tested
  behaviourally in `scripts/selftest.sh` (stubs `pa11y-ci`, crashes the real script; runs on
  bash 5 **and** bash 3.2 in `a11y-audit-selftest.yml`).
- **Desktop viewport only** (pa11y default 1280×1024). Elements hidden at desktop width
  (e.g. a `md:hidden` mobile nav) are not exercised; audit a mobile URL separately if needed.
- **Reload-on-load resilience.** Pages that navigate a beat after first load — **LiteSpeed
  Guest Mode** (`window.location.reload`), splash/intro overlays — can race pa11y's runner
  injection and throw `Execution context was destroyed, most likely because of a navigation`
  → a flaky *Failed to run*. Primary guard is deterministic: a dummy `_lscache_vary` cookie
  makes Guest Mode skip the reload entirely (plus a 3 s settle `wait`). As defense-in-depth,
  a **single retry** kicks in only on a *run* error and only when **no** URL reported real
  violations — so the retry can never mask a WCAG failure. The decision is keyed off pa11y's
  per-URL summary lines (`> <url> - …`, ANSI-stripped), not the page's own HTML, so page
  content can't spoof it. A URL that still *Fails to run* after the retry stays non-zero and
  blocks in enforce mode.

## Refreshing the lockfile

**Who:** whoever maintains ci-actions (today Manos, or an agent session on his word): a refresh
changes what every caller runs, so it is a release like any other.

**When:** the week the `a11y-audit self-test` workflow goes red on its Monday run (a new advisory
on a locked package, an `osv-scanner.toml` exception reaching its `ignoreUntil`, a package gone
from the registry, a Chrome build no longer served), or when a new pa11y-ci release is a week old.
No calendar refresh beyond that: an exception expires within 100 days, so a lock carrying one is
reviewed at least that often, and one carrying none moves when osv.dev knows of a reason to.

**How** (from `a11y-audit/`):

1. pa11y-ci: a release at least a week old, set as an exact version in `package.json`.
2. Resolve every package to what was published at least a week ago, the way the lock was cut
   (2026-09-28, `--before=2026-09-21`):
   ```bash
   npm install --package-lock-only --ignore-scripts --no-audit --no-fund --before="$(date -u -v-7d +%F)"
   ```
   (GNU date: `date -u -d '7 days ago' +%F`.) Read what moved: `git diff package-lock.json`.
3. Advisories: `osv-scanner scan source --recursive .` (the pinned binary, or the osv.dev
   `querybatch` API). Drop the `osv-scanner.toml` entries the lock no longer needs; for one you
   keep, say why again and move its `ignoreUntil` (100 days at most).
4. The Chrome build: install the new lock in a scratch dir as the action does (`npm ci
   --ignore-scripts`) and read `node -p "require('./node_modules/puppeteer-core/lib/cjs/puppeteer/revisions.js').PUPPETEER_REVISIONS.chrome"`.
   If it moved, download
   `https://storage.googleapis.com/chrome-for-testing-public/<build>/linux64/chrome-linux64.zip`,
   hash it (`shasum -a 256`), compare its md5 (`openssl dgst -md5 -binary <zip> | base64`) with the
   bucket's record (`curl -s
   https://storage.googleapis.com/storage/v1/b/chrome-for-testing-public/o/<build>%2Flinux64%2Fchrome-linux64.zip`:
   `md5Hash`; `timeCreated` equal to `updated` and `metageneration` 1 say it was never replaced),
   and set the build and digest on chrome-for-testing's line in `security-baseline/tool-pins.txt`
   and in its comment.
5. Token scope: if pa11y or pa11y-ci moved, read the new pa11y's `lib/pa11y.js` for the
   first-request-only interception, and put the new versions in `scripts/audit.sh`'s TOKEN SCOPE
   note (`selftest-pins.sh` fails until they match); the real-install self-test then measures it.
6. `bash security-baseline/scripts/selftest-pins.sh --offline`, then a PR: the workflow's
   `real-install` and `advisories` jobs must pass on it. Then the release ritual.
