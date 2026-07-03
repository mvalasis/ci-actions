# test-suite

Runs a repo's **own** test suite in CI — auto-detecting the stack (Node or PHP) and resolving the
command the repo already uses — **report-mode-first**. A repo with **no tests configured is PASS
(green)**, never a block, so you can wire this onto every repo (including ones that have no tests
yet) without newly-blocking anything. Air-gapped: it runs only the repo's own test command — no
SaaS, no telemetry.

## Severity model — report-mode-first, "no tests = green"

Like `seo-aeo`, the default is **report-only** (`fail-on-fail` defaults to `false`): wiring a
caller emits a step-summary table and exits `0` even when tests fail. Once the suite is green you
flip `fail-on-fail: true` to turn it into a real gate. Two floors keep it safe by construction:

| Situation | Exit | Why |
|---|---|---|
| No `package.json` / `composer.json` (**no stack**) | `0` (green) | nothing to test |
| Stack present but **no test config** (no `test` script / no runner / npm-init placeholder) | `0` (green) | a repo without tests is **never** blocked |
| Tests ran, all passed | `0` (green) | — |
| Tests ran, ≥1 failed, `fail-on-fail: false` (default) | `0` | **report-only** — surfaced, would block if enforcing |
| Tests ran, ≥1 failed, `fail-on-fail: true` | `1` | **BLOCKED** — the gate is enforcing |

The **exit code of the test command is authoritative** for the verdict — the parsed pass/fail
counts only enrich the summary table, so an unrecognized runner (or a compile error before any
test ran) degrades to "counts unknown", never to a wrong verdict. The npm-init placeholder
(`"test": "echo \"Error: no test specified\" && exit 1"`) is recognized as **not a real suite** and
treated as "no tests configured" (green), so it can't masquerade as a red gate.

## Stack detection & command resolution

`stack: auto` (default) picks **node** if `package.json` is present, else **php** if
`composer.json` is present, else **none**. Then the command is resolved from what the repo
actually has:

- **Node** — a real `package.json` `"test"` script via the repo's package manager (`pnpm` /
  `yarn` / `bun` / `npm`, chosen from the `packageManager` field or lockfile — `pnpm-lock.yaml`,
  `yarn.lock`, `bun.lock`/`bun.lockb`; degrades to `npm run test` with a visible ℹ️ note if the
  chosen PM isn't on PATH, so a bun repo needs bun installed in a prior step — e.g.
  `oven-sh/setup-bun@v2` — to actually run under bun); else `npx vitest run` when `vitest` is a
  (dev)dependency; else **no tests**.
- **PHP** — a `composer.json` `"test"` script → `composer test`; else `vendor/bin/pest`; else
  `vendor/bin/phpunit`; else **no tests**.

Set `test-command` to override resolution entirely (e.g. `pnpm test:ci`,
`vendor/bin/phpunit --testsuite unit`) — it runs verbatim via the shell.

> **WordPress-on-hulk repos (gitignored phar) — override is mandatory.** A WP repo that commits
> `vendor/` and does **not** run `composer install` on deploy runs PHPUnit from a **gitignored
> `phpunit.phar`** fetched at CI time — so there is no composer `test` script and no
> `vendor/bin/phpunit`, and PHP auto-detect resolves to **"no tests configured" (green) WITHOUT
> running the suite** (a silent false-green). Fetch the phar in a prior step and pass
> `test-command: 'php phpunit.phar'` to force the real run. Reference caller: `mvalasis/epn.one`
> → `.github/workflows/test-suite.yml`.

## Use it

```yaml
# .github/workflows/test-suite.yml
name: test-suite
on:
  pull_request:
  push: { branches: [main] }
  workflow_dispatch: {}
permissions: { contents: read }
jobs:
  tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # install deps in a prior step (the action runs the tests, it does not install them):
      - uses: actions/setup-node@v4
        with: { node-version: '22' }
      - run: npm ci                     # or: pnpm i --frozen-lockfile / bun install --frozen-lockfile / composer install
      - uses: mvalasis/ci-actions/test-suite@v1
        with:
          # working-directory: apps/web   # monorepo sub-package
          # stack: node                   # skip auto-detection
          # test-command: pnpm test:ci    # override resolution
          fail-on-fail: 'false'           # report-only first; flip to 'true' once green
```

The action **runs** the suite — it does **not** install dependencies or the runner. Do `npm ci` /
`pnpm i` / `composer install` in a prior step; if the runner isn't on PATH the action says so and
(in report-only) stays green.

### Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `working-directory` | no | `.` | Dir to detect the stack in and run tests from. |
| `stack` | no | `auto` | `auto` \| `node` \| `php` \| `none`. Explicit value skips detection. |
| `test-command` | no | `''` | Override the resolved command entirely (run via shell). |
| `fail-on-fail` | no | `false` | `true` = BLOCK on a test failure; `false` = report-only. |

## Offline self-test

`scripts/selftest.mjs` is a network-free regression guard with two layers: the **pure core**
(`detect.mjs` — detection, resolution, runner-aware count parsing for vitest/jest/pest/phpunit,
exit-code-authoritative verdict, the "no tests = green" floor) **and end-to-end** runs of
`run.mjs` over committed node fixtures whose `test` script is a self-contained Node stub emitting
real vitest-shaped output — so it proves the action **detects RED** (1 pass + 1 fail → reported,
and blocks under `fail-on-fail`), **reports GREEN**, and **passes green on a no-tests repo**. No
real test runner is installed and nothing touches the network.

```bash
node test-suite/scripts/selftest.mjs    # exits non-zero on any regression
```

Runs in CI on every `test-suite/**` change (`.github/workflows/test-suite-selftest.yml`), plus a
report-mode self-run smoke against this repo (which has no root suite → "no tests configured",
green).
