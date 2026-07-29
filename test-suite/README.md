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
| No `package.json` / `composer.json` (**no stack**) | `0` (green) ⚠️ **nothing ran** | nothing to test |
| Stack present but **no test config** (no `test` script / no runner / npm-init placeholder) | `0` (green) ⚠️ **nothing ran** | a repo without tests is **never** blocked |
| Tests ran, all passed | `0` (green) | — |
| Tests ran, ≥1 failed, `fail-on-fail: false` (default) | `0` | **report-only** — surfaced, would block if enforcing |
| Tests ran, ≥1 failed, `fail-on-fail: true` | `1` | **BLOCKED** — the gate is enforcing |

The two ⚠️ rows exit `0` **even under `fail-on-fail: true`** — read
[the auto-detect false-green](#-the-auto-detect-false-green--test-command-is-load-bearing) before
you trust a green tick from this action.

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

## ⚠️ The auto-detect false-green — `test-command:` is load-bearing

**Auto-detect only finds suites that look like a framework.** When it finds nothing it reports
`PASS — no stack to test` (or `no tests configured`) and **exits `0` even with
`fail-on-fail: 'true'`** — a green check mark for a job that ran **zero tests**. That is the
"never block a repo without tests" floor working as designed, and it is indistinguishable from a
real green run unless you look. Two shapes hit real callers:

| Repo shape | What auto-detect sees | Result |
|---|---|---|
| Suites are **plain scripts** (`tests/bin/run-suites.sh`, `node tests/js/*.mjs`, a `php tests/*.php` loop) with **no root `package.json` / `composer.json`** | no stack | `PASS — no stack to test`, **nothing ran** |
| WP repo running a **gitignored `phpunit.phar`** (commits `vendor/`, no `composer install` on deploy — so no composer `test` script and no `vendor/bin/phpunit`) | php stack, no config | `PASS — no tests configured`, **nothing ran** |

**Fix: pass `test-command:` explicitly.** It is not an optional nicety for these repos — it is the
only thing that makes the gate real:

```yaml
- uses: mvalasis/ci-actions/test-suite@v1
  with:
    test-command: 'bash tests/bin/run-suites.sh php'   # plain-script suite runner
    # test-command: 'php phpunit.phar'                 # gitignored-phar WP repos (epn.one)
    fail-on-fail: 'true'
```

**How to tell which you got:** the job log's verdict line says it outright —
`status=no-stack — … NOTHING RAN …` vs `status=pass — PASS — suite green · N passed`. Check it
once after wiring a caller, and again after any repo restructure that could move a manifest.

Belt-and-braces: have your runner script **fail loudly when it discovers zero suites**, so a
branch or path where the tests simply aren't present goes red instead of quietly green — the
action can only report on the command it was given.

Both shapes are live in this ecosystem: the phar one in `mvalasis/epn.one`
(`.github/workflows/test-suite.yml`), the plain-script one in a WP caller that splits js/php into
two jobs, each passing its own `test-command`.

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

## Where to read the result — job log *and* step summary

The rich table lives in the **step summary** (web UI). Since **v1.7.0** the essentials are also
mirrored to **stdout**, so `gh run view --log` alone answers "did my tests actually run?" — before
that, a green run left the job log empty between the env block and post-job cleanup:

```
test-suite: mode=block-on-fail · working-dir=. · stack=node (npm) · command=npm run test
::group::test output — last 8 line(s)
│  ✓ test/math.test.js 3 tests 4ms
│       Tests  3 passed 3
│    Duration  8ms
::endgroup::
test-suite: ✅ status=pass — PASS — suite green · 3 passed, 3 total · exit 0
```

- One `test-suite: … status=…` line on **every** path — including the early exits, where it reads
  `⚠️ status=no-stack — … NOTHING RAN …`. Grep `test-suite: ` to get command + verdict.
- The output tail is echoed on **success as well as failure** (the summary keeps its
  failure-only `<details>` pane — a green table needs no evidence).
- Captured output is defanged twice: `safe()` (CR/LF + markdown structure) **and** a `│ ` gutter,
  because GitHub treats a log line as a workflow command only when the line *starts* with `::` —
  the gutter stops a hostile test name or file path from forging an `::error::` annotation or
  firing `::stop-commands::`. The action's own `::group::` markers are code-controlled.
- ⚠️ / ✅ in the log line reflect **what was verified**, not the exit code: `no-stack` and
  `no-tests` still exit `0`, and are still marked ⚠️.
- A custom runner whose output doesn't match a known format reads `counts unparsed` — expected,
  not a fault: the **exit code** decides the verdict, counts only enrich the line (see above).

## Offline self-test

`scripts/selftest.mjs` is a network-free regression guard with two layers: the **pure core**
(`detect.mjs` — detection, resolution, runner-aware count parsing for vitest/jest/pest/phpunit
plus bun's native runner (`bun test` — bare ` N pass`/` N fail`/` N skip` lines + `Ran N tests
across M files`), exit-code-authoritative verdict, the "no tests = green" floor) **and end-to-end** runs of
`run.mjs` over committed node fixtures whose `test` script is a self-contained Node stub emitting
real vitest-shaped output — so it proves the action **detects RED** (1 pass + 1 fail → reported,
and blocks under `fail-on-fail`), **reports GREEN**, and **passes green on a no-tests repo**. No
real test runner is installed and nothing touches the network.

It also pins the **job-log mirror**: every path emits a `test-suite: … status=…` line, a green run
echoes a real output tail, the two nothing-ran paths say `NOTHING RAN` and name `test-command`,
and a test command that prints `::error::` / `::stop-commands::` / `::set-output` **cannot** get
those to line-start in the log (they stay visible behind the gutter) while the action's own
`::group::` markers survive.

```bash
node test-suite/scripts/selftest.mjs    # exits non-zero on any regression
```

Runs in CI on every `test-suite/**` change (`.github/workflows/test-suite-selftest.yml`), plus a
report-mode self-run smoke against this repo (which has no root manifest → `status=no-stack`,
green — the false-green shape above, deliberately, as a live sample of what it looks like).
