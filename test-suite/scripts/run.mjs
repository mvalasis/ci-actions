// test-suite CLI — detects the stack in working-directory, resolves the repo's own test command
// (detect.mjs), runs it, parses pass/fail counts, renders a GitHub step-summary table, mirrors a
// compact run log to STDOUT (so `gh run view --log` can answer "did my tests actually run?"), and
// exits non-zero ONLY when a test FAILED AND fail-on-fail is set. A repo with no test config
// PASSES green (never blocks a repo that has no tests yet). Air-gapped: runs only the repo's own
// command. Mirrors seo-aeo/check.mjs + security-baseline/scan.mjs shape.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { STATUS, safe, resolveCommand, parseCounts, verdict } from './detect.mjs';

const env = process.env;
const WD = path.resolve(env.WORKING_DIRECTORY || '.');
const STACK = (env.STACK || 'auto').trim();
const TEST_COMMAND = (env.TEST_COMMAND || '').trim();
const FAIL_ON_FAIL = (env.FAIL_ON_FAIL || 'false').trim() === 'true';

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const lines = [];
const note = (s = '') => lines.push(s);
// Job-log verdict icons. no-stack / no-tests are ⚠️ rather than ✅ ON PURPOSE: both exit 0 (the
// "a repo without tests is never blocked" floor stands), but nothing was verified — rendering
// them as a green tick is the false-green this mirror exists to expose.
const ICON = { pass: '✅', fail: '❌', 'no-tests': '⚠️', 'no-stack': '⚠️', error: '❌' };
const flush = () => fs.appendFileSync(summaryFile, lines.join('\n') + '\n');

const MODE = FAIL_ON_FAIL ? 'block-on-fail' : 'report-only';
const WD_REL = safe(path.relative(process.cwd(), WD) || '.', 120);
const TAIL_LINES = 20;
const tailOf = (out, n = TAIL_LINES) => String(out).split('\n').filter((l) => l.trim()).slice(-n);

// ---------- job-log mirror (stdout) ----------
// The step summary is only readable in the web UI, so a green run used to leave the JOB LOG
// empty — `gh run view --log` could not tell a real green suite from a silent "no stack to test"
// false-green. Every terminal path now prints one `test-suite: status=…` line, and the runner's
// own output is tailed here on SUCCESS as well as failure (proof the suite ran is the point).
// fs.writeSync, not console.log: process.stdout writes are ASYNC on macOS pipes (synchronous on
// Linux/Windows), and every path here ends in process.exit(), which does not drain a pending
// async write. CI runs on Linux so it would be safe there, but the verdict line must never be
// the thing that goes missing — that is the bug this mirror exists to fix.
const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };

// Captured runner output is defanged TWICE on its way to the job log: safe() strips CR/LF and
// markdown structure (the summary-spoofing guard), and every echoed line is printed behind a
// gutter. GitHub parses a log line as a workflow command only when the line STARTS with `::`, so
// the gutter makes an `::error::` / `::stop-commands::` embedded in a hostile test name or file
// path inert instead of letting it forge an annotation — safe() guards markdown, and knows
// nothing about workflow commands. Our own `::group::` markers are code-controlled, never input.
const GUTTER = '│ ';
function echoTail(tail) {
  if (!tail.length) return;
  say(`::group::test output — last ${tail.length} line(s)`);
  for (const l of tail) say(GUTTER + safe(l, 300));
  say('::endgroup::');
}

// Single exit funnel: guarantees the job log carries a verdict line on EVERY path, including the
// early green ones (no-stack / no-tests) that are the easiest to mistake for "tests ran".
function finish(status, detail, code) {
  say(`test-suite: ${ICON[status] || ''} status=${status} — ${detail}`);
  flush();
  process.exit(code);
}

// Resolve a PM/runner binary to an absolute path so a spawn without a shell still finds it; falls
// back to npm for a node package-script when the chosen PM isn't on PATH (corepack-less runner).
function onPath(bin) {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'command', process.platform === 'win32' ? [bin] : ['-v', bin], { encoding: 'utf8', shell: true });
  return r.status === 0 && (r.stdout || '').trim() ? (r.stdout || '').trim().split('\n')[0] : '';
}

function runCommand(argv, cwd) {
  // No shell: argv is a fixed, code-resolved vector (never interpolated from page/tool input),
  // so there is nothing to quote and no injection surface.
  const r = spawnSync(argv[0], argv.slice(1), {
    cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 30 * 60 * 1000,
    env: { ...env, CI: 'true', FORCE_COLOR: '0' },
  });
  const out = (r.stdout || '') + '\n' + (r.stderr || '');
  if (r.error && r.error.code === 'ENOENT') return { exit: 127, out, missing: true };
  return { exit: r.status == null ? 1 : r.status, out, missing: false, signal: r.signal || null };
}

// A test-command override is run via the shell (it may be a compound like `pnpm test:ci`); detect
// resolution returns a fixed argv vector run without a shell.
function runShell(cmd, cwd) {
  const r = spawnSync(cmd, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 30 * 60 * 1000, shell: true, env: { ...env, CI: 'true', FORCE_COLOR: '0' } });
  const out = (r.stdout || '') + '\n' + (r.stderr || '');
  return { exit: r.status == null ? 1 : r.status, out, missing: false, signal: r.signal || null };
}

(async () => {
  note('## 🧪 test-suite — per-stack test run');
  note('');
  note(`- mode: ${FAIL_ON_FAIL ? '**BLOCK on test failure**' : 'report-only (never blocks)'}`);
  note(`- working dir: \`${WD_REL}\``);

  if (!fs.existsSync(WD)) {
    note(`- ❌ working-directory \`${safe(WD)}\` does not exist`);
    note('');
    note('**status: error**');
    note(FAIL_ON_FAIL ? 'BLOCKED — working-directory missing.' : 'report-only — would BLOCK under fail-on-fail.');
    finish('error', `working-directory ${safe(WD)} does not exist${FAIL_ON_FAIL ? '' : ' — report-only, would BLOCK under fail-on-fail:true'}`, FAIL_ON_FAIL ? 1 : 0);
  }

  let label, runner, stack, exit, out;

  if (TEST_COMMAND) {
    // Explicit override — stack detection is for the label only.
    const res = resolveCommand(WD, STACK);
    stack = res.stack;
    label = TEST_COMMAND;
    runner = 'override';
    note(`- stack: ${stack === 'none' ? 'none (override)' : `**${stack}**`} · command: \`${safe(TEST_COMMAND, 160)}\` (override)`);
    note('');
    say(`test-suite: mode=${MODE} · working-dir=${WD_REL} · stack=${stack} (override) · command=${safe(TEST_COMMAND, 160)}`);
    const r = runShell(TEST_COMMAND, WD);
    exit = r.exit; out = r.out;
  } else {
    const res = resolveCommand(WD, STACK);
    stack = res.stack;
    if (res.stack === 'none') {
      note(`- stack: none — ${safe(res.reason, 160)}`);
      note('');
      note('| stack | tests | result |');
      note('| --- | --- | --- |');
      note('| none | — | ⚠️ no stack to test — **nothing ran** |');
      note('');
      note('**status: no-stack**');
      note('PASS (exit 0) — no test stack detected, so **nothing ran** — this is green even under `fail-on-fail: true`. If this repo does have tests, set `test-command:`: auto-detect only finds framework-shaped suites (a root `package.json` / `composer.json`), not plain scripts.');
      // Loud in the job log on purpose: this is the false-green shape — green with fail-on-fail:
      // true and NO suite executed. A repo whose tests are plain scripts needs `test-command:`.
      finish('no-stack', `PASS — no stack detected, NOTHING RAN (${safe(res.reason, 160)}). Set \`test-command:\` if this repo does have tests.`, 0);
    }
    if (!res.command) {
      // Stack present but NO test config — green PASS, never a block.
      note(`- stack: **${stack}**${res.pm ? ` (${res.pm})` : ''} — no tests configured`);
      note(`- ${safe(res.reason, 200)}`);
      note('');
      note('| stack | tests | result |');
      note('| --- | --- | --- |');
      note(`| ${stack} | — | ⚠️ no tests configured — **nothing ran** |`);
      note('');
      note('**status: no-tests**');
      note('PASS (exit 0) — no test suite configured for this stack, so **nothing ran** (a repo without tests is not blocked). If this repo does have tests the resolver could not see them — set `test-command:` to force the real run.');
      finish('no-tests', `PASS — stack ${stack} but no suite configured, NOTHING RAN (${safe(res.reason, 160)}). Set \`test-command:\` if this repo does have tests.`, 0);
    }

    label = res.label; runner = res.runner;
    note(`- stack: **${stack}**${res.pm ? ` (${res.pm})` : ''} · command: \`${safe(label, 160)}\``);
    note('');

    // For a node package-script, if the chosen PM isn't on PATH degrade to npm (corepack-less
    // runner) — the script body is the same regardless of which PM invokes `run test`.
    let argv = res.command;
    if (res.stack === 'node' && runner === 'package-script') {
      const pm = argv[0];
      if (pm !== 'npm' && !onPath(pm)) { argv = ['npm', 'run', 'test']; note(`- ℹ️ \`${pm}\` not on PATH — degraded to \`npm run test\``); }
    }
    // Echoed AFTER the PM-degrade check so the job log names the command actually executed.
    say(`test-suite: mode=${MODE} · working-dir=${WD_REL} · stack=${stack}${res.pm ? ` (${res.pm})` : ''} · command=${safe(argv.join(' '), 160)}`);
    const r = runCommand(argv, WD);
    exit = r.exit; out = r.out;
    if (r.missing) {
      note(`- ❌ test runner not found on PATH (\`${safe(argv[0])}\`) — install it in a prior step (e.g. \`${stack === 'node' ? 'npm ci' : 'composer install'}\`)`);
      note('');
      note('**status: error**');
      note(FAIL_ON_FAIL ? 'BLOCKED — test runner missing.' : 'report-only — would BLOCK under fail-on-fail.');
      finish('error', `test runner not found on PATH (${safe(argv[0])}) — install it in a prior step${FAIL_ON_FAIL ? '' : ' · report-only, would BLOCK under fail-on-fail:true'}`, FAIL_ON_FAIL ? 1 : 0);
    }
  }

  const counts = parseCounts(out, runner);
  const status = verdict(exit, counts);
  const countsLine = [
    counts.passed != null ? `${counts.passed} passed` : null,
    counts.failed != null ? `${counts.failed} failed` : null,
    counts.skipped ? `${counts.skipped} skipped` : null,
    counts.total != null ? `${counts.total} total` : null,
  ].filter(Boolean).join(', ') || 'counts unparsed';

  // ---- summary table ----
  const cell = (n) => (n == null ? '—' : String(n));
  note('| stack | command | passed | failed | skipped | total | exit |');
  note('| --- | --- | ---: | ---: | ---: | ---: | ---: |');
  note(`| ${safe(stack, 12)} | \`${safe(label, 60)}\` | ${cell(counts.passed)} | ${cell(counts.failed)} | ${cell(counts.skipped)} | ${cell(counts.total)} | ${exit} |`);
  note('');

  // ---- a short tail of the runner output (defanged) ----
  // Summary: only on failure — a green table needs no evidence pane. Job log: ALWAYS, because
  // "the suite really executed" is exactly what the log could not previously show.
  const tail = tailOf(out);
  if (status === STATUS.FAIL && tail.length) {
    note('<details><summary>last lines of test output</summary>');
    note('');
    note('```');
    for (const l of tail) note(safe(l, 300));
    note('```');
    note('</details>');
    note('');
  }
  echoTail(tail);

  // ---- verdict ----
  const failedN = counts.failed != null ? counts.failed : (status === STATUS.FAIL ? '≥1' : 0);
  note(`**status: ${status}**`);
  if (status === STATUS.FAIL) {
    if (FAIL_ON_FAIL) {
      note(`BLOCKED — ${failedN} test failure(s) (exit ${exit}). Fix the failing tests above.`);
      finish(status, `BLOCKED — ${failedN} test failure(s) · ${countsLine} · exit ${exit}`, 1);
    }
    note(`report-only — ${failedN} test failure(s) (exit ${exit}) would BLOCK under \`fail-on-fail: true\`.`);
    finish(status, `report-only — ${failedN} test failure(s) · ${countsLine} · exit ${exit} — would BLOCK under fail-on-fail:true`, 0);
  }
  note(`PASS — suite green${counts.passed != null ? ` (${counts.passed} passed${counts.skipped ? `, ${counts.skipped} skipped` : ''})` : ''}.`);
  finish(status, `PASS — suite green · ${countsLine} · exit ${exit}`, 0);
})().catch((e) => {
  note(`- ❌ test-suite crashed: ${safe(String(e && e.stack || e), 400)}`);
  note('');
  note('**status: error**');
  finish('error', `test-suite crashed: ${safe(String(e && e.message || e), 200)}`, FAIL_ON_FAIL ? 1 : 0);
});
