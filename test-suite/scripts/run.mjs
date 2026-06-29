// test-suite CLI — detects the stack in working-directory, resolves the repo's own test command
// (detect.mjs), runs it, parses pass/fail counts, renders a GitHub step-summary table, and exits
// non-zero ONLY when a test FAILED AND fail-on-fail is set. A repo with no test config PASSES
// green (never blocks a repo that has no tests yet). Air-gapped: runs only the repo's own command.
// Mirrors seo-aeo/check.mjs + security-baseline/scan.mjs shape.
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
const ICON = { pass: '✅', fail: '❌', 'no-tests': '✅', 'no-stack': '✅', error: '❌' };
const flush = () => fs.appendFileSync(summaryFile, lines.join('\n') + '\n');

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
  note(`- working dir: \`${safe(path.relative(process.cwd(), WD) || '.', 120)}\``);

  if (!fs.existsSync(WD)) {
    note(`- ❌ working-directory \`${safe(WD)}\` does not exist`);
    note('');
    note('**status: error**');
    note(FAIL_ON_FAIL ? 'BLOCKED — working-directory missing.' : 'report-only — would BLOCK under fail-on-fail.');
    flush(); process.exit(FAIL_ON_FAIL ? 1 : 0);
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
      note('| none | — | ✅ no stack to test |');
      note('');
      note('**status: no-stack**');
      note('PASS — no test stack detected (nothing to run).');
      flush(); process.exit(0);
    }
    if (!res.command) {
      // Stack present but NO test config — green PASS, never a block.
      note(`- stack: **${stack}**${res.pm ? ` (${res.pm})` : ''} — no tests configured`);
      note(`- ${safe(res.reason, 200)}`);
      note('');
      note('| stack | tests | result |');
      note('| --- | --- | --- |');
      note(`| ${stack} | — | ✅ no tests configured |`);
      note('');
      note('**status: no-tests**');
      note('PASS — no test suite configured for this stack (a repo without tests is not blocked).');
      flush(); process.exit(0);
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
    const r = runCommand(argv, WD);
    exit = r.exit; out = r.out;
    if (r.missing) {
      note(`- ❌ test runner not found on PATH (\`${safe(argv[0])}\`) — install it in a prior step (e.g. \`${stack === 'node' ? 'npm ci' : 'composer install'}\`)`);
      note('');
      note('**status: error**');
      note(FAIL_ON_FAIL ? 'BLOCKED — test runner missing.' : 'report-only — would BLOCK under fail-on-fail.');
      flush(); process.exit(FAIL_ON_FAIL ? 1 : 0);
    }
  }

  const counts = parseCounts(out, runner);
  const status = verdict(exit, counts);

  // ---- summary table ----
  const cell = (n) => (n == null ? '—' : String(n));
  note('| stack | command | passed | failed | skipped | total | exit |');
  note('| --- | --- | ---: | ---: | ---: | ---: | ---: |');
  note(`| ${safe(stack, 12)} | \`${safe(label, 60)}\` | ${cell(counts.passed)} | ${cell(counts.failed)} | ${cell(counts.skipped)} | ${cell(counts.total)} | ${exit} |`);
  note('');

  // ---- a short tail of the runner output on failure (defanged) ----
  if (status === STATUS.FAIL) {
    const tail = String(out).split('\n').filter((l) => l.trim()).slice(-20);
    if (tail.length) {
      note('<details><summary>last lines of test output</summary>');
      note('');
      note('```');
      for (const l of tail) note(safe(l, 300));
      note('```');
      note('</details>');
      note('');
    }
  }

  // ---- verdict ----
  const failedN = counts.failed != null ? counts.failed : (status === STATUS.FAIL ? '≥1' : 0);
  note(`**status: ${status}**`);
  if (status === STATUS.FAIL) {
    if (FAIL_ON_FAIL) { note(`BLOCKED — ${failedN} test failure(s) (exit ${exit}). Fix the failing tests above.`); flush(); process.exit(1); }
    note(`report-only — ${failedN} test failure(s) (exit ${exit}) would BLOCK under \`fail-on-fail: true\`.`);
    flush(); process.exit(0);
  }
  note(`PASS — suite green${counts.passed != null ? ` (${counts.passed} passed${counts.skipped ? `, ${counts.skipped} skipped` : ''})` : ''}.`);
  flush(); process.exit(0);
})().catch((e) => {
  note(`- ❌ test-suite crashed: ${safe(String(e && e.stack || e), 400)}`);
  note('');
  note('**status: error**');
  flush(); process.exit(FAIL_ON_FAIL ? 1 : 0);
});
