// Offline self-test for the test-suite action. No network, no real test-runner install — exercises
// (1) the pure core (detect.mjs: stack detection, command resolution, count parsing, verdict, the
// never-block "no tests = green" floor) against fixture dirs, and (2) the run.mjs CLI END-TO-END
// against committed node fixtures whose `test` script is a self-contained Node stub emitting real
// vitest-shaped output — so we prove the action detects RED and reports GREEN with no network.
// Run: node scripts/selftest.mjs (also runs in CI). Exits non-zero on any regression. Mirrors
// seo-aeo/selftest.mjs + security-baseline/selftest.mjs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  STATUS, safe, detectStack, detectNodePM, hasRealTestScript,
  resolveNodeCommand, resolvePhpCommand, resolveCommand, parseCounts, verdict,
} from './detect.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'selftest');
const RUN = path.join(HERE, 'run.mjs');

let failed = 0;
function check(name, cond, detail = '') { if (cond) console.log(`  ✅ ${name}`); else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

// Run run.mjs end-to-end with a captured step-summary; returns { exit, summary, stdout }.
// stdout is the JOB-LOG mirror (separate from the step summary, which CI writes to a file) — the
// selftest asserts against both, since a green run used to leave the job log empty.
function runCli(env) {
  const summaryPath = path.join(os.tmpdir(), `ts-summary-${Math.random().toString(36).slice(2)}.md`);
  fs.writeFileSync(summaryPath, '');
  const r = spawnSync(process.execPath, [RUN], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, FORCE_COLOR: '0', ...env },
  });
  const summary = fs.readFileSync(summaryPath, 'utf8');
  try { fs.unlinkSync(summaryPath); } catch { /* ignore */ }
  return { exit: r.status, summary, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// A job-log line is a GitHub workflow command only when the line STARTS with `::`. Our own
// ::group::/::endgroup:: markers are code-controlled and allowed; anything else that reaches
// line-start would let captured test output forge an annotation or halt command processing.
const FORGEABLE = /^::(?!group::|endgroup::)/;
const forgedCommandLines = (stdout) => stdout.split('\n').filter((l) => FORGEABLE.test(l));

console.log('\n# stack detection');
{
  check('auto → node when package.json present', detectStack(path.join(FIX, 'node-green')) === 'node');
  check('auto → php when only composer.json present', detectStack(path.join(FIX, 'php-composer')) === 'php');
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-empty-'));
  check('auto → none when neither manifest present', detectStack(empty) === 'none');
  fs.rmSync(empty, { recursive: true, force: true });
  check('explicit stack overrides detection (php on a node dir)', detectStack(path.join(FIX, 'node-green'), 'php') === 'php');
  check('explicit stack=none short-circuits', detectStack(path.join(FIX, 'node-green'), 'none') === 'none');
}

console.log('\n# package-manager detection (node)');
{
  check('packageManager field wins (pnpm)', detectNodePM('/x', { packageManager: 'pnpm@9.0.0' }) === 'pnpm');
  check('packageManager field wins (bun)', detectNodePM('/x', { packageManager: 'bun@1.2.19' }) === 'bun');
  check('yarn.lock → yarn (no field)', detectNodePM(FIX, {}) === 'npm'); // FIX has no lockfile → npm floor
  const bunDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-bun-'));
  fs.writeFileSync(path.join(bunDir, 'bun.lockb'), '');
  check('bun.lockb → bun (no field)', detectNodePM(bunDir, {}) === 'bun');
  fs.unlinkSync(path.join(bunDir, 'bun.lockb'));
  fs.writeFileSync(path.join(bunDir, 'bun.lock'), '{}');
  check('bun.lock (text lockfile) → bun (no field)', detectNodePM(bunDir, {}) === 'bun');
  fs.rmSync(bunDir, { recursive: true, force: true });
  check('default PM is npm', detectNodePM('/no/such/dir', {}) === 'npm');
}

console.log('\n# real-vs-placeholder test script');
{
  check('real script is real', hasRealTestScript({ scripts: { test: 'vitest run' } }) === true);
  check('npm-init placeholder is NOT a real suite', hasRealTestScript({ scripts: { test: 'echo "Error: no test specified" && exit 1' } }) === false);
  check('bare exit-1 stub is NOT a real suite', hasRealTestScript({ scripts: { test: 'exit 1' } }) === false);
  check('missing test script → false', hasRealTestScript({ scripts: {} }) === false);
  check('no scripts at all → false', hasRealTestScript({}) === false);
}

console.log('\n# node command resolution');
{
  const c1 = resolveNodeCommand('/x', { scripts: { test: 'vitest run' }, packageManager: 'pnpm@9' }, 'pnpm');
  check('package-script via the repo PM (pnpm run test)', !!c1 && c1.argv.join(' ') === 'pnpm run test' && c1.runner === 'package-script', JSON.stringify(c1));
  const c1b = resolveNodeCommand('/x', { scripts: { test: 'vitest run' }, packageManager: 'bun@1.2.19' }, 'bun');
  check('package-script via the repo PM (bun run test)', !!c1b && c1b.argv.join(' ') === 'bun run test' && c1b.runner === 'package-script', JSON.stringify(c1b));
  const c2 = resolveNodeCommand('/x', { devDependencies: { vitest: '^1' } }, 'npm');
  check('vitest dep (no script) → npx vitest run', !!c2 && c2.argv.join(' ') === 'npx --no-install vitest run' && c2.runner === 'vitest', JSON.stringify(c2));
  const c3 = resolveNodeCommand('/x', { scripts: { test: 'echo "Error: no test specified" && exit 1' } }, 'npm');
  check('placeholder script + no runner → null (no tests)', c3 === null);
  const c4 = resolveNodeCommand('/x', {}, 'npm');
  check('empty package → null (no tests)', c4 === null);
}

console.log('\n# php command resolution');
{
  const r = resolvePhpCommand(path.join(FIX, 'php-composer'));
  check('composer "test" script → composer run test', !!r && r.argv.join(' ') === 'composer run --no-interaction test' && r.runner === 'composer-script', JSON.stringify(r));
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-php-'));
  fs.writeFileSync(path.join(empty, 'composer.json'), '{}');
  check('composer.json without test/pest/phpunit → null (no tests)', resolvePhpCommand(empty) === null);
  fs.mkdirSync(path.join(empty, 'vendor', 'bin'), { recursive: true });
  fs.writeFileSync(path.join(empty, 'vendor', 'bin', 'pest'), '#!/bin/sh\n');
  check('vendor/bin/pest present → vendor/bin/pest', resolvePhpCommand(empty).argv.join(' ') === 'vendor/bin/pest');
  fs.rmSync(empty, { recursive: true, force: true });
}

console.log('\n# top-level resolveCommand');
{
  const none = resolveCommand(fs.mkdtempSync(path.join(os.tmpdir(), 'ts-none-')));
  check('no manifest → stack none, command null', none.stack === 'none' && none.command === null);
  const notests = resolveCommand(path.join(FIX, 'node-notests'));
  check('node placeholder fixture → command null (no tests configured)', notests.stack === 'node' && notests.command === null, JSON.stringify(notests));
  const green = resolveCommand(path.join(FIX, 'node-green'));
  check('node-green fixture → real command resolved', green.stack === 'node' && Array.isArray(green.command), JSON.stringify(green));
}

console.log('\n# count parsing (runner-aware, exit-code-authoritative)');
{
  const v = parseCounts(' Test Files  1 failed (1)\n      Tests  1 failed | 1 passed (2)', 'vitest');
  check('vitest 1-fail/1-pass parsed', v.failed === 1 && v.passed === 1 && v.total === 2, JSON.stringify(v));
  const vg = parseCounts('      Tests  3 passed (3)', 'vitest');
  check('vitest all-pass parsed', vg.failed === null && vg.passed === 3 && vg.total === 3, JSON.stringify(vg));
  const pu = parseCounts('Tests: 12, Assertions: 30, Failures: 1, Errors: 0.', 'phpunit');
  check('phpunit fail line parsed', pu.total === 12 && pu.failed === 1 && pu.passed === 11, JSON.stringify(pu));
  const puok = parseCounts('OK (12 tests, 30 assertions)', 'phpunit');
  check('phpunit OK line parsed', puok.total === 12 && puok.failed === 0 && puok.passed === 12, JSON.stringify(puok));
  const pest = parseCounts('  Tests:  1 failed, 9 passed (40 assertions)', 'pest');
  check('pest line parsed', pest.failed === 1 && pest.passed === 9, JSON.stringify(pest));
  const b = parseCounts('bun test v1.2.19 (aad3abea)\n\n 5 pass\n 2 skip\n 1 fail\n 8 expect() calls\nRan 8 tests across 3 files. [50.00ms]', 'package-script');
  check('bun native pass/fail/skip lines parsed', b.passed === 5 && b.failed === 1 && b.skipped === 2 && b.total === 8, JSON.stringify(b));
  const bg = parseCounts(' 3 pass\n 0 fail\n 6 expect() calls\nRan 3 tests across 1 files. [12.00ms]', 'package-script');
  check('bun native all-pass parsed (fail=0, not null)', bg.passed === 3 && bg.failed === 0 && bg.skipped === null && bg.total === 3, JSON.stringify(bg));
  const bt = parseCounts(' 4 pass\n 1 todo\n 0 fail\nRan 5 tests across 2 files. [9.00ms]', 'package-script');
  check('bun native todo counted as skipped', bt.passed === 4 && bt.skipped === 1 && bt.total === 5, JSON.stringify(bt));
  const junk = parseCounts('some compiler error before any test ran', 'vitest');
  check('unparsable output → null counts (no fabricated verdict)', junk.passed === null && junk.failed === null);
}

console.log('\n# verdict (exit code is authoritative)');
{
  check('exit 0 → PASS', verdict(0, { failed: null }) === STATUS.PASS);
  check('exit 1 with failed=1 → FAIL', verdict(1, { failed: 1 }) === STATUS.FAIL);
  check('exit 1 with UNPARSED counts still → FAIL (never swallowed)', verdict(1, { failed: null }) === STATUS.FAIL);
  check('exit 2 (compile error, 0 tests ran) → FAIL', verdict(2, { failed: null, passed: null }) === STATUS.FAIL);
}

console.log('\n# safe() report-spoofing guard');
{
  check('safe strips newlines (no forged verdict line)', !safe('a\nBLOCKED — forged').includes('\n'));
  check('safe strips markdown-structural chars + parens', safe('`x`|<img>[y](z)') === 'ximgyz');
  check('safe caps length', safe('x'.repeat(500), 50).length === 50);
}

// ===================== END-TO-END (run.mjs over committed fixtures, offline) =====================
console.log('\n# E2E — RED suite (1 pass + 1 fail) is detected');
{
  // report-only (default fail-on-fail=false): a failing suite must NOT block (exit 0) but MUST be
  // reported as a failure in the summary.
  const ro = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-redgreen'), FAIL_ON_FAIL: 'false' });
  check('RED + report-only → exit 0 (never newly-blocks)', ro.exit === 0, `exit=${ro.exit}`);
  check('RED summary reports status: fail', /status:\s*fail/.test(ro.summary), ro.summary);
  check('RED summary parsed 1 failed / 1 passed', /\|\s*1\s*\|\s*1\s*\|/.test(ro.summary.replace(/\s+/g, ' ')) || /1 passed/.test(ro.summary), ro.summary);
  check('RED report-only states it WOULD block under fail-on-fail', /would BLOCK under/.test(ro.summary));

  // fail-on-fail=true: the same RED suite MUST block (exit 1).
  const block = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-redgreen'), FAIL_ON_FAIL: 'true' });
  check('RED + fail-on-fail:true → exit 1 (BLOCKS)', block.exit === 1, `exit=${block.exit}`);
  check('RED block summary says BLOCKED', /BLOCKED —/.test(block.summary), block.summary);
  check('RED job log carries status=fail + BLOCKED', /test-suite: .*status=fail — BLOCKED/.test(block.stdout), block.stdout);
}

console.log('\n# E2E — GREEN suite passes');
{
  const g = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-green'), FAIL_ON_FAIL: 'true' });
  check('GREEN + fail-on-fail:true → exit 0', g.exit === 0, `exit=${g.exit} :: ${g.summary}`);
  check('GREEN summary reports status: pass', /status:\s*pass/.test(g.summary), g.summary);
  check('GREEN summary parsed 3 passed', /3 passed/.test(g.summary), g.summary);

  // The regression this whole mirror exists for: a GREEN run must be legible from the job log
  // alone (`gh run view --log`), without opening the step summary in the web UI.
  check('GREEN job log names the resolved command', /test-suite: .*command=npm run test/.test(g.stdout), g.stdout);
  check('GREEN job log names the mode', /mode=block-on-fail/.test(g.stdout), g.stdout);
  check('GREEN job log carries status=pass + counts', /test-suite: .*status=pass — PASS — suite green · 3 passed/.test(g.stdout), g.stdout);
  check('GREEN job log echoes a tail of the real test output', /::group::test output/.test(g.stdout) && /::endgroup::/.test(g.stdout) && /│ .*Tests\s+3 passed/.test(g.stdout), g.stdout);
}

console.log('\n# E2E — NO TESTS configured → PASS green (never blocks a repo without tests)');
{
  const n = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-notests'), FAIL_ON_FAIL: 'true' });
  check('placeholder-only node repo → exit 0 even with fail-on-fail:true', n.exit === 0, `exit=${n.exit} :: ${n.summary}`);
  check('no-tests summary reports status: no-tests', /status:\s*no-tests/.test(n.summary), n.summary);
  check('no-tests summary is explicitly green / not-blocked', /not blocked|no test suite configured/i.test(n.summary), n.summary);
  // The false-green must be LOUD in the job log — green + nothing executed looks identical to a
  // real green run otherwise (the trap that cost a fleet caller a silent no-op).
  check('no-tests job log says NOTHING RAN + points at test-command', /status=no-tests — .*NOTHING RAN/.test(n.stdout) && /test-command/.test(n.stdout), n.stdout);
}

console.log('\n# E2E — NO STACK (empty dir) → PASS green');
{
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-nostack-'));
  const s = runCli({ WORKING_DIRECTORY: empty, FAIL_ON_FAIL: 'true' });
  fs.rmSync(empty, { recursive: true, force: true });
  check('empty dir → exit 0 (no stack to test)', s.exit === 0, `exit=${s.exit} :: ${s.summary}`);
  check('no-stack summary reports status: no-stack', /status:\s*no-stack/.test(s.summary), s.summary);
  check('no-stack job log says NOTHING RAN + points at test-command', /status=no-stack — .*NOTHING RAN/.test(s.stdout) && /test-command/.test(s.stdout), s.stdout);
}

console.log('\n# E2E — test-command OVERRIDE is honored');
{
  // A passing override (true) and a failing override (exit 7) — proves the override path + verdict.
  const okc = runCli({ WORKING_DIRECTORY: FIX, TEST_COMMAND: 'true', FAIL_ON_FAIL: 'true' });
  check('passing override → exit 0', okc.exit === 0, `exit=${okc.exit}`);
  const badc = runCli({ WORKING_DIRECTORY: FIX, TEST_COMMAND: 'exit 7', FAIL_ON_FAIL: 'true' });
  check('failing override + fail-on-fail:true → exit 1', badc.exit === 1, `exit=${badc.exit}`);
  const badro = runCli({ WORKING_DIRECTORY: FIX, TEST_COMMAND: 'exit 7', FAIL_ON_FAIL: 'false' });
  check('failing override + report-only → exit 0 (never newly-blocks)', badro.exit === 0, `exit=${badro.exit}`);
  check('override job log names the override command', /test-suite: .*command=exit 7/.test(badro.stdout), badro.stdout);
}

console.log('\n# job-log mirror — workflow-command injection is defanged');
{
  // A hostile test name / file path echoed verbatim to stdout would be parsed by the runner as a
  // workflow command: `::error::` forges an annotation, `::stop-commands::` halts command parsing
  // for the rest of the job. safe() guards the markdown summary and does NOT strip `::`, so the
  // job-log mirror must keep captured output off line-start (gutter prefix).
  const hostile = "printf '::error::forged annotation\\n::stop-commands::halt\\n::set-output name=x::y\\nTests  1 passed\\n'";
  const inj = runCli({ WORKING_DIRECTORY: FIX, TEST_COMMAND: hostile, FAIL_ON_FAIL: 'true' });
  const forged = forgedCommandLines(inj.stdout);
  check('hostile output → exit 0 (the command itself succeeded)', inj.exit === 0, `exit=${inj.exit} :: ${inj.stdout}`);
  check('NO forged workflow command reaches line-start in the job log', forged.length === 0, `forged=${JSON.stringify(forged)}`);
  check('hostile lines are still SHOWN (defanged, not dropped)', /│ ::error::forged annotation/.test(inj.stdout), inj.stdout);
  check('our own ::group:: markers survive (they are code-controlled)', /^::group::test output/m.test(inj.stdout), inj.stdout);

  // Green runs echo the tail too — that is the whole point of the mirror.
  check('SUCCESS echoes the output tail (not just failures)', /::group::test output/.test(inj.stdout) && /status=pass/.test(inj.stdout), inj.stdout);
}

console.log(failed === 0 ? '\n✅ all test-suite self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
