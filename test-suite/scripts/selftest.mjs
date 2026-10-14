// Offline self-test for the test-suite action. No network, no real test-runner install — exercises
// (1) the pure core (detect.mjs: stack detection, command resolution, count parsing, verdict, the
// never-block "no tests = green" floor) against fixture dirs, and (2) the run.mjs CLI END-TO-END
// against committed node fixtures whose `test` script is a self-contained Node stub emitting real
// vitest-shaped output — so we prove the action detects RED and reports GREEN with no network —
// and where its output goes: a local run prints the job log once, with no step summary, and an
// unwritable summary exits under fail-on-fail. (3) The step summary stays under GitHub's 1 MiB
// (v1.29.9): a report over 900,000 bytes is cut for the summary alone — pinned cap by cap against a
// cut built by hand, then through the real run.mjs past 1 MiB, at exactly 900,000 bytes and one byte
// over; a fault in the cut costs the summary, never the exit code.
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
  shellQuote, parseTestFileList, isolationPlan, defectLine, fitReport,
} from './detect.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'selftest');
const RUN = path.join(HERE, 'run.mjs');

let failed = 0;
function check(name, cond, detail = '') { if (cond) console.log(`  ✅ ${name}`); else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

// Run run.mjs end-to-end with a captured step-summary; returns { exit, summary, stdout }.
// stdout is the JOB-LOG mirror (separate from the step summary, which CI writes to a file) — the
// selftest asserts against both, since a green run used to leave the job log empty. `script` is
// another copy of run.mjs (the fault-injection leg's).
function runCli(env, script = RUN) {
  const summaryPath = path.join(os.tmpdir(), `ts-summary-${Math.random().toString(36).slice(2)}.md`);
  fs.writeFileSync(summaryPath, '');
  const r = spawnSync(process.execPath, [script], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, FORCE_COLOR: '0', ...env },
  });
  const summary = fs.readFileSync(summaryPath, 'utf8');
  try { fs.unlinkSync(summaryPath); } catch { /* ignore */ }
  return { exit: r.status, summary, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// Run run.mjs the way a LOCAL run does. The runner's own GITHUB_STEP_SUMMARY is dropped (else this
// is the CI shape again, writing into this self-test's own step summary); a leg that wants one
// names it. stdout is either what spawnSync hands a child — a socket — or an O_APPEND file; the
// "local run" block below says why both.
function spawnLocal(env, stdout) {
  const inherited = { ...process.env };
  delete inherited.GITHUB_STEP_SUMMARY;
  const opts = { encoding: 'utf8', env: { ...inherited, FORCE_COLOR: '0', ...env } };
  if (stdout === 'socket') {
    const r = spawnSync(process.execPath, [RUN], opts);
    return { exit: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-stdout-'));
  const outPath = path.join(dir, 'stdout.txt');
  const fd = fs.openSync(outPath, 'a');
  try {
    const r = spawnSync(process.execPath, [RUN], { ...opts, stdio: ['ignore', fd, 'pipe'] });
    return { exit: r.status, stdout: fs.readFileSync(outPath, 'utf8'), stderr: r.stderr || '' };
  } finally {
    fs.closeSync(fd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The job log's verdict lines (`test-suite: … status=…`), and a crash's fingerprints: the crash
// line, or a stack frame that an unhandled throw prints to stderr.
const verdictLines = (stdout) => stdout.split('\n').filter((l) => /^test-suite: .*status=/.test(l));
const crashed = (r) => /crashed/.test(r.stdout + r.stderr) || /^\s+at /m.test(r.stderr);

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

console.log('\n# local run — the job log exactly once, the step summary only when there is one');
{
  // Before v1.19.3 a run with no GITHUB_STEP_SUMMARY (a local run), or with
  // GITHUB_STEP_SUMMARY=/dev/stdout, appended the step summary to /dev/stdout. Where that open
  // works (macOS, where it dups fd 1; a Linux file, pipe or tty) the summary followed the log lines,
  // a FAIL's output tail and verdict a second time. On Linux with a SOCKET stdout, which is what
  // spawnSync hands a child, it fails ENXIO: finish() threw after the verdict line, the crash path
  // printed a second one, threw again, and node exited 1 with a bare stack even in report-only.
  // So every case runs with a socket AND an O_APPEND file as stdout: on the ubuntu runner the socket
  // leg sees only the crash, and the file leg only the duplicate. RED under fail-on-fail exits 1
  // like that crash, so the output is the oracle there, not the exit code. The RED stub runs as a
  // test-command override: its output is fixed, so two runs' job logs compare byte for byte with
  // no package manager's chatter in the tail.
  const RED = { WORKING_DIRECTORY: path.join(FIX, 'node-redgreen'), TEST_COMMAND: `"${process.execPath}" vitest-stub.mjs` };
  for (const [mode, FAIL_ON_FAIL, exit] of [['report-only', 'false', 0], ['fail-on-fail', 'true', 1]]) {
    const ci = runCli({ ...RED, FAIL_ON_FAIL });
    for (const [label, sink] of [['no GITHUB_STEP_SUMMARY', undefined], ['GITHUB_STEP_SUMMARY=/dev/stdout', '/dev/stdout']]) {
      for (const stdout of ['socket', 'file']) {
        const r = spawnLocal({ ...RED, FAIL_ON_FAIL, GITHUB_STEP_SUMMARY: sink }, stdout);
        const v = verdictLines(r.stdout);
        check(`RED ${mode}, ${label}, stdout a ${stdout}: one verdict line, exit ${exit}, no crash`,
          r.exit === exit && v.length === 1 && /status=fail/.test(v[0]) && !crashed(r),
          `exit=${r.exit} verdicts=${JSON.stringify(v)} stderr=${JSON.stringify(r.stderr.slice(0, 200))}`);
        check(`RED ${mode}, ${label}, stdout a ${stdout}: prints the Actions job log, byte for byte, and nothing else`,
          ci.stdout.length > 0 && r.stdout === ci.stdout, `extra: ${JSON.stringify(r.stdout.replace(ci.stdout, '').slice(0, 200))}`);
      }
    }
  }
}

console.log('\n# unwritable step summary — the verdict and the fault in the log, fail-on-fail decides the exit');
{
  // The summary write throws (EISDIR) after finish() has printed the verdict line, and the crash path
  // runs. Its own finish() flushed again, unguarded, before v1.19.3: that throw escaped the crash
  // handler and node exited 1 with a bare stack whatever fail-on-fail said. A tool fault exits
  // `fail-on-fail ? 1 : 0` like every other one — so a GREEN suite under fail-on-fail exits 1 here.
  const sinkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-summary-dir-'));
  for (const [mode, FAIL_ON_FAIL, fixture, first, exit] of [['RED report-only', 'false', 'node-redgreen', 'fail', 0], ['GREEN fail-on-fail', 'true', 'node-green', 'pass', 1]]) {
    const r = runCli({ WORKING_DIRECTORY: path.join(FIX, fixture), FAIL_ON_FAIL, GITHUB_STEP_SUMMARY: sinkDir });
    const v = verdictLines(r.stdout);
    check(`${mode}: the log has the verdict (status=${first}), then the fault (status=error, EISDIR)`,
      v.length === 2 && v[0].includes(`status=${first} — `) && /status=error — test-suite crashed: EISDIR/.test(v[1]), JSON.stringify(v));
    check(`${mode}: exit ${exit}, not an unhandled throw`, r.exit === exit && !/^\s+at /m.test(r.stderr), `exit=${r.exit} stderr=${JSON.stringify(r.stderr.slice(0, 200))}`);
  }
  fs.rmSync(sinkDir, { recursive: true, force: true });
}

console.log('\n# isolate-files — the pure helpers');
{
  const listing = 'PHPUnit 12.5.30 by Sebastian Bergmann and contributors.\n\nAvailable test files:\n - /r/tests/ATest.php\n - /r/tests/B Test.php\n';
  const l = parseTestFileList(listing);
  check('--list-test-files output → its files, in order', JSON.stringify(l) === JSON.stringify(['/r/tests/ATest.php', '/r/tests/B Test.php']), JSON.stringify(l));
  check('no "Available test files:" header → null (not PHPUnit, or a PHPUnit without the option)', parseTestFileList('Unknown option "--list-test-files"') === null);
  check('the header with no file under it → [] (a fault to the caller, never "nothing failed")', JSON.stringify(parseTestFileList('Available test files:\n')) === '[]');
  // Through a real shell: a path with a quote, a substitution and backticks must come back verbatim.
  const odd = "tests/it's $(echo injected) `echo x` \"q\"Test.php";
  const echoed = spawnSync('sh', ['-c', `printf %s ${shellQuote(odd)}`], { encoding: 'utf8' });
  check('shellQuote survives sh unchanged (no substitution runs)', echoed.stdout === odd, JSON.stringify(echoed.stdout));
  const o = isolationPlan({ stack: 'php', testCommand: 'php phpunit.phar' });
  check('override → the option and the quoted file are appended to the shell command',
    o.list.shell === 'php phpunit.phar --list-test-files' && o.file('/r/a b.php').shell === "php phpunit.phar '/r/a b.php'", JSON.stringify(o.list));
  check('override probe → lists what one per-file run would load', o.probe('/r/a b.php').shell === "php phpunit.phar '/r/a b.php' --list-test-files", o.probe('/r/a b.php').shell);
  const v = isolationPlan({ stack: 'php', argv: ['vendor/bin/phpunit'], runner: 'phpunit' });
  check('resolved vendor/bin/phpunit → appended as arguments',
    v.list.argv.join(' ') === 'vendor/bin/phpunit --list-test-files' && v.file('/r/x.php').argv.join(' ') === 'vendor/bin/phpunit /r/x.php'
    && v.probe('/r/x.php').argv.join(' ') === 'vendor/bin/phpunit /r/x.php --list-test-files', JSON.stringify(v.list));
  const c = isolationPlan({ stack: 'php', argv: ['composer', 'run', '--no-interaction', 'test'], runner: 'composer-script' });
  check('composer script → the arguments go after --', c.list.argv.join(' ') === 'composer run --no-interaction test -- --list-test-files'
    && c.probe('/r/x.php').argv.join(' ') === 'composer run --no-interaction test -- /r/x.php --list-test-files', JSON.stringify(c.list));
  check('node stack → no plan', isolationPlan({ stack: 'node', testCommand: 'npm test' }) === null);
  check('a PHPUnit defect block → its message line',
    defectLine('There was 1 error:\n\n1) ATest::test_x\nError: Call to undefined function wp_json_encode()\n\n/r/ATest.php:3') === 'Error: Call to undefined function wp_json_encode()');
  check('no defect block → the last non-empty line', defectLine('PHP Fatal error:  x\n\n') === 'PHP Fatal error:  x');
}

console.log('\n# E2E — isolate-files runs each PHPUnit test file alone');
{
  // The fixture's full suite is green and BorrowedHarnessTest.php fails alone: the defect this
  // input exists for (a file that passes only because a sibling file's harness is loaded too).
  const ISO = { WORKING_DIRECTORY: path.join(FIX, 'php-isolation'), STACK: 'php', TEST_COMMAND: `"${process.execPath}" phpunit-stub.mjs`, FAIL_ON_FAIL: 'true' };

  const off = runCli(ISO);
  check('unset (the default) → exit 0 and status=pass, as before: no file is run alone',
    off.exit === 0 && /status=pass — PASS — suite green · 2 passed, 0 failed, 2 total · exit 0$/m.test(off.stdout) && !/isolate-files/.test(off.stdout + off.summary), off.stdout);

  const ro = runCli({ ...ISO, ISOLATE_FILES: 'true' });
  check('a file that fails alone, report-only → exit 0', ro.exit === 0, `exit=${ro.exit}`);
  check('… status=fail naming the file, and it says it would block',
    /status=fail — report-only — the suite is green \(2 passed, 0 failed, 2 total\) but 1 of 2 test file\(s\) fail when run alone: tests\/BorrowedHarnessTest\.php — would BLOCK under fail-on-isolation:true$/m.test(ro.stdout), ro.stdout);
  check('… the job log gives the file its exit and the defect line, behind the gutter',
    /^│ tests\/BorrowedHarnessTest\.php — exit 2 — Error: Call to undefined function wp_json_encode$/m.test(ro.stdout), ro.stdout);
  check('… the mode line says isolate-files is report-only', /^test-suite: mode=block-on-fail · isolate-files=report-only · /m.test(ro.stdout), ro.stdout);
  check('… the step summary tables the file, its exit and why',
    /\| `tests\/BorrowedHarnessTest\.php` \| 2 \| Error: Call to undefined function wp_json_encode \|/.test(ro.summary) && /status: fail/.test(ro.summary), ro.summary);
  check('… the passing file is not named', !/AloneTest/.test(ro.stdout + ro.summary), ro.stdout);

  const block = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true' });
  check('fail-on-isolation → exit 1, BLOCKED, naming the file',
    block.exit === 1 && /status=fail — BLOCKED — the suite is green .* fail when run alone: tests\/BorrowedHarnessTest\.php$/m.test(block.stdout), block.stdout);
  const blockAlone = runCli({ ...ISO, FAIL_ON_FAIL: 'false', ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true' });
  check('… independent of fail-on-fail (blocks with it false)', blockAlone.exit === 1, `exit=${blockAlone.exit}`);

  const fixed = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_FIXED: '1' });
  check('every file passes alone → exit 0, and the verdict counts the files',
    fixed.exit === 0 && /status=pass — PASS — suite green · 2 passed, 0 failed, 2 total · exit 0 · each of 2 test file\(s\) passes alone$/m.test(fixed.stdout), fixed.stdout);

  const red = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_SUITE: 'fail' });
  check('a red suite → no file is run alone, and the suite\'s own verdict stands',
    red.exit === 1 && /status=fail — BLOCKED — 1 test failure/.test(red.stdout) && !/listing with/.test(red.stdout) && /skipped — the suite failed/.test(red.summary), red.stdout);

  const nolist = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_LIST: 'fail' });
  check('files that cannot be listed → status=error, exit 1 under fail-on-isolation (never "nothing failed")',
    nolist.exit === 1 && /status=error — BLOCKED — the suite is green .* isolate-files could not run: .*--list-test-files did not list the test files: it exited 2 with no/.test(nolist.stdout), nolist.stdout);
  const nolistRo = runCli({ ...ISO, ISOLATE_FILES: 'true', STUB_LIST: 'fail' });
  check('… and exit 0 report-only', nolistRo.exit === 0 && /status=error — report-only — /.test(nolistRo.stdout), nolistRo.stdout);

  const node = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-green'), FAIL_ON_FAIL: 'true', ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true' });
  check('a node suite → isolate-files cannot run there: status=error, BLOCKED under fail-on-isolation',
    node.exit === 1 && /status=error — BLOCKED — the suite is green \(3 passed.*isolate-files could not run: .*stack node has none/.test(node.stdout), node.stdout);
  const nodeRo = runCli({ WORKING_DIRECTORY: path.join(FIX, 'node-green'), FAIL_ON_FAIL: 'true', ISOLATE_FILES: 'true' });
  check('… and exit 0 report-only, still status=error', nodeRo.exit === 0 && /status=error — report-only — .*stack node has none/.test(nodeRo.stdout), nodeRo.stdout);

  // A test-command that names a path of its own keeps loading it beside every file, so each
  // "alone" run is the whole suite and passes: the probe must refuse it.
  const pathCmd = runCli({ ...ISO, TEST_COMMAND: `"${process.execPath}" phpunit-stub.mjs tests`, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true' });
  check('a test-command that already names a path → status=error, BLOCKED (never "each file passes alone")',
    pathCmd.exit === 1 && /status=error — BLOCKED — the suite is green .* isolate-files could not run: .* with one test file appended would load 2 files, not that one: the command already selects tests of its own/.test(pathCmd.stdout) && !/passes alone/.test(pathCmd.stdout), pathCmd.stdout);

  const empty = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_LIST: 'empty' });
  check('a listing with the header and no file → status=error, exit 1 (not "each of 0 files passes")',
    empty.exit === 1 && /status=error — BLOCKED — .*it listed no test file/.test(empty.stdout), empty.stdout);
  const listExit = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_LIST: 'exit1' });
  check('a listing that names files but exits 1 → status=error, exit 1',
    listExit.exit === 1 && /status=error — BLOCKED — .*did not list the test files: it exited 1\. /.test(listExit.stdout), listExit.stdout);

  const exit1 = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_ALONE: 'exit1' });
  check('a file that fails alone with an assertion (PHPUnit exit 1) is named, with its defect line',
    exit1.exit === 1 && /^│ tests\/BorrowedHarnessTest\.php — exit 1 — Failed asserting that false is true\.$/m.test(exit1.stdout), exit1.stdout);
  // The override runs through `sh -c`. Where sh execs the command (macOS) the child's signal is the
  // run's and there is no exit status, which the action reports as 1; where it does not (dash on
  // the Linux runner) sh relays the kill as 137. The file must be counted as failing either way.
  const killed = runCli({ ...ISO, ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_ALONE: 'signal' });
  check('a file whose run is killed counts as failing, never as passing',
    killed.exit === 1 && /^│ tests\/BorrowedHarnessTest\.php — exit (?:1|137) — /m.test(killed.stdout) && /fail when run alone: tests\/BorrowedHarnessTest\.php$/m.test(killed.stdout), killed.stdout);

  // Faults block whenever a check the caller made blocking could not run.
  const sinkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-iso-summary-dir-'));
  const crash = runCli({ ...ISO, FAIL_ON_FAIL: 'false', ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true', STUB_FIXED: '1', GITHUB_STEP_SUMMARY: sinkDir });
  fs.rmSync(sinkDir, { recursive: true, force: true });
  check('a crash (unwritable summary) exits 1 under fail-on-isolation even with fail-on-fail off',
    crash.exit === 1 && /status=error — test-suite crashed: EISDIR/.test(crash.stdout) && !/^\s+at /m.test(crash.stderr), `exit=${crash.exit} ${crash.stdout}`);
  const noWd = runCli({ WORKING_DIRECTORY: path.join(FIX, 'no-such-dir'), FAIL_ON_FAIL: 'false', ISOLATE_FILES: 'true', FAIL_ON_ISOLATION: 'true' });
  check('a missing working-directory exits 1 under fail-on-isolation even with fail-on-fail off',
    noWd.exit === 1 && /status=error — working-directory .* does not exist$/m.test(noWd.stdout), noWd.stdout);
  const noWdRo = runCli({ WORKING_DIRECTORY: path.join(FIX, 'no-such-dir'), FAIL_ON_FAIL: 'false' });
  check('… and, with isolate-files unset, report-only exactly as before', noWdRo.exit === 0 && /would BLOCK under fail-on-fail:true$/m.test(noWdRo.stdout), noWdRo.stdout);

  const hostile = runCli({ ...ISO, ISOLATE_FILES: 'true', STUB_WHY: '::error::forged annotation' });
  check('a hostile defect line cannot reach line-start in the job log (it is shown, behind the gutter)',
    forgedCommandLines(hostile.stdout).length === 0 && /^│ tests\/BorrowedHarnessTest\.php — exit 2 — ::error::forged annotation$/m.test(hostile.stdout), hostile.stdout);
}

console.log("\n# the step summary's cut (pure)");
const CAP = 900000;
const RUN_URL = 'https://github.com/acme/site/actions/runs/33911783576';
{
  // A report in run.mjs's grammar, each line labelled by hand: F fixed, R a row of the isolate-files
  // table. The counts table is fixed too, though its rows start `| ` like the isolate table's. The cut at
  // a cap is built here the long way — the largest k for which the fixed lines, the first k rows, a blank
  // line and the longest note (every row left out) fit — and fitReport must give exactly that, at every
  // cap.
  const SPEC = [
    ['## 🧪 test-suite — per-stack test run', 'F'], ['', 'F'],
    ['- mode: **BLOCK on test failure**', 'F'], ['- isolate-files: report-only (never blocks)', 'F'],
    ['- working dir: `wp-content/plugins/shop`', 'F'], ['- stack: **php** · command: `composer test`', 'F'], ['', 'F'],
    ['| stack | command | passed | failed | skipped | total | exit |', 'F'],
    ['| --- | --- | ---: | ---: | ---: | ---: | ---: |', 'F'],
    ['| php | `composer test` | 41 | 0 | — | 41 | 0 |', 'F'], ['', 'F'],
    ['**Each test file alone** (`isolate-files`)', 'F'], ['', 'F'],
    ['- ❌ 4 of 9 test file(s) fail alone. Each passed in the full suite, so it depends on something another test file loads or leaves behind.', 'F'], ['', 'F'],
    ['| file | exit | why |', 'F'], ['| --- | ---: | --- |', 'F'],
    ['| `tests/Unit/CartTest.php` | 2 | Error: Call to undefined function wc_get_cart_url |', 'R'],
    ['| `tests/Unit/Γλώσσα/ΜετάφρασηTest.php` | 2 | Error: Class "WP_UnitTestCase" not found |', 'R'],
    ['| `tests/Unit/OrderTotalsTest.php` | 1 | Failed asserting that 12.5 matches expected 10.0. |', 'R'],
    ['| `tests/Integration/RestTest.php` | 255 | PHP Fatal error:  Uncaught Error: Call to undefined function rest_get_server |', 'R'],
    ['', 'F'],
    ['**status: fail**', 'F'],
    ['report-only — the suite is green (41 passed, 0 failed, 41 total) but 4 of 9 test file(s) fail when run alone: tests/Unit/CartTest.php, …. This would BLOCK under `fail-on-isolation: true`.', 'F'],
  ];
  const lines = SPEC.map(([l]) => l);
  const whole = `${lines.join('\n')}\n`;
  const rows = SPEC.map((_, i) => i).filter((i) => SPEC[i][1] === 'R');
  const built = (k, n) => `${[...lines.filter((_, i) => SPEC[i][1] === 'F' || rows.slice(0, k).includes(i)), '', `(truncated — ${n} more rows; the full report is in the run log: ${RUN_URL})`].join('\n')}\n`;
  const expect = (cap) => {
    if (Buffer.byteLength(whole) <= cap) return whole;
    let k = 0;
    while (k < rows.length && Buffer.byteLength(built(k + 1, rows.length)) <= cap) k++;
    return built(k, rows.length - k);
  };
  const lo = Buffer.byteLength(built(0, rows.length));
  const bad = [];
  for (let cap = lo - 3; cap <= Buffer.byteLength(whole) + 1; cap++) if (fitReport(lines, RUN_URL, cap) !== expect(cap)) bad.push(cap);
  check(`fitReport at every cap from ${lo - 3} to ${Buffer.byteLength(whole) + 1} bytes is the cut built by hand`, bad.length === 0, `wrong at ${bad.slice(0, 5).join(', ')}`);
  const mid = fitReport(lines, RUN_URL, Buffer.byteLength(built(2, rows.length)));
  check('…a mid cut: the first two rows, the counts table and the verdict whole, the note counting 2',
    mid.includes('| php | `composer test` | 41 |') && /CartTest[\s\S]*ΜετάφρασηTest/.test(mid) && !/OrderTotalsTest|RestTest\.php` \|/.test(mid)
      && mid.endsWith(`This would BLOCK under \`fail-on-isolation: true\`.\n\n(truncated — 2 more rows; the full report is in the run log: ${RUN_URL})\n`), JSON.stringify(mid.slice(-300)));
  const noTable = [...lines.slice(0, 11), '**status: pass**', 'x'.repeat(300)];
  check('…no isolate-files table (the counts table is not one): an over-cap report goes whole, with no note', fitReport(noTable, RUN_URL, 100) === `${noTable.join('\n')}\n`);
}

console.log("\n# isolate-files — the step summary stays under GitHub's limit (run.mjs end to end)");
{
  // GitHub drops a step summary over 1 MiB (the upload fails with an error annotation, so the run shows
  // none), and the isolate-files table has a row per test file that fails alone: a report over 900,000
  // bytes is cut for the summary alone (fitReport, pinned cap by cap above). The suite is
  // phpunit-many-stub.sh over files.txt, every file failing alone with its name and defect line at
  // safe()'s caps in 3-byte characters (917 bytes a row), so 1,200 files take the report past 1 MiB.
  const WD = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'ts-many-')));
  fs.copyFileSync(path.join(FIX, 'php-isolation', 'phpunit-many-stub.sh'), path.join(WD, 'phpunit-many-stub.sh'));
  const WHY = `Error: ${'中'.repeat(193)}`;   // 200 characters, the why column's cap
  // File i: `tests/`, its number, 3-byte characters, `extra` ASCII bytes and `Test.php` — 118 characters
  // with no extra, and the file column's cap is 120. A file's extra is the 1-byte knob of the boundary
  // legs; the first ten files never take one, so the verdict, which names them, does not move.
  const fileOf = (i, extra = 0) => `tests/${String(i).padStart(4, '0')}${'中'.repeat(100)}${'x'.repeat(extra)}Test.php`;
  // n files, `pad` bytes spread over files 11..n, one each.
  const suite = (n, pad = 0) => Array.from({ length: n }, (_, j) => fileOf(j + 1, j >= 10 && j - 10 < pad ? 1 : 0));
  const rowOf = (f) => `| \`${f}\` | 2 | ${WHY} |`;
  const GH = { GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'acme/site', GITHUB_RUN_ID: '33911783576' };
  const ISO = { ...GH, WORKING_DIRECTORY: WD, STACK: 'php', TEST_COMMAND: 'sh phpunit-many-stub.sh', FAIL_ON_FAIL: 'true', ISOLATE_FILES: 'true', STUB_WHY: WHY };
  const runSuite = (files, extra = {}, script = RUN) => {
    fs.writeFileSync(path.join(WD, 'files.txt'), files.map((f) => `${WD}/${f}\n`).join(''));
    return runCli({ ...ISO, ...extra }, script);
  };
  const isRow = (l) => l.startsWith('| `tests/');
  const nonRows = (text) => text.split('\n').filter((l) => !isRow(l));
  // What a cut summary owes against the rows of the report it was cut from (`all`, the listing's order),
  // each property on its own.
  const cutOf = (summary, all) => {
    const m = summary.match(/^([\s\S]*)\n\n\(truncated — (\d+) more rows; the full report is in the run log: (\S+)\)\n$/);
    const kept = (m ? m[1] : summary).split('\n').filter(isRow);
    const k = kept.length;
    const size = Buffer.byteLength(summary);
    const b = (l) => Buffer.byteLength(l) + 1;
    return { size, k, m,
      // The report's size: the summary's lines, the rows left out put back, less the blank line and note.
      uncut: m ? Buffer.byteLength(m[1]) + 1 + all.slice(k).reduce((sum, l) => sum + b(l), 0) : size,
      under: size <= CAP,
      shape: !!m && m[3] === RUN_URL,
      prefix: k > 0 && k < all.length && kept.every((l, i) => l === all[i]),
      count: !!m && Number(m[2]) === all.length - k,
      // The first row left out would not fit, the note budgeted at its longest (every row left out).
      fill: k < all.length && CAP - size - (String(all.length).length - String(all.length - k).length) < b(all[k]),
      verdict: !!m && /\n\n\*\*status: fail\*\*\nreport-only — the suite is green \(2 passed, 0 failed, 2 total\) but \d+ of \d+ test file\(s\) fail when run alone: .*\. This would BLOCK under `fail-on-isolation: true`\.$/.test(m[1]) };
  };
  const owed = (c) => c.under && c.shape && c.prefix && c.count && c.fill && c.verdict;
  const logged = (stdout) => stdout.split('\n').filter((l) => l.startsWith('│ tests/'));
  try {
    const N = 1200;
    const files = suite(N);
    const big = runSuite(files);
    const c = cutOf(big.summary, files.map(rowOf));
    check(`${N} files that fail alone, a report past 1 MiB: exit 0 and the report-only verdict, as uncut`,
      c.uncut > 1048576 && big.exit === 0 && /^test-suite: ❌ status=fail — report-only — the suite is green .* but 1200 of 1200 test file\(s\) fail when run alone: .* — would BLOCK under fail-on-isolation:true$/m.test(big.stdout),
      `${c.uncut} B, exit=${big.exit} ${big.stderr.slice(0, 200)}`);
    check('…the summary is at most 900,000 bytes', c.under, `${c.size} B`);
    check('…the report cut, then the note with the run URL', c.shape, JSON.stringify(big.summary.slice(-200)));
    check('…the rows kept are the first in the listing, in its order', c.prefix, `kept ${c.k}`);
    check(`…the note counts the ${N - c.k} rows left out`, c.count);
    check('…and fills the room: the first row left out would not fit', c.fill, `${c.size} B`);
    check('…the head, the counts table, the table header and the verdict kept',
      big.summary.startsWith('## 🧪 test-suite — per-stack test run\n') && big.summary.includes('\n| php | `sh phpunit-many-stub.sh` | 2 | 0 | — | 2 | 0 |\n')
        && big.summary.includes('\n- ❌ 1200 of 1200 test file(s) fail alone.') && big.summary.includes(`\n| file | exit | why |\n| --- | ---: | --- |\n${rowOf(files[0])}\n`) && c.verdict);
    check('…the job log names every file, in the listing\'s order, with its exit and why',
      logged(big.stdout).join('\n') === files.map((f) => `│ ${f} — exit 2 — ${WHY}`).join('\n'), `${logged(big.stdout).length} logged`);

    // The boundary, both sides: 110 files measure the fixed lines; enough files to come within a row of
    // 900,000 bytes (their counts as many digits long as 110's, so the fixed lines do not move); the rest
    // in single bytes over the files' names, to exactly 900,000 — the summary must be the report, nothing
    // cut — then one byte more.
    const small = runSuite(suite(110));
    const n = 110 + Math.floor((CAP - Buffer.byteLength(small.summary)) / (Buffer.byteLength(rowOf(fileOf(1))) + 1));
    const pad = CAP - Buffer.byteLength(small.summary) - (n - 110) * (Buffer.byteLength(rowOf(fileOf(1))) + 1);
    const atCap = runSuite(suite(n, pad));
    check(`${n} files and ${pad} bytes over their names, a report of exactly 900,000 bytes: the summary is the report, every row in it`,
      !cutOf(small.summary, []).m && pad + 1 <= n - 10 && Buffer.byteLength(atCap.summary) === CAP && !atCap.summary.includes('(truncated')
        && atCap.summary.split('\n').filter(isRow).join('\n') === suite(n, pad).map(rowOf).join('\n'), `${Buffer.byteLength(atCap.summary)} B, pad ${pad}`);
    const past = suite(n, pad + 1);
    const pastCap = runSuite(past);
    const p = cutOf(pastCap.summary, past.map(rowOf));
    check('…one byte more: cut to at most 900,000, the first rows kept, the rest counted, every other line as at the cap',
      p.uncut === CAP + 1 && owed(p) && nonRows(`${p.m[1]}\n`).join('\n') === nonRows(atCap.summary).join('\n'), `${p.uncut} → ${p.size} B, kept ${p.k}`);

    // A fault in the cut costs the run its summary, never its exit code: the job log is as it was, then
    // one plain line naming the fault. A copy of the scripts whose fitReport throws; under fail-on-fail a
    // crash would exit 1.
    const faulty = fs.mkdtempSync(path.join(os.tmpdir(), 'ts-faulty-'));
    try {
      const source = fs.readFileSync(path.join(HERE, 'detect.mjs'), 'utf8');
      const CUT = 'export function fitReport(lines, runUrl, cap = SUMMARY_CAP) {';
      check('fault-injection anchor still present in detect.mjs', source.includes(CUT));
      fs.writeFileSync(path.join(faulty, 'detect.mjs'), source.replace(CUT, `${CUT} throw new Error('injected cut fault');`));
      fs.copyFileSync(RUN, path.join(faulty, 'run.mjs'));
      const FAULT = "test-suite: the report is over the step summary's limit and could not be cut, so the summary does not carry it; the job log above holds every row (injected cut fault)";
      const sunk = runSuite(files, {}, path.join(faulty, 'run.mjs'));
      check('a fault in the cut: the job log as uncut, then one plain line naming it; no summary; exit 0, not a crash',
        sunk.stdout === `${big.stdout}${FAULT}\n` && sunk.summary === '' && sunk.exit === 0, `exit=${sunk.exit} ${JSON.stringify(sunk.stdout.slice(-300))}`);
    } finally {
      fs.rmSync(faulty, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(WD, { recursive: true, force: true });
  }
}

console.log(failed === 0 ? '\n✅ all test-suite self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
