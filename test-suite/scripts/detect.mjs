// Pure, network-free core for the test-suite action: stack detection, test-command resolution,
// and pass/fail-count parsing. Kept side-effect-free (only reads the filesystem it's told to)
// so scripts/selftest.mjs can exercise every branch offline against fixture dirs. Mirrors the
// pure-engine split used by seo-aeo (checks.mjs) and security-baseline (tiers.mjs).
import fs from 'node:fs';
import path from 'node:path';

export const STATUS = { PASS: 'pass', FAIL: 'fail', NO_TESTS: 'no-tests', NO_STACK: 'no-stack', ERROR: 'error' };

// Neutralize tool-controlled strings before they reach the markdown step-summary: strip CR/LF +
// markdown-structural chars and cap length, so a hostile test name / file path can't forge a
// verdict line or inject an image beacon into the job summary (report-spoofing guard — same
// posture as seo-aeo's safe()).
export const safe = (s, max = 220) =>
  String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/[`|<>[\]()]/g, '').slice(0, max);

const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } };
const exists = (p) => { try { return fs.existsSync(p); } catch { return false; } };

// ---------- stack detection ----------
// auto: node if package.json, else php if composer.json, else none. An explicit `stack` skips
// detection. Returns one of 'node' | 'php' | 'none'.
export function detectStack(dir, requested = 'auto') {
  const want = (requested || 'auto').trim().toLowerCase();
  if (want === 'node' || want === 'php' || want === 'none') return want;
  if (exists(path.join(dir, 'package.json'))) return 'node';
  if (exists(path.join(dir, 'composer.json'))) return 'php';
  return 'none';
}

// ---------- package-manager detection (node) ----------
// Prefer the PM the repo actually uses (lockfile / packageManager field), else npm. We only ever
// pick a PM that's plausibly present; the CLI degrades to npm if the chosen one isn't on PATH.
export function detectNodePM(dir, pkg) {
  const field = pkg && typeof pkg.packageManager === 'string' ? pkg.packageManager.split('@')[0].trim() : '';
  if (field === 'pnpm' || field === 'yarn' || field === 'npm') return field;
  if (exists(path.join(dir, 'pnpm-lock.yaml'))) return 'pnpm';
  if (exists(path.join(dir, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

// Does this node project actually have a real (non-placeholder) `test` script? The npm-init
// default `"test": "echo \"Error: no test specified\" && exit 1"` is NOT a configured suite — a
// repo carrying only that placeholder must be treated as "no tests" (green), never as a failure.
export function hasRealTestScript(pkg) {
  const t = pkg && pkg.scripts && typeof pkg.scripts.test === 'string' ? pkg.scripts.test.trim() : '';
  if (!t) return false;
  if (/no test specified/i.test(t)) return false;          // npm-init placeholder
  if (/^(echo\b.*&&\s*)?exit\s+1\s*$/i.test(t)) return false; // bare `exit 1` stub
  return true;
}

const hasDep = (pkg, name) =>
  !!(pkg && ((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name])));

// ---------- node command resolution ----------
// Prefer a real package.json "test" script via the repo's PM; else fall back to a known runner
// that's declared as a dependency (vitest → `npx vitest run`). No test config → null (the caller
// renders "no tests configured" and PASSES green).
export function resolveNodeCommand(dir, pkg, pm) {
  if (hasRealTestScript(pkg)) {
    const runner = { pnpm: ['pnpm', 'run', 'test'], yarn: ['yarn', 'run', 'test'], npm: ['npm', 'run', 'test'] }[pm] || ['npm', 'run', 'test'];
    return { argv: runner, label: `${pm} run test`, runner: 'package-script' };
  }
  if (hasDep(pkg, 'vitest')) return { argv: ['npx', '--no-install', 'vitest', 'run'], label: 'npx vitest run', runner: 'vitest' };
  return null;
}

// ---------- php command resolution ----------
// composer "test" script → `composer test`; else pest/phpunit binary if vendored. No config → null.
export function resolvePhpCommand(dir) {
  const composer = readJson(path.join(dir, 'composer.json'));
  const scripts = composer && composer.scripts ? composer.scripts : {};
  if (scripts && Object.prototype.hasOwnProperty.call(scripts, 'test')) {
    return { argv: ['composer', 'run', '--no-interaction', 'test'], label: 'composer test', runner: 'composer-script' };
  }
  if (exists(path.join(dir, 'vendor/bin/pest'))) return { argv: ['vendor/bin/pest'], label: 'vendor/bin/pest', runner: 'pest' };
  if (exists(path.join(dir, 'vendor/bin/phpunit'))) return { argv: ['vendor/bin/phpunit'], label: 'vendor/bin/phpunit', runner: 'phpunit' };
  return null;
}

// ---------- top-level resolution ----------
// Returns { stack, command|null, runner, label, reason } — command:null means "no tests
// configured" for that stack (→ green PASS at the CLI), reason explains why.
export function resolveCommand(dir, requested = 'auto') {
  const stack = detectStack(dir, requested);
  if (stack === 'none') return { stack, command: null, reason: 'no package.json or composer.json detected — no stack to test' };
  if (stack === 'node') {
    const pkg = readJson(path.join(dir, 'package.json')) || {};
    const pm = detectNodePM(dir, pkg);
    const cmd = resolveNodeCommand(dir, pkg, pm);
    if (!cmd) return { stack, command: null, pm, reason: 'no "test" script and no known test runner (vitest) in dependencies' };
    return { stack, command: cmd.argv, runner: cmd.runner, label: cmd.label, pm };
  }
  // php
  const cmd = resolvePhpCommand(dir);
  if (!cmd) return { stack, command: null, reason: 'no composer "test" script and no vendor/bin/pest|phpunit' };
  return { stack, command: cmd.argv, runner: cmd.runner, label: cmd.label };
}

// ---------- pass/fail-count parsing ----------
// Best-effort, runner-aware extraction of {passed, failed, skipped, total} from combined
// stdout+stderr. The AUTHORITATIVE pass/fail signal is always the process EXIT CODE (the caller
// uses it for the verdict); these counts only enrich the summary table, so an unparsed runner
// degrades to nulls, never to a wrong verdict.
export function parseCounts(output, runner = '') {
  const text = String(output || '');
  const num1 = (s, re) => { const m = String(s).match(re); return m ? parseInt(m[1], 10) : null; };
  let passed = null, failed = null, skipped = null, total = null;

  // --- PHPUnit (distinct format: "Tests: N, ... Failures: N, Errors: N" or "OK (N tests, ...)"). ---
  // Matched FIRST so its `Tests:` line never collides with vitest's `Tests` summary line below.
  const puLine = text.match(/^.*\bTests:\s*\d+,.*$/im);
  if (puLine) {
    const puTotal = num1(puLine[0], /Tests:\s*(\d+)/i);
    const f = (num1(puLine[0], /Failures:\s*(\d+)/i) || 0) + (num1(puLine[0], /Errors:\s*(\d+)/i) || 0);
    if (puTotal != null) return { passed: Math.max(0, puTotal - f), failed: f, skipped: num1(puLine[0], /Skipped:\s*(\d+)/i), total: puTotal };
  }
  const ok = text.match(/OK\s*\((\d+)\s+tests?/i);
  if (ok) { const n = parseInt(ok[1], 10); return { passed: n, failed: 0, skipped: null, total: n }; }

  // --- vitest / jest / pest: parse the CANONICAL summary line only. ---
  // vitest:  "      Tests  1 failed | 1 passed (2)"   (NB: a sibling "Test Files …" line carries
  //           the same N-passed/(N) tokens, so matching the whole text would pick the wrong line.)
  // pest:    "  Tests:  1 failed, 9 passed (40 assertions)"
  // jest:    "Tests:       1 failed, 2 passed, 3 total"
  const summaryLines = text.split('\n').filter((l) => /(^|\s)Tests:?\s+\d/.test(l) && !/Test Files/i.test(l));
  const line = summaryLines.length ? summaryLines[summaryLines.length - 1] : '';
  if (line) {
    failed = num1(line, /(\d+)\s+failed/i);
    passed = num1(line, /(\d+)\s+passed/i);
    skipped = num1(line, /(\d+)\s+(?:skipped|todo|pending)/i);
    total = num1(line, /(\d+)\s+total/i) ?? num1(line, /\((\d+)\)\s*$/);
  }

  if (total == null && (passed != null || failed != null)) total = (passed || 0) + (failed || 0) + (skipped || 0);
  return { passed, failed, skipped, total };
}

// Final verdict from the exit code + parsed counts. Exit code is authoritative: a non-zero exit
// is a FAIL even if we couldn't parse a failure count (e.g. a compile error before any test ran).
export function verdict(exitCode, counts) {
  if (exitCode === 0) return STATUS.PASS;
  if (counts && counts.failed != null && counts.failed > 0) return STATUS.FAIL;
  return STATUS.FAIL; // any non-zero exit is a failure
}
