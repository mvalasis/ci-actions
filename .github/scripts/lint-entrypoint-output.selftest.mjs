#!/usr/bin/env node
// Offline fixture suite for lint-entrypoint-output. Runs the scrubber + matcher
// over hand-written sources that pin down BOTH directions:
//   - it fires on every shape of the real defect, including the v1.7.1 shape
//     where the console call and the process.exit sit lines apart;
//   - it does NOT fire on the sync-write fallback, on comments that merely
//     mention console.log (run.mjs and render-check.mjs both do, in the comment
//     explaining why they avoid it), or on the literal text inside a string.
// The desync fixtures are the load-bearing ones: a regex containing a quote
// would derail a naive string scanner and hide every violation after it.
//
// A blocking gate whose scrubber is wrong fails silently in the permissive
// direction, so this suite runs in CI ahead of the lint itself.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintSource, discoverEntrypoints, blankNonCode } from './lint-entrypoint-output.mjs';

const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };

let failed = 0;
function check(name, cond, detail = '') {
  if (cond) say(`  ✅ ${name}`);
  else { say(`  ❌ ${name} ${detail}`); failed++; }
}

const src = (...lines) => lines.join('\n');
const count = (...lines) => lintSource(src(...lines)).length;
const findings = (...lines) => lintSource(src(...lines));

// ---------------------------------------------------------------------------
say('\n# the defect fires');

check('bare console.log', count("console.log('report');") === 1);
check('bare console.error', count("console.error('boom');") === 1);
check('any console method (warn/info/debug)',
  count("console.warn('a');", "console.info('b');", "console.debug('c');") === 3);
check('process.stdout.write', count("process.stdout.write('report');") === 1);
check('process.stderr.write', count("process.stderr.write('boom');") === 1);
check('spaced-out member access still matches', count('console . log ("x");') === 1);

// The v1.7.1 shape: the write and the exit were separated by a blank line and an
// `if`, which is why proximity-based detection was never an option.
check('console.log separated from process.exit by other statements',
  count(
    "console.log(report);",
    '',
    'if (failures) {',
    '  process.exit(2);',
    '}',
    'process.exit(0);',
  ) === 1);

check('reports line and column',
  (() => {
    const f = findings('const a = 1;', "console.log('x');")[0];
    return f && f.line === 2 && f.col === 1 && f.what === 'console.log(';
  })());

// ---------------------------------------------------------------------------
say('\n# the sync-write fallback is allowed, narrowly');

check('say helper (fd 1)',
  count('const say = (s) => { try { fs.writeSync(1, `${s}\\n`); } catch { console.log(s); } };') === 0);
check('sayErr helper (fd 2)',
  count('const sayErr = (s) => { try { fs.writeSync(2, `${s}\\n`); } catch { console.error(s); } };') === 0);
check('both real helpers verbatim (test-suite v1.7.0 + verify-homepage v1.7.1)',
  count(
    "const say = (s = '') => { try { fs.writeSync(1, `${s}\\n`); } catch { console.log(s); } };",
    'const sayErr = (s) => { try { fs.writeSync(2, `${s}\\n`); } catch { console.error(s); } };',
  ) === 0);
// The allowance is positional, not "line mentions writeSync": a console call
// BEFORE the catch is a real violation riding along on a shared line.
check('console BEFORE the catch on a writeSync line is still a finding',
  count("console.log(x); try { fs.writeSync(1, 'a'); } catch { }") === 1);
check('console on a writeSync line with no catch is still a finding',
  count("fs.writeSync(1, 'a'); console.log('b');") === 1);

// ---------------------------------------------------------------------------
say('\n# comments and strings are not code');

check('line comment mentioning console.log',
  count('// fs.writeSync, not console.log: stdout is async on macOS pipes') === 0);
check('trailing comment mentioning console.error',
  count('const x = 1; // never console.error(msg) here') === 0);
check('block comment mentioning console.log',
  count('/*', ' * console.log(x) would truncate here', ' */') === 0);
check('render-check.mjs comment shape (console.log/console.error in one line)',
  count('// Job-log output goes through fs.writeSync, never console.log/console.error:') === 0);
check('string containing the literal text console.log(',
  count("const hint = 'console.log(x) is banned';") === 0);
check('template literal containing console.log(',
  count('const hint = `console.log(${x}) is banned`;') === 0);
check('URL in a string is not a line comment',
  count("const u = 'https://example.com/a'; console.log(u);") === 1,
  '(the // in https:// must not blank the rest of the line)');

// ---------------------------------------------------------------------------
say('\n# scrubber desync guards (the silent-permissive failure mode)');

check('regex containing quote chars does not swallow later code',
  count("const safe = s.replace(/['\"]/g, ''); console.log(safe);") === 1);
check('regex containing a slash in a character class',
  count("const re = /[/]+/g; console.error('x');") === 1);
check('division is not mistaken for a regex',
  count("const pct = a / b; console.log(pct);") === 1);
check('regex after return keyword',
  count('function f() { return /a/.test(s); }', "console.log('x');") === 1);
check('template interpolation returns to code mode',
  count('const t = `a${b}c`;', "console.log(t);") === 1);
check('nested template interpolation',
  count('const t = `a${`b${c}d`}e`;', "console.log(t);") === 1);
check('console.log inside a template interpolation is still code',
  count('const t = `x${console.log(y)}z`;') === 1);
check('escaped quote inside a string does not desync',
  count("const s = 'it\\'s fine'; console.log(s);") === 1);
check('apostrophe inside a comment does not desync',
  count("// it's fine to say console.log here", "console.log('real');") === 1);
check('blankNonCode preserves length and line count',
  (() => {
    const s = "// c\nconst a = 'str'; /* b */\nconsole.log(a);\n";
    const b = blankNonCode(s);
    return b.length === s.length && b.split('\n').length === s.split('\n').length;
  })());

// ---------------------------------------------------------------------------
say('\n# the pragma escape hatch');

check('pragma with a reason, same line',
  count("console.log(x); // lint-allow-raw-output: 40-byte banner, cannot truncate") === 0);
check('pragma with a reason, line above',
  count('// lint-allow-raw-output: 40-byte banner, cannot truncate', 'console.log(x);') === 0);
check('bare pragma with no reason does NOT excuse',
  count('// lint-allow-raw-output:', 'console.log(x);') === 1);
check('pragma two lines above does NOT excuse',
  count('// lint-allow-raw-output: stale', '', 'console.log(x);') === 1);

// ---------------------------------------------------------------------------
say('\n# discovery — action entrypoints, not selftests');

const root = path.resolve(fileURLToPath(new URL('.', import.meta.url)), '../..');
const found = discoverEntrypoints(root);

check('discovers entrypoints', found.length > 0, `(got ${found.length})`);
check('excludes */scripts/selftest.mjs',
  !found.some((f) => f.endsWith('/selftest.mjs')), `(${found.filter((f) => f.endsWith('/selftest.mjs')).join(', ')})`);
check('excludes nested fixtures under scripts/selftest/',
  !found.some((f) => f.includes('/selftest/')));
check('excludes .github/scripts (no action.yml, so never an entrypoint)',
  !found.some((f) => f.startsWith('.github/')));
check('only scans dirs that carry an action.yml',
  found.every((f) => fs.existsSync(path.join(root, f.split('/')[0], 'action.yml'))));
check('covers the two files that carried the hand-fix',
  found.includes('test-suite/scripts/run.mjs') && found.includes('verify-homepage/scripts/render-check.mjs'));
check('covers every documented entrypoint basename',
  ['check.mjs', 'checks.mjs', 'scan.mjs', 'engine.mjs', 'run.mjs', 'detect.mjs', 'tiers.mjs', 'render-check.mjs']
    .every((b) => found.some((f) => f.endsWith(`/${b}`))));

// ---------------------------------------------------------------------------
say('\n# the live tree is clean (the lint is wired as blocking)');

let live = 0;
for (const rel of found) live += lintSource(fs.readFileSync(path.join(root, rel), 'utf8'), rel).length;
check(`all ${found.length} entrypoints lint clean`, live === 0, `(${live} finding(s))`);

// The six exempt selftests must stay exempt AND stay small — the exemption is
// "2-4 KB of output cannot reach a 64 KiB pipe buffer", not "selftests are
// special". If one ever grows a large report, this is where that shows up.
say('\n# the selftest exemption still holds');
const selftests = fs.readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && fs.existsSync(path.join(root, d.name, 'scripts', 'selftest.mjs')))
  .map((d) => path.join(d.name, 'scripts', 'selftest.mjs'));
check('six action selftests exist and are out of scope',
  selftests.length === 6 && !found.some((f) => selftests.includes(f)), `(${selftests.length})`);

say(failed === 0 ? '\n✅ all lint-entrypoint-output self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
