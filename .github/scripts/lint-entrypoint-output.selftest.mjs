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
import {
  lintSource, lintEntrypoint, lintCrashGuardPresence,
  discoverEntrypoints, discoverExecuted, blankNonCode,
} from './lint-entrypoint-output.mjs';

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
// Rule 2. The load-bearing fixture is the PAIR below: the same source differing
// ONLY in where the guard sits. If the rule ever goes vacuous, the dead variant
// stops firing while the live one still reads 0, and this pair catches it —
// asserting one direction alone would not (ci-actions has already shipped a
// 5-week-live defect behind a fixture that pinned only one direction).
say('\n# rule 2 — crash guards registered after main is dead code');

const IIFE_BODY = src(
  'const summaryFile = process.env.GITHUB_STEP_SUMMARY;',
  '(function main() {',
  '  fs.appendFileSync(summaryFile, report);',
  '  process.exit(blocked ? 1 : 0);',
  '})();',
);
const GUARD = "process.on('uncaughtException', (e) => { process.exit(FAIL ? 1 : 0); });";

check('DEAD — guard below the main IIFE fires (the deps-currency shape)',
  count(IIFE_BODY, GUARD) === 1);
check('LIVE — the same source with the guard hoisted is clean',
  count(GUARD, IIFE_BODY) === 0,
  '(if this and the line above are not 1/0, the rule has gone vacuous)');

check('DEAD — guard below an async IIFE fires',
  count('(async () => { process.exit(0); })();', GUARD) === 1);
check('DEAD — unhandledRejection is covered too',
  count(IIFE_BODY, "process.on('unhandledRejection', (e) => { process.exit(1); });") === 1);
check('DEAD — guard below a top-level process.exit() fires',
  count('process.exit(2);', GUARD) === 1);

check('LIVE — the sibling .catch() shape never trips the rule',
  count('(async () => { process.exit(0); })().catch((e) => { process.exit(FAIL ? 1 : 0); });') === 0);
check('LIVE — a file with no terminator at all is clean',
  count('const a = 1;', GUARD) === 0);
check('LIVE — a benign top-level IIFE that cannot exit is still a terminator (strict by design)',
  count('const v = (() => 1)();', GUARD) === 1,
  '(hoisting is free, so the rule does not try to prove the IIFE exits)');

check('scoped to top level — a guard registered inside a function is not flagged',
  count(IIFE_BODY, 'function arm() {', `  ${GUARD}`, '}') === 0);
check('non-crash process.on events are out of scope',
  count(IIFE_BODY, "process.on('SIGINT', () => {});", "process.on('exit', () => {});") === 0);

// The scrubber has to hold for rule 2 as well — the event name is read from the
// RAW line precisely because the scrubber blanked the string literal it lives in.
check('comment mentioning uncaughtException is not a registration',
  count(IIFE_BODY, '// process.on(\'uncaughtException\') would be dead here') === 0);
check('string containing the registration text is not a registration',
  count(IIFE_BODY, 'const hint = "process.on(\'uncaughtException\', f)";') === 0);

check('reports the guard line and the terminator line',
  (() => {
    const f = findings(IIFE_BODY, GUARD).find((x) => x.kind === 'dead-crash-guard');
    return f && f.line === 6 && f.detail.includes('line 5') && f.what === "process.on('uncaughtException'";
  })(),
  JSON.stringify(findings(IIFE_BODY, GUARD)));

check('rule 2 findings are tagged, and do not disturb rule 1 tagging',
  (() => {
    const f = findings(IIFE_BODY, 'console.log(x);', GUARD);
    return f.length === 2
      && f.filter((x) => x.kind === 'raw-output').length === 1
      && f.filter((x) => x.kind === 'dead-crash-guard').length === 1;
  })());

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
// ---------------------------------------------------------------------------
// RULE 3 — crash-guard presence, per language.
//
// Fixtures, not the live tree, so both directions are pinned: the rule must fire
// on an unguarded executed entrypoint in each of the three shipped languages, and
// must stay silent on every legitimate guarded shape. A rule that only ever runs
// against a clean tree is indistinguishable from a rule that never fires.
say('\n# rule 3: crash-guard presence (.mjs / .py / .sh)');

const guard = (file, src, executed = true) => lintCrashGuardPresence(src, file, executed);
const missing = (file, src, executed = true) =>
  guard(file, src, executed).some((f) => f.kind === 'missing-crash-guard');

// --- JavaScript: both accepted shapes, and the unguarded one.
check('.mjs with a hoisted process.on(uncaughtException) is guarded',
  !missing('a/scripts/x.mjs', src("process.on('uncaughtException', (e) => {});", '(function main(){})();')));
check('.mjs with the ordering-immune `)().catch(` shape is guarded',
  !missing('a/scripts/x.mjs', src('(async () => { await go(); })().catch((e) => { process.exit(0); });')));
check('.mjs with unhandledRejection only is guarded',
  !missing('a/scripts/x.mjs', src("process.on('unhandledRejection', (e) => {});")));
check('.mjs with NO guard is a finding',
  missing('a/scripts/x.mjs', src('const x = 1;', 'process.exit(0);')));

// --- Python: the guard must wrap the main invocation, not merely exist.
check('.py with try/except under `if __name__` is guarded',
  !missing('a/scripts/x.py', src('def main():', '    pass', '', 'if __name__ == "__main__":',
    '    try:', '        main()', '    except Exception:', '        raise SystemExit(2)')));
check('.py with a bare main() call under `if __name__` is a finding',
  missing('a/scripts/x.py', src('def main():', '    pass', '', 'if __name__ == "__main__":', '    main()')));
// The load-bearing one: a try/except somewhere INSIDE the program does not guard
// the entrypoint. sitemap-urls.py has exactly that shape (a per-child-sitemap
// try/except in collect()) and must still be seen as unguarded, or its exemption
// would be silently unnecessary and the rule would be lying about what it checks.
check('.py with try/except only INSIDE a helper is still a finding',
  missing('a/scripts/x.py', src('def collect():', '    try:', '        fetch()', '    except Exception:', '        return', '',
    'def main():', '    collect()', '', 'if __name__ == "__main__":', '    main()')));

// --- bash.
check('.sh with a trap on EXIT is guarded',
  !missing('a/scripts/x.sh', src('set -uo pipefail', 'on_exit() { :; }', 'trap on_exit EXIT')));
check('.sh with no trap is a finding',
  missing('a/scripts/x.sh', src('set -euo pipefail', 'echo hi', 'exit 0')));
// The documented limit, asserted so it stays a KNOWN limit rather than a
// surprise: a pure cleanup trap satisfies the bash heuristic. This is exactly why
// link-crawl.sh carries an explicit pragma instead of relying on detection.
check('.sh cleanup-only trap satisfies the heuristic (documented limit)',
  !missing('a/scripts/x.sh', src('set -uo pipefail', 'trap \'rm -f "$TMP"\' EXIT')));

// --- scope: libraries and pragmas.
check('an unguarded file that action.yml never executes is NOT a finding',
  !missing('a/scripts/engine.mjs', src('export const f = () => 1;'), false));
check('the pragma exempts, and requires a reason',
  !missing('a/scripts/x.py', src('# lint-allow-no-crash-guard: wrapper attributes it', 'main()')));
check('a BARE pragma with no reason does NOT exempt',
  missing('a/scripts/x.py', src('# lint-allow-no-crash-guard:', 'main()')));
check('an unknown extension is out of scope',
  !missing('a/scripts/x.rb', src('puts 1')));

// --- discoverExecuted: the ground-truth set rule 3 keys on.
say('\n# discoverExecuted — read from action.yml, not guessed');
const executedSet = discoverExecuted(root);
check('finds the executed scripts across every language',
  ['a11y-audit/scripts/audit.sh', 'linkcheck/scripts/linkcheck.py', 'linkcheck/scripts/sitemap-urls.py',
   'verify-homepage/scripts/render-check.mjs', 'verify-homepage/scripts/link-crawl.sh',
   'security-baseline/scripts/scan.mjs'].every((f) => executedSet.has(f)),
  JSON.stringify([...executedSet].sort()));
// The distinction the rule depends on: pure library modules are NOT executed.
check('pure library modules are NOT in the executed set',
  !['deps-currency/scripts/engine.mjs', 'seo-aeo/scripts/checks.mjs', 'test-suite/scripts/detect.mjs',
    'security-baseline/scripts/tiers.mjs'].some((f) => executedSet.has(f)),
  JSON.stringify([...executedSet].sort()));

// ---------------------------------------------------------------------------
say('\n# the live tree is clean (the lint is wired as blocking)');

let live = 0;
for (const rel of found) {
  live += lintEntrypoint(fs.readFileSync(path.join(root, rel), 'utf8'), rel, executedSet.has(rel)).length;
}
check(`all ${found.length} entrypoints lint clean`, live === 0, `(${live} finding(s))`);

// Discovery must actually reach the non-JS entrypoints, or rule 3 passes
// vacuously on exactly the two languages it was added for.
check('discovery covers .py and .sh entrypoints, not just .mjs',
  found.includes('linkcheck/scripts/linkcheck.py') && found.includes('a11y-audit/scripts/audit.sh'),
  JSON.stringify(found));
// …and the three actions this rule was written for must be GUARDED in the live
// tree — the positive assertion that v1.12.0 actually landed.
check('the three v1.12.0 entrypoints are guarded in the live tree',
  ['verify-homepage/scripts/render-check.mjs', 'linkcheck/scripts/linkcheck.py', 'a11y-audit/scripts/audit.sh']
    .every((f) => !lintCrashGuardPresence(fs.readFileSync(path.join(root, f), 'utf8'), f, true).length));

// The exempt selftests must stay exempt AND stay small — the exemption is
// "1-4 KB of output cannot reach a 64 KiB pipe buffer", not "selftests are
// special". If one ever grows a large report, this is where that shows up.
say('\n# the selftest exemption still holds');
const selftests = fs.readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && fs.existsSync(path.join(root, d.name, 'scripts', 'selftest.mjs')))
  .map((d) => path.join(d.name, 'scripts', 'selftest.mjs'));
check('seven action selftests exist and are out of scope',
  selftests.length === 7 && !found.some((f) => selftests.includes(f)), `(${selftests.length})`);

say(failed === 0 ? '\n✅ all lint-entrypoint-output self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
