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
  lintSource, lintEntrypoint, lintCrashGuardPresence, lintArgvSecret, lintStdioPath,
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
// An astral character (an emoji — six .mjs entrypoints carry one) is TWO code
// units. A code-point output array put every later wipe one slot late per astral
// char: with two of them, this comment's wipe ate the newline and the `c` of
// `console`, and the finding on the next line vanished.
check('astral characters do not desync the scrubber',
  (() => {
    const s = "const a = '🔒🔒'; // two astral chars\nconsole.log(a);\n";
    const b = blankNonCode(s);
    return b.length === s.length && b.split('\n')[1] === 'console.log(a);' && count(s) === 1;
  })(),
  JSON.stringify(blankNonCode("const a = '🔒🔒'; // two astral chars\nconsole.log(a);\n")));
// Rule 4's view: comments go, every literal stays exactly as written — including
// a `//` inside a string or a template, which is not a comment.
check('literals:false blanks comments only',
  (() => {
    const s = "const u = 'https://x/a'; // c\nconst t = `k ${v} // t`; /* b */ const r = /['\"]/;";
    const k = blankNonCode(s, { literals: false });
    return k.length === s.length && k.includes("'https://x/a'") && k.includes('`k ${v} // t`')
      && k.includes("/['\"]/") && !k.includes('// c') && !k.includes('/* b */');
  })(),
  JSON.stringify(blankNonCode("const u = 'https://x/a'; // c\nconst t = `k ${v} // t`; /* b */ const r = /['\"]/;", { literals: false })));

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
// link-crawl.sh (deleted in v1.15.0) carried an explicit pragma instead of relying on detection.
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
   'verify-homepage/scripts/render-check.mjs',
   'security-baseline/scripts/scan.mjs'].every((f) => executedSet.has(f)),
  JSON.stringify([...executedSet].sort()));
// The distinction the rule depends on: pure library modules are NOT executed.
check('pure library modules are NOT in the executed set',
  !['deps-currency/scripts/engine.mjs', 'seo-aeo/scripts/checks.mjs', 'test-suite/scripts/detect.mjs',
    'security-baseline/scripts/tiers.mjs'].some((f) => executedSet.has(f)),
  JSON.stringify([...executedSet].sort()));

// ---------------------------------------------------------------------------
// RULE 4 — a secret spelled into a child process's argv.
//
// The positives are the shipped defects verbatim and the load-bearing negatives
// are the shipped FIXES verbatim, so the rule is pinned from both sides on the
// exact text it exists for: a matcher that stops seeing the defect, or starts
// firing on the fix, goes red here before it ever reads the live tree.
say('\n# rule 4: a secret spelled into a child process\'s argv (.sh / .py / .mjs)');

const argv = (file, ...lines) => lintArgvSecret(src(...lines), file, true);
const leaks = (file, ...lines) => argv(file, ...lines).length;

// --- the shipped defects, verbatim.
check('shell: array assignment on a line that never names curl (audit.sh @ da689db:87)',
  leaks('a/scripts/x.sh', '[ -n "${VERIFY_TOKEN:-}" ] && hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")') === 1);
check('shell: inline on the curl line',
  leaks('a/scripts/x.sh', 'curl -sS -H "X-Verify-Source: ${VERIFY_TOKEN}" "$sitemap_url"') === 1);
check('Python: list with an f-string (linkcheck.py @ 25e83a6:146)',
  leaks('a/scripts/x.py', '    return ["-H", f"X-Verify-Source: {TOKEN}"] if (TOKEN and is_internal(url)) else []') === 1);
check('Python: the same, appended (sitemap-urls.py @ 25e83a6:78)',
  leaks('a/scripts/x.py', '                cmd += ["-H", f"X-Verify-Source: {TOKEN}"]') === 1);

// --- other spellings of the same leak.
check('Python: list exploded one element per line (flag and value on different lines)',
  leaks('a/scripts/x.py', 'cmd = [', '    "curl",', '    "-H",', '    f"X-Verify-Source: {TOKEN}",', '    url,', ']') === 1);
check('a scheme before the variable (Authorization: Bearer $GITHUB_TOKEN)',
  leaks('a/scripts/x.sh', 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" "$api"') === 1);
check('--header, and wget\'s --header=',
  leaks('a/scripts/x.sh', 'curl --header "X-Api-Key: $API_KEY" "$u"', 'wget --header="X-Api-Key: $API_KEY" "$u"') === 2);
check('Python: concatenation ("Name: " + VAR)',
  leaks('a/scripts/x.py', 'cmd += ["-H", "X-Verify-Source: " + TOKEN]') === 1);
check('.mjs: template literal in a spawn argv',
  leaks('a/scripts/x.mjs', "spawnSync('curl', ['-H', `X-Verify-Source: ${process.env.VERIFY_TOKEN}`, url]);") === 1);
check('case-insensitive on the variable (self.token, $db_password)',
  leaks('a/scripts/x.py', 'cmd += ["-H", f"X-Verify-Source: {self.token}"]') === 1
  && leaks('a/scripts/x.sh', 'curl -H "X-Db-Auth: $db_password" "$u"') === 1);

// --- the shipped fixes, verbatim: `-H @file` keeps the value out of argv.
check('NOT the fix: -H "@$file" from a mode-600 file (audit.sh, v1.15.1)',
  leaks('a/scripts/x.sh', '  hdr=(-H "@$workdir/token-header")') === 0);
// The load-bearing negative: a TOKEN-named call right after the flag. The value
// is "@", not a `Name:` literal, so it must not match — or the fix itself blocks.
check('NOT the fix: ["-H", "@" + _token_header()] (linkcheck.py, v1.15.2)',
  leaks('a/scripts/x.py', '    return ["-H", "@" + _token_header()] if (TOKEN and is_internal(url)) else []') === 0);
check('NOT the header written into that file (no flag: the value never reaches argv)',
  leaks('a/scripts/x.sh', "  ( umask 077; printf 'X-Verify-Source: %s\\n' \"$VERIFY_TOKEN\" > \"$workdir/token-header\" ) ||") === 0
  && leaks('a/scripts/x.py', '                f.write(f"X-Verify-Source: {TOKEN}\\n")') === 0);
check('NOT a header whose variable is not secret-named',
  leaks('a/scripts/x.sh', 'curl -H "X-Request-Id: $REQUEST_ID" -H "Accept: application/json" "$u"') === 0);

// --- comments are not code.
check('NOT a comment line (audit.sh v1.15.1 explains its fix in exactly this text)',
  leaks('a/scripts/x.sh', '# `-H "X-Verify-Source: $VERIFY_TOKEN"`: argv is world-readable (`ps`, /proc) to') === 0
  && leaks('a/scripts/x.py', '    # never as `-H "X-Verify-Source: {TOKEN}"`') === 0);
check('NOT a .mjs comment — line, trailing or block (the scrubber, literals kept)',
  leaks('a/scripts/x.mjs',
    "// never ['-H', `X-Verify-Source: ${token}`]",
    "run(); // nor ['-H', `X-Verify-Source: ${token}`]",
    '/*',
    " * ['-H', `X-Verify-Source: ${token}`]",
    ' */') === 0);

// --- the pragma: a reason is required, and it reaches one line up, no further.
check('pragma with a reason, same line',
  leaks('a/scripts/x.sh', 'curl -H "X-Cache-Key: $CACHE_KEY" "$u"  # lint-allow-argv-secret: a cache key, not a credential') === 0);
check('pragma with a reason, line above (// in .mjs)',
  leaks('a/scripts/x.mjs', '// lint-allow-argv-secret: a cache key, not a credential', "run(['-H', `X-Cache-Key: ${cacheKey}`]);") === 0);
check('a BARE pragma does NOT exempt',
  leaks('a/scripts/x.sh', '# lint-allow-argv-secret:', 'curl -H "X-Cache-Key: $CACHE_KEY" "$u"') === 1);
check('a pragma two lines above does NOT exempt',
  leaks('a/scripts/x.py', '# lint-allow-argv-secret: stale', '', 'cmd += ["-H", f"X-Cache-Key: {CACHE_KEY}"]') === 1);

// --- scope, dispatch and reporting.
check('a file action.yml never executes is out of scope',
  lintArgvSecret(src('cmd += ["-H", f"X-Verify-Source: {TOKEN}"]'), 'a/scripts/lib.py', false).length === 0);
// lintEntrypoint is what main() and the live-tree check below call — pin that
// rule 4 is wired into it for a non-JS file, not merely callable on its own.
check('lintEntrypoint runs rule 4 on a .sh entrypoint',
  lintEntrypoint(src('trap on_exit EXIT', 'hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")'), 'a/scripts/x.sh', true)
    .filter((f) => f.kind === 'argv-secret').length === 1);
const EXPLODED = ['cmd = [', '    "-H",', '    f"X-Verify-Source: {TOKEN}",', ']'];
check('reports the VALUE\'s line and column, and names the variable',
  (() => {
    const f = argv('a/scripts/x.py', ...EXPLODED)[0];
    return f && f.kind === 'argv-secret' && f.line === 3 && f.col === 6
      && f.detail === 'TOKEN' && f.what === '-H X-Verify-Source ← TOKEN';
  })(),
  JSON.stringify(argv('a/scripts/x.py', ...EXPLODED)));

// ---------------------------------------------------------------------------
// RULE 5 — stdout/stderr opened BY PATH.
//
// The positive is the shipped defect verbatim (test-suite run.mjs before v1.19.3)
// and the load-bearing negatives are the shipped FIX verbatim, so the rule is
// pinned from both sides on the exact text it exists for. Two fixtures carry the
// allowance's edges: a comparison and a fallback on ONE line (an allowance that
// excused the whole line passes every other case here), and a bash assignment,
// whose `=` differs from a test's `=` only by the blanks around it.
say('\n# rule 5: stdout/stderr opened by path (.mjs / .sh / .py)');

const stdio = (file, ...lines) => lintStdioPath(src(...lines), file);
const opens = (file, ...lines) => stdio(file, ...lines).length;

// --- the shipped defect, and the other ways to open the path (JS).
check('JS: the `|| \'/dev/stdout\'` summary fallback (test-suite run.mjs before v1.19.3)',
  opens('a/scripts/x.mjs', "const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';") === 1);
check('JS: a `??` fallback, a ternary branch and an assignment',
  opens('a/scripts/x.mjs', "const a = env.S ?? '/dev/stdout';", "const b = env.S ? env.S : '/dev/stdout';",
    "let c; c = '/dev/stdout';") === 3);
check('JS: a literal handed to appendFileSync / writeFileSync / openSync / createWriteStream',
  opens('a/scripts/x.mjs',
    "fs.appendFileSync('/dev/stdout', report);",
    "fs.writeFileSync(\"/dev/stdout\", report);",
    "const fd = fs.openSync(`/dev/stdout`, 'a');",
    "const out = fs.createWriteStream('/dev/stdout');") === 4);
check('JS: the path inside a command string for a child',
  opens('a/scripts/x.mjs', "execSync('report >> /dev/stdout');") === 1);
check('every spelling of fd 1 and of fd 2',
  opens('a/scripts/x.mjs', "o('/dev/fd/1');", "o('/proc/self/fd/1');",
    "o('/dev/stderr');", "o('/dev/fd/2');", "o('/proc/self/fd/2');") === 5);
check('NOT another fd or device (/dev/fd/3, /dev/fd/10, /proc/self/fd/3, /proc/self/fd/12, /dev/null, /dev/stdin)',
  opens('a/scripts/x.mjs', "o('/dev/fd/3');", "o('/dev/fd/10');", "o('/proc/self/fd/3');", "o('/proc/self/fd/12');",
    "o('/dev/null');", "o('/dev/stdin');") === 0);

// --- the allowed comparison: the shipped fix, verbatim.
check('NOT the fix: `!== \'/dev/stdout\'` (the v1.16.0–v1.19.3 summaryFile line)',
  opens('a/scripts/x.mjs',
    "const summaryFile = env.GITHUB_STEP_SUMMARY && env.GITHUB_STEP_SUMMARY !== '/dev/stdout' ? env.GITHUB_STEP_SUMMARY : '';") === 0);
check('NOT render-check.mjs\'s crash-note guard, nor ===, ==, !=, nor the path on the left',
  opens('a/scripts/x.mjs', "if (sink && sink !== '/dev/stdout') {", 'if (s === "/dev/stdout") s = \'\';',
    'if (s == `/dev/stdout`) s = \'\';', "if ('/dev/stdout' != s) go(s);") === 0);
check('the allowance is per OCCURRENCE: a comparison and a fallback on one line is one finding',
  (() => {
    const f = stdio('a/scripts/x.mjs', "const s = env.S !== '/dev/stdout' ? env.S : '/dev/stdout';");
    return f.length === 1 && f[0].col === 46;
  })(),
  JSON.stringify(stdio('a/scripts/x.mjs', "const s = env.S !== '/dev/stdout' ? env.S : '/dev/stdout';")));
check('a comparison operator that is not equality does not excuse (`=>`, `>=`, `+=`)',
  opens('a/scripts/x.mjs', "const f = () => '/dev/stdout';", "if (a >= '/dev/stdout') b();",
    "cmd += '/dev/stdout';") === 3);
// A guard against a NEAR MISS never matches the value a user sets, so the append
// it was meant to skip still opens /dev/stdout: the operand must be the path exactly.
check('a comparison against a near miss (`\'/dev/stdout \'`) does not excuse — that guard is broken',
  opens('a/scripts/x.mjs', "const summaryFile = env.S && env.S !== '/dev/stdout ' ? env.S : '';") === 1);

// --- comments are prose: "a string in a comment" in every shape the scrubber sees.
check('NOT a JS comment — line, trailing or block — even with the path quoted in it',
  opens('a/scripts/x.mjs',
    "// never fall back to '/dev/stdout': it is the job log again",
    "const s = env.S; // not appendFileSync('/dev/stdout')",
    '/*', " * env.GITHUB_STEP_SUMMARY || '/dev/stdout' crashed on a Linux socket", ' */') === 0);
check('NOT a bash or Python comment line (the fixed entrypoints explain the fix in one)',
  opens('a/scripts/x.sh', "  # never >> '/dev/stdout': ENXIO on a Linux socket stdout") === 0
  && opens('a/scripts/x.py', "    # never open('/dev/stdout', 'a')") === 0);
// The documented limit, asserted so it stays a KNOWN limit (rule 4 reads bash and
// Python comments the same way): a trailing `#` comment is scanned.
check('a trailing # comment on a bash code line IS scanned (documented limit)',
  opens('a/scripts/x.sh', 'summary="${GITHUB_STEP_SUMMARY:-}"  # not /dev/stdout') === 1);

// --- bash.
check('bash: the `${GITHUB_STEP_SUMMARY:-/dev/stdout}` sink (a11y-audit, latin-urls) and GITHUB_OUTPUT\'s (pull-tier)',
  opens('a/scripts/x.sh', 'summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"',
    '{ printf \'pull=true\\n\'; } >> "${GITHUB_OUTPUT:-/dev/stdout}" 2>/dev/null || true') === 2);
check('bash: a redirect, quoted or bare, tee, and exec',
  opens('a/scripts/x.sh', 'echo x >> /dev/stdout', 'echo x > "/dev/stderr"', 'cmd | tee /dev/fd/1',
    'exec 3>/proc/self/fd/1') === 4);
check('bash: an assignment is not a test (`sink=/dev/stdout`, no blanks around the `=`)',
  opens('a/scripts/x.sh', 'sink=/dev/stdout', "sink='/dev/stdout'") === 2);
check('NOT a bash test: = / == / !=, quoted or bare, either side',
  opens('a/scripts/x.sh',
    '[ "$GITHUB_STEP_SUMMARY" != /dev/stdout ] && summary="$GITHUB_STEP_SUMMARY"',
    '[ "$s" = "/dev/stdout" ] && s=""',
    "[[ $s == '/dev/stdout' ]] && s=''",
    '[ /dev/stdout = "$s" ] && s=""') === 0);
check('a bash test against a near miss (`/dev/stdout/`) does not excuse',
  opens('a/scripts/x.sh', '[ "$s" != /dev/stdout/ ] && summary="$s"') === 1);
check('NOT an fd duplication, which writes without re-opening (>&1, >&2, 2>/dev/null)',
  opens('a/scripts/x.sh', 'echo x >&2', 'printf y >&1', 'cmd 2>/dev/null') === 0);

// --- Python.
check('Python: an `or` fallback and an open()',
  opens('a/scripts/x.py', 'summary = os.environ.get("GITHUB_STEP_SUMMARY") or "/dev/stdout"',
    'with open("/dev/stdout", "a") as f:') === 2);
check('NOT a Python comparison (!= / ==, either side, a string prefix)',
  opens('a/scripts/x.py', 'if summary != "/dev/stdout":', "if r'/dev/stdout' == summary:",
    'if summary == f"/dev/stdout":') === 0);

// --- the pragma: a reason is required, it names THIS rule, and it reaches one line up.
check('pragma with a reason, same line (# in bash) and line above (// in JS)',
  opens('a/scripts/x.sh', 'summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"  # lint-allow-stdio-path: the notes\' one local copy') === 0
  && opens('a/scripts/x.mjs', '// lint-allow-stdio-path: a local-run fallback, guarded', "const s = env.S || '/dev/stdout';") === 0);
check('a BARE pragma does NOT exempt',
  opens('a/scripts/x.sh', '# lint-allow-stdio-path:', 'summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"') === 1);
check('a pragma two lines above does NOT exempt',
  opens('a/scripts/x.sh', '# lint-allow-stdio-path: stale', '', 'summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"') === 1);
check('another rule\'s pragma does NOT exempt',
  opens('a/scripts/x.mjs', "const s = env.S || '/dev/stdout'; // lint-allow-raw-output: the wrong rule") === 1);

// --- scope, dispatch and reporting.
// A library is in scope, unlike for rules 3 and 4: a helper that opens the path
// does it inside the entrypoint's process.
check('lintEntrypoint runs rule 5 on a LIBRARY module (executed=false) and on .sh and .py',
  lintEntrypoint(src("export const sink = process.env.S || '/dev/stdout';"), 'a/scripts/lib.mjs', false)
    .filter((f) => f.kind === 'stdio-path').length === 1
  && lintEntrypoint(src('trap on_exit EXIT', 'summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"'), 'a/scripts/x.sh', true)
    .filter((f) => f.kind === 'stdio-path').length === 1
  && lintEntrypoint(src('out = open("/dev/stdout", "a")'), 'a/scripts/x.py', false)
    .filter((f) => f.kind === 'stdio-path').length === 1);
check('an unknown extension is out of scope',
  opens('a/scripts/x.rb', "File.open('/dev/stdout', 'a')") === 0);
const FDS = ['set -u', 'echo x >> /dev/stdout', 'echo y > /dev/fd/2', 'exec 3>/proc/self/fd/1'];
check('reports the path\'s line and column, and the fd it re-opens',
  (() => {
    const [a, b, c] = stdio('a/scripts/x.sh', ...FDS);
    return a && b && c && a.line === 2 && a.col === 11 && a.what === '/dev/stdout' && a.detail === 'fd 1'
      && b.line === 3 && b.what === '/dev/fd/2' && b.detail === 'fd 2'
      && c.line === 4 && c.what === '/proc/self/fd/1' && c.detail === 'fd 1';
  })(),
  JSON.stringify(stdio('a/scripts/x.sh', ...FDS)));

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
// The deliberate bash fallbacks are clean because their PRAGMAS exempt them, not
// because rule 5 cannot see `${VAR:-/dev/stdout}`: with each pragma's name spoiled,
// every one of them fires. A rule blind to the shape would pass the clean-tree
// check above just the same.
const STDIO_PRAGMAD = { 'a11y-audit/scripts/audit.sh': 1, 'latin-urls/scripts/audit.sh': 2, 'pull-tier/scripts/tier.sh': 2 };
check('the 5 deliberate bash fallbacks are exempt by pragma, not unseen',
  Object.entries(STDIO_PRAGMAD).every(([f, n]) => {
    const raw = fs.readFileSync(path.join(root, f), 'utf8');
    return lintStdioPath(raw, f).length === 0
      && lintStdioPath(raw.replaceAll('lint-allow-stdio-path:', 'lint-allow-spoiled:'), f).length === n;
  }),
  JSON.stringify(Object.keys(STDIO_PRAGMAD).map((f) => {
    const raw = fs.readFileSync(path.join(root, f), 'utf8');
    return [f, lintStdioPath(raw, f).length, lintStdioPath(raw.replaceAll('lint-allow-stdio-path:', 'lint-allow-spoiled:'), f).length];
  })));

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
