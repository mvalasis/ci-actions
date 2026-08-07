#!/usr/bin/env node
// ---------------------------------------------------------------------------
// lint-entrypoint-output — repo-internal hygiene gate (NOT a shipped action).
//
// THREE RULES, one theme: defects in action entrypoints that a green run cannot
// distinguish from correct code.
//   1. async stdout writes before process.exit()  — see below.
//   2. crash guards registered after main runs     — see "rule 2" further down.
//   3. no crash guard at all, in any language      — see "rule 3" further down.
//
// Rules 1 and 2 are JavaScript-shaped and apply to `*.mjs` only. Rule 3 applies
// to every language an action ships an entrypoint in (.mjs, .py, .sh), and only
// to the files an `action.yml` actually EXECUTES — the pure library modules
// beside them cannot set an exit code, so a guard there would be noise.
//
// THE DEFECT CLASS THIS EXISTS TO KILL
// `process.stdout` / `process.stderr` writes are ASYNC when the fd is a pipe on
// macOS (they are synchronous on Linux and Windows, and synchronous to a TTY or
// a file everywhere). `process.exit()` does NOT drain a pending async write, so
// an action entrypoint that emits its report with `console.log(...)` and then
// exits truncates its own output at the 65,536-byte pipe buffer — silently, with
// a zero exit code. CI runs on Linux, so the bug is LATENT there and only bites
// on local runs, which is exactly why it survives review.
//
// Fixed by hand twice already:
//   - test-suite      v1.7.0 (66154d0) — introduced the `say` helper.
//   - verify-homepage v1.7.1 (c4197b9) — same fix + `sayErr` on fd 2. Measured
//     on a Mac: a 78,083-byte report arrived as 65,536 bytes, losing the `---`
//     verdict line. Found only because a sibling audit happened to look.
//
// THE RULE
// Inside an action entrypoint, ALL job-log output goes through a synchronous
// write. Any `console.*(...)` or `process.std{out,err}.write(...)` is a finding —
// not just one adjacent to a `process.exit()`. That is deliberately stricter than
// the defect (the two can sit many lines apart — in the v1.7.1 case they were
// separated by a blank line and an `if`), and it is why this lint has no false
// negatives and needs no dataflow analysis. Entrypoints already emit either via
// `fs.appendFileSync(summaryFile, …)` or via a `say`/`sayErr` helper, so the
// clean state is the status quo, not a migration.
//
//   const say    = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };
//   const sayErr = (s = '') => { try { fs.writeSync(2, `${s}\n`); } catch { console.error(s); } };
//
// SCOPE
// Action scripts only: `<dir-with-an-action.yml>/scripts/*.{mjs,py,sh}`, minus
// `selftest*`. Discovery is by `action.yml` presence rather than a hardcoded
// list, so a new action's entrypoint is covered the day it lands — and so this
// script's own directory (`.github/scripts/`, no action.yml) is structurally out
// of scope. The scan is NON-recursive, which also keeps test fixtures like
// `test-suite/scripts/selftest/*/vitest-stub.mjs` out.
//
// Rule 3 narrows further to the EXECUTED subset (discoverExecuted), read from the
// `run:` lines of each action.yml. Both discovery passes fail CLOSED on an empty
// result: a restructured tree must not silently pass a blocking gate, and a rule
// that has switched itself off looks exactly like a rule with nothing to report.
//
// The seven `*/scripts/selftest.mjs` files legitimately end in `console.log(...)`
// then `process.exit(...)`. They are exempt because they CANNOT hit the bug:
// measured output is 1375–4117 bytes (contract-check 2534, seo-aeo 3043,
// form-protection 3396, security-baseline 2100, deps-currency 2577, test-suite
// 4117, verify-homepage 1375) — an order of magnitude under the 65,536-byte pipe
// buffer. Do not "fix" them; the exemption is the finding, not an oversight.
//
// ALLOWANCES (both deliberate, both narrow)
//   1. The sync-write fallback itself: a `console.*` that is the `catch` arm of
//      an `fs.writeSync(` on the SAME line — i.e. the `say`/`sayErr` helper.
//      That console call only ever runs when the sync write already threw.
//   2. `// lint-allow-raw-output: <reason>` on the offending line or the line
//      directly above it. A reason is REQUIRED — a bare pragma does not pass.
//
// Repo-internal only: no caller consumes this, so changing it needs no version
// bump and no `v1` tag move.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// This linter is subject to its own rule. Its output is a variable-length
// violation list followed by process.exit() — precisely the shape that
// truncates. fs.writeSync, never console.log.
const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };

const PRAGMA = /\/\/\s*lint-allow-raw-output:\s*\S/;

// ---------- source scrubber ----------
// Blank every non-code span (comments, string and template literals, regex
// literals) so the matcher below only ever sees CODE. Offsets and line numbers
// are preserved: each blanked character becomes a space, newlines are kept.
//
// Without this the lint would fire on its own remediation advice — run.mjs:37
// and render-check.mjs:44 both spell out `console.log` in a comment explaining
// why they do not use it — and a regex such as /['"]/ would desync a naive
// string scanner and swallow real code after it.
const REGEX_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'case', 'do', 'else', 'yield', 'await',
]);

// Decide whether `/` opens a regex literal or is a division operator, from the
// last significant code token. 'w' = identifier/number, 'x' = a completed
// literal. After a value, `/` divides; after an operator or a keyword, it opens
// a regex.
function regexAllowed(prev, word) {
  if (prev === '') return true;                       // start of file
  if (prev === 'w') return REGEX_KEYWORDS.has(word);  // `return /re/` vs `a / b`
  if (prev === 'x') return false;                     // after a string/regex
  if (prev === ')' || prev === ']') return false;     // (a+b)/2, arr[0]/2
  return true;                                        // ( , = : [ ! & | ? { } ; …
}

export function blankNonCode(src) {
  const out = Array.from(src);
  const n = src.length;
  const wipe = (i) => { if (i < n && src[i] !== '\n') out[i] = ' '; };
  const interp = [];   // brace depths at which a `${` interpolation was opened
  let depth = 0;
  let prev = '';
  let word = '';
  let mode = 'code';
  let i = 0;

  while (i < n) {
    if (mode === 'tmpl') {
      if (src[i] === '\\') { wipe(i); wipe(i + 1); i += 2; continue; }
      if (src[i] === '`') { wipe(i); i++; mode = 'code'; prev = 'x'; word = ''; continue; }
      if (src[i] === '$' && src[i + 1] === '{') {
        wipe(i); wipe(i + 1); i += 2;
        interp.push(depth); depth++;              // the `{` of `${`
        mode = 'code'; prev = '{'; word = '';
        continue;
      }
      wipe(i); i++; continue;
    }

    const c = src[i], d = src[i + 1];

    if (c === '/' && d === '/') {                 // line comment
      while (i < n && src[i] !== '\n') wipe(i++);
      continue;
    }
    if (c === '/' && d === '*') {                 // block comment
      wipe(i); wipe(i + 1); i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) wipe(i++);
      if (i < n) { wipe(i); wipe(i + 1); i += 2; }
      continue;
    }
    if (c === "'" || c === '"') {                 // string literal
      wipe(i); i++;
      while (i < n && src[i] !== c && src[i] !== '\n') {
        if (src[i] === '\\') { wipe(i); wipe(i + 1); i += 2; continue; }
        wipe(i); i++;
      }
      if (i < n && src[i] === c) { wipe(i); i++; }
      prev = 'x'; word = '';
      continue;
    }
    if (c === '`') { wipe(i); i++; mode = 'tmpl'; continue; }
    if (c === '/' && regexAllowed(prev, word)) {  // regex literal
      wipe(i); i++;
      let inClass = false;
      while (i < n && src[i] !== '\n') {
        const r = src[i];
        if (r === '\\') { wipe(i); wipe(i + 1); i += 2; continue; }
        if (r === '[') inClass = true;
        else if (r === ']') inClass = false;
        else if (r === '/' && !inClass) break;
        wipe(i); i++;
      }
      if (i < n && src[i] === '/') { wipe(i); i++; }
      while (i < n && /[a-z]/.test(src[i])) { wipe(i); i++; }   // flags
      prev = 'x'; word = '';
      continue;
    }
    if (c === '{') { depth++; prev = '{'; word = ''; i++; continue; }
    if (c === '}') {
      if (interp.length && depth === interp[interp.length - 1] + 1) {
        interp.pop(); depth--; wipe(i); i++; mode = 'tmpl';     // close `${…}`
        continue;
      }
      depth--; prev = '}'; word = ''; i++;
      continue;
    }
    if (/\s/.test(c)) { i++; continue; }
    if (/[A-Za-z_$0-9]/.test(c)) {                // identifier / number / member path
      let j = i, w = '';
      while (j < n && /[A-Za-z_$0-9.]/.test(src[j])) { w += src[j]; j++; }
      word = w; prev = 'w'; i = j;
      continue;
    }
    prev = c; word = ''; i++;
  }

  return out.join('');
}

// ---------- rule 2: crash-guard ordering ----------
// THE DEFECT CLASS: `process.on('uncaughtException', …)` registered BELOW the main
// IIFE. The IIFE is evaluated at module load and every path through it ends in
// `process.exit()`, so the registration is unreachable — the guard is dead code
// that has never run. It reads as defensive and reviews as fine, which is exactly
// why it survived from deps-currency's first commit to 2026-08-05.
//
// Two ways it stays dead, both silent:
//   - main succeeds → process.exit() terminates before the registration line;
//   - main throws   → module evaluation aborts at the throw, never reaching it.
// Either way the crash exits 1 with a bare stack and writes NOTHING to the step
// summary (the report is appended at the END of main), so the operator loses both
// the intended exit code and the intended diagnostic.
//
// THE RULE: a top-level crash-guard registration must not be preceded by a
// top-level statement that can terminate the process — a direct `process.exit(`
// or an invoked top-level IIFE. Deliberately strict: hoisting the guard to the
// top is always free and always correct, so there is no shape worth excusing and
// no dataflow analysis needed. The five sibling entrypoints register via
// `(async () => {…})().catch(…)`, which is ordering-immune and never trips this.
const GUARD_EVENTS = /uncaughtException|unhandledRejection/;

// Depth of each character, with closers already popped — so a character that
// belongs to a top-level statement reads 0.
function depthMap(code) {
  const d = new Array(code.length);
  let depth = 0;
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c === ')' || c === ']' || c === '}') depth--;
    d[i] = depth;
    if (c === '(' || c === '[' || c === '{') depth++;
  }
  return d;
}

// Top-level `(…)()` invocations — the main-IIFE shape in both its sync
// (`(function main(){…})();`) and async (`(async () => {…})();`) spellings.
// Returns the index just past the trailing `()`.
function iifeInvocations(code, d) {
  const ends = [];
  for (let i = 0; i < code.length; i++) {
    if (code[i] !== ')' || d[i] !== 0) continue;
    let k = i + 1;
    while (k < code.length && /\s/.test(code[k])) k++;
    if (code[k] !== '(') continue;
    let m = k + 1;
    while (m < code.length && /\s/.test(code[m])) m++;
    if (code[m] !== ')') continue;
    // Confirm the `)` at i actually closes a top-level group (balanced walk back).
    let bal = 0, start = -1;
    for (let b = i - 1; b >= 0; b--) {
      const c = code[b];
      if (c === ')' || c === ']' || c === '}') bal++;
      else if (c === '(' || c === '[' || c === '{') {
        if (bal === 0 && c === '(') { start = b; break; }
        bal--;
      }
    }
    if (start === -1) continue;
    ends.push(m);
    i = m;
  }
  return ends;
}

export function lintCrashGuardOrder(src, file = '<input>') {
  const code = blankNonCode(src);
  const d = depthMap(code);
  const findings = [];

  // Earliest top-level statement that can terminate the process.
  const terminators = iifeInvocations(code, d);
  const exitRe = /\bprocess\s*\.\s*exit\s*\(/g;
  let m;
  while ((m = exitRe.exec(code)) !== null) {
    if (d[m.index] === 0) terminators.push(m.index);
  }
  if (terminators.length === 0) return findings;
  const firstTerminator = Math.min(...terminators);

  // Line starts, for translating an offset into line/col.
  const lineAt = (idx) => {
    let line = 1, col = idx + 1;
    for (let i = 0; i < idx; i++) if (code[i] === '\n') { line++; col = idx - i; }
    return { line, col };
  };

  const onRe = /\bprocess\s*\.\s*on\s*\(/g;
  const rawLines = src.split('\n');
  while ((m = onRe.exec(code)) !== null) {
    if (d[m.index] !== 0) continue;               // registered inside a function — not our class
    if (m.index < firstTerminator) continue;      // armed before anything runs — correct
    // The event name lives in a string literal, which the scrubber blanked; read it raw.
    const { line, col } = lineAt(m.index);
    const raw = src.slice(m.index, m.index + 80);
    if (!GUARD_EVENTS.test(raw)) continue;        // some other process.on — out of scope
    const ev = raw.match(GUARD_EVENTS)[0];
    const tl = lineAt(firstTerminator).line;
    findings.push({
      file, line, col, kind: 'dead-crash-guard',
      what: `process.on('${ev}'`,
      text: (rawLines[line - 1] || '').trim(),
      detail: `registered at line ${line}, but the process can already have exited at line ${tl}`,
    });
  }
  return findings;
}

// ---------- matcher ----------
const BANNED = [
  { re: /\bconsole\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g, name: (m) => `console.${m[1]}(` },
  { re: /\bprocess\s*\.\s*(stdout|stderr)\s*\.\s*write\s*\(/g, name: (m) => `process.${m[1]}.write(` },
];

// The `say`/`sayErr` shape: `try { fs.writeSync(…) } catch { console.log(s) }`.
// Requires the sync write to come BEFORE the `catch`, and the console call
// AFTER it, on one line — so only the fallback arm is excused, never a bare
// console call that happens to share a line with an unrelated writeSync.
function isSyncFallback(codeLine, at) {
  const w = codeLine.indexOf('fs.writeSync(');
  const c = codeLine.indexOf('catch');
  return w !== -1 && c > w && at > c;
}

export function lintSource(src, file = '<input>') {
  const rawLines = src.split('\n');
  const codeLines = blankNonCode(src).split('\n');
  const findings = [];

  for (let i = 0; i < codeLines.length; i++) {
    const code = codeLines[i];
    if (!code.includes('console') && !code.includes('process')) continue;

    for (const { re, name } of BANNED) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(code)) !== null) {
        if (isSyncFallback(code, m.index)) continue;
        // Pragma is read from the RAW line (it lives in a comment, which the
        // scrubber blanked) — same line, or the line directly above.
        if (PRAGMA.test(rawLines[i] || '') || PRAGMA.test(rawLines[i - 1] || '')) continue;
        findings.push({ file, line: i + 1, col: m.index + 1, kind: 'raw-output', what: name(m), text: rawLines[i].trim() });
      }
    }
  }
  findings.push(...lintCrashGuardOrder(src, file));
  return findings.sort((a, b) => a.line - b.line || a.col - b.col);
}

// ---------- rule 3: crash-guard PRESENCE, in every shipped language ----------
// THE DEFECT CLASS: an entrypoint with no crash guard at all. A fault in the tool
// then exits non-zero and BLOCKS a caller who explicitly asked for report mode —
// our bug, charged to their repo, under a verdict the tool never actually reached.
//
// Rule 2 above covers only the JS ordering shape (a guard registered too late).
// It cannot see the three actions that shipped with no guard whatsoever until
// v1.12.0 — render-check.mjs (a top-level-await module ending in a bare
// process.exit), linkcheck.py (a plain main() under `if __name__`), audit.sh
// (`set -uo pipefail`, no trap). Two of those are not even JavaScript, which is
// why discovery below covers .mjs, .py and .sh rather than a hardcoded list.
//
// Detection is per language, and deliberately shallow — it answers "is there a
// guard here at all", not "is it correct". Correctness is asserted BEHAVIOURALLY
// by each action's own selftest, which crashes the real entrypoint and reads the
// exit code; a static check cannot do that and should not pretend to.
//
// KNOWN LIMIT, stated rather than papered over: for bash this matches any
// `trap … EXIT`, so a pure CLEANUP trap (`trap 'rm -f "$TMP"' EXIT`) reads as a
// guard. link-crawl.sh has exactly that shape. It carries an explicit exemption
// pragma anyway, so its rationale is on the record and does not rest on this
// heuristic — but a future bash entrypoint could satisfy the rule with a cleanup
// trap and no guard. The behavioural selftests are the layer that catches that;
// tightening this regex to guess intent would trade a known limit for a false
// sense of one.
const GUARD_PRESENT = {
  '.mjs': (src) =>
    // an explicit process-level handler …
    /process\s*\.\s*on\s*\(\s*['"](?:uncaughtException|unhandledRejection)['"]/.test(src)
    // … or the ordering-immune sibling shape: `(async () => {…})().catch(…)`
    || /\)\s*\(\s*\)\s*\.\s*catch\s*\(/.test(src),
  '.py': (src) => {
    // The guard has to wrap the main invocation, so look only BELOW `if __name__`.
    const i = src.search(/^if\s+__name__\s*==/m);
    if (i === -1) return /^\s*try:/m.test(src) && /^\s*except\b/m.test(src);
    const tail = src.slice(i);
    return /^\s+try:/m.test(tail) && /^\s+except\b/m.test(tail);
  },
  '.sh': (src) => /^\s*trap\s+.*\bEXIT\b/m.test(src),
};

// `# lint-allow-no-crash-guard: <reason>` (or `//` for JS). A reason is REQUIRED,
// same as the raw-output pragma — a bare pragma does not pass, because the point
// is to record WHY an entrypoint is allowed to fail loud, not to switch the rule
// off. The two exemptions in this repo are linkcheck/scripts/sitemap-urls.py and
// verify-homepage/scripts/link-crawl.sh: neither has a report-mode input to
// consult, and each one's wrapper already attributes its failure correctly, so
// there is no misattribution to fix. That — misattribution, not the exit code —
// is the test for whether an entrypoint needs this rule.
// `[ \t]` and not `\s`: this regex is tested against the WHOLE file, so a `\s*`
// here would happily cross the newline and let the next line's first character
// satisfy the required `\S` — making a bare, reason-less pragma pass. (The
// raw-output pragma above uses `\s*` safely only because it is tested one line at
// a time.) Caught by the "a BARE pragma does not exempt" fixture.
const NO_GUARD_PRAGMA = /(?:\/\/|#)[ \t]*lint-allow-no-crash-guard:[ \t]*\S/;

export function lintCrashGuardPresence(src, file = '<input>', executed = false) {
  // A guard only means anything in a file that is EXECUTED as a process. The
  // pure library modules beside the entrypoints (engine.mjs, checks.mjs,
  // tiers.mjs, detect.mjs, firstparty.mjs — "no network, no process exit" by
  // their own headers) are imported, never spawned: they cannot set an exit code,
  // so there is nothing for them to get wrong and a guard in one would be noise.
  // Callers pass `executed` from discoverExecuted(); the default is false so a
  // direct call cannot accidentally flag a library.
  if (!executed) return [];
  const ext = path.extname(file);
  const detect = GUARD_PRESENT[ext];
  if (!detect) return [];
  if (NO_GUARD_PRAGMA.test(src)) return [];
  if (detect(src)) return [];
  return [{
    file, line: 1, col: 1, kind: 'missing-crash-guard',
    what: 'no crash guard',
    text: (src.split('\n')[0] || '').trim(),
    detail: `${ext} entrypoint has no crash guard, so a fault in the tool exits non-zero and blocks a report-mode caller`,
  }];
}

// Dispatch the whole rule set for one entrypoint. The JS rules (raw output,
// guard ordering) are JS-only — running the JS scrubber over Python or bash
// would produce noise, not findings — while rule 3 applies to every language,
// but only to files that action.yml actually executes.
export function lintEntrypoint(src, file = '<input>', executed = false) {
  const findings = path.extname(file) === '.mjs' ? lintSource(src, file) : [];
  findings.push(...lintCrashGuardPresence(src, file, executed));
  return findings.sort((a, b) => a.line - b.line || a.col - b.col);
}

// ---------- which scripts are actually EXECUTED ----------
// Ground truth, read from each action.yml rather than guessed from the source: a
// script is executed iff some action.yml names it, whether as `run: node
// scripts/x.mjs` or `bash "${{ github.action_path }}/scripts/x.sh"`. Everything
// else under scripts/ is a library module reached only by `import`.
//
// Deliberately over-inclusive: a filename mentioned in an action.yml COMMENT also
// counts. The failure mode of over-inclusion is "we asked for a crash guard in a
// file that did not need one", which surfaces immediately and loudly; the failure
// mode of under-inclusion is an unguarded entrypoint shipping silently, which is
// the whole defect class. Bias to the noisy side.
export function discoverExecuted(root) {
  const executed = new Set();
  for (const dir of fs.readdirSync(root, { withFileTypes: true })) {
    if (!dir.isDirectory() || dir.name.startsWith('.')) continue;
    const actionYml = path.join(root, dir.name, 'action.yml');
    if (!fs.existsSync(actionYml)) continue;
    const yml = fs.readFileSync(actionYml, 'utf8');
    for (const m of yml.matchAll(/scripts\/([A-Za-z0-9_.-]+\.(?:mjs|py|sh))/g)) {
      executed.add(path.posix.join(dir.name, 'scripts', m[1]));
    }
  }
  return executed;
}

// ---------- entrypoint discovery ----------
// An "action entrypoint" is any top-level `<action>/scripts/*.{mjs,py,sh}` where
// `<action>/action.yml` exists, except `selftest.*`. Non-recursive.
//
// Discovery is by `action.yml` presence rather than a hardcoded list, so a new
// action's entrypoint is covered the day it lands — and so this script's own
// directory (`.github/scripts/`, no action.yml) is structurally out of scope.
const ENTRYPOINT_EXT = ['.mjs', '.py', '.sh'];
export function discoverEntrypoints(root) {
  const files = [];
  for (const dir of fs.readdirSync(root, { withFileTypes: true })) {
    if (!dir.isDirectory() || dir.name.startsWith('.')) continue;
    if (!fs.existsSync(path.join(root, dir.name, 'action.yml'))) continue;
    const scripts = path.join(root, dir.name, 'scripts');
    if (!fs.existsSync(scripts)) continue;
    for (const e of fs.readdirSync(scripts, { withFileTypes: true })) {
      if (!e.isFile()) continue;
      if (!ENTRYPOINT_EXT.includes(path.extname(e.name))) continue;
      // Selftests are not shipped entrypoints — no caller ever runs one.
      if (/^selftest(\.|-)/.test(e.name) || e.name.startsWith('selftest')) continue;
      files.push(path.posix.join(dir.name, 'scripts', e.name));
    }
  }
  return files.sort();
}

const REMEDY_GUARD = [
  '',
  'Why this is a finding:',
  '  A crash guard registered below the main IIFE is DEAD CODE. The IIFE runs at',
  '  module load and every path through it ends in process.exit(), so the line is',
  '  never reached — and if main throws instead, module evaluation aborts at the',
  '  throw, which does not reach it either. The crash then exits 1 with a bare',
  '  stack and writes NOTHING to the step summary. Shipped this way in',
  '  deps-currency from its first commit until 2026-08-05.',
  '',
  'Fix — hoist the registration above the invocation (always free, always correct):',
  "  process.on('uncaughtException', (e) => { …report…; process.exit(FAIL_ON_X ? 1 : 0); });",
  '',
  '  (function main() { … })();',
  '',
  '  …or use the sibling shape, which is ordering-immune because the handler is',
  '  attached to the promise rather than to the process:',
  '  (async () => { … })().catch((e) => { …report…; process.exit(FAIL_ON_X ? 1 : 0); });',
];

const REMEDY_MISSING = [
  '',
  'Why this is a finding:',
  '  An entrypoint with no crash guard turns a fault in OUR tool into a red build',
  '  in the CALLER\'s repo — even when that caller explicitly asked for report mode.',
  '  The fault is also mis-attributed: it arrives looking like a finding about their',
  '  site. Three actions shipped this way until v1.12.0 (verify-homepage, linkcheck,',
  '  a11y-audit); linkcheck additionally filed a false "broken links found" issue.',
  '',
  'The rule: report the fault as a fault, and exit under the caller\'s own setting.',
  '  JS    process.on(\'uncaughtException\', …) hoisted above the main invocation,',
  '        or the ordering-immune `(async () => {…})().catch(…)` shape.',
  '        Exit FAIL_ON_X ? 1 : 0. Read FAIL_ON_X from process.env, not from a',
  '        module const — the const is in the TDZ if the crash happens during init.',
  '  Python  try/except around main() under `if __name__`. SystemExit is not an',
  '        Exception, so deliberate verdict exits pass through untouched.',
  '  bash  `trap … EXIT` armed on the FIRST executable line, plus a sentinel that',
  '        deliberate exits set. NOT `trap … ERR`: `set -u` aborts without firing',
  '        ERR, and with errexit off ERR fires on commands that are not faults.',
  '',
  'Failing loud is genuinely right? Annotate it (a reason is required):',
  '  # lint-allow-no-crash-guard: <why a fault here must not be softened>',
  '  The test is MISATTRIBUTION, not the exit code: an entrypoint with no',
  '  report-mode input whose wrapper already reports the fault correctly has',
  '  nothing to align (see sitemap-urls.py, link-crawl.sh).',
];

const REMEDY = [
  '',
  'Why this is a finding:',
  '  process.stdout/stderr writes are ASYNC on macOS pipes (sync on Linux/Windows),',
  '  and process.exit() does not drain a pending async write — so output truncates',
  '  at the 65,536-byte pipe buffer, silently, with a zero exit code. CI is Linux so',
  '  it is latent there; it bites on local runs. Fixed by hand in test-suite v1.7.0',
  '  and again in verify-homepage v1.7.1 (a 78,083-byte report arrived as 65,536).',
  '',
  'Fix — emit through a synchronous write:',
  '  const say    = (s = \'\') => { try { fs.writeSync(1, `${s}\\n`); } catch { console.log(s); } };',
  '  const sayErr = (s = \'\') => { try { fs.writeSync(2, `${s}\\n`); } catch { console.error(s); } };',
  '',
  '  …or append to the step summary, which is already synchronous:',
  '  fs.appendFileSync(env.GITHUB_STEP_SUMMARY || \'/dev/stdout\', text);',
  '',
  'Genuinely need the raw call? Annotate it (a reason is required):',
  '  // lint-allow-raw-output: <why this cannot truncate>',
];

function main() {
  const root = process.argv[2] || process.cwd();
  const files = discoverEntrypoints(root);

  // Fail CLOSED on an empty scan: a restructured tree must not silently pass a
  // blocking gate. This is the same false-green the test-suite v1.7.0 job-log
  // mirror was built to prevent.
  if (files.length === 0) {
    say(`::error::lint-entrypoint-output: no action entrypoints found under ${root} — discovery is broken, refusing to pass`);
    return 2;
  }

  const executed = discoverExecuted(root);

  // Fail CLOSED again: every action ships at least one executed script, so an
  // empty set means the action.yml parse broke and rule 3 has silently switched
  // itself off — indistinguishable, in a green run, from "every guard is present".
  if (executed.size === 0) {
    say(`::error::lint-entrypoint-output: no executed scripts found in any action.yml under ${root} — rule 3 would pass vacuously, refusing to pass`);
    return 2;
  }

  const findings = [];
  for (const rel of files) {
    findings.push(...lintEntrypoint(fs.readFileSync(path.join(root, rel), 'utf8'), rel, executed.has(rel)));
  }

  if (findings.length === 0) {
    // Name every file scanned: a green run has to be auditable, or "0 findings"
    // is indistinguishable from "scanned nothing".
    say(`lint-entrypoint-output: ✅ clean — ${files.length} action entrypoint(s), no raw stdout/stderr writes, no dead crash guards, no missing crash guards`);
    for (const f of files) say(`  · ${f}`);
    return 0;
  }

  say(`lint-entrypoint-output: ❌ ${findings.length} finding(s) across ${files.length} scanned entrypoint(s)`);
  say('');
  const guards = findings.filter((f) => f.kind === 'dead-crash-guard');
  const missing = findings.filter((f) => f.kind === 'missing-crash-guard');
  const raws = findings.filter((f) => f.kind !== 'dead-crash-guard' && f.kind !== 'missing-crash-guard');
  for (const f of findings) {
    // Annotation content is derived from our own repo tree, never from input.
    let msg;
    if (f.kind === 'dead-crash-guard') {
      msg = `${f.what} is registered AFTER the entrypoint's main invocation — ${f.detail}, so the guard is dead code and has never run. Hoist it above the invocation. See .github/scripts/lint-entrypoint-output.mjs`;
    } else if (f.kind === 'missing-crash-guard') {
      msg = `${f.detail}. Add one, or annotate the file with \`lint-allow-no-crash-guard: <why failing loud is correct here>\`. See .github/scripts/lint-entrypoint-output.mjs`;
    } else {
      msg = `${f.what} in an action entrypoint — output must go through a synchronous write (fs.writeSync), not an async stdout/stderr write. See .github/scripts/lint-entrypoint-output.mjs`;
    }
    say(`::error file=${f.file},line=${f.line},col=${f.col}::${msg}`);
    say(`  ${f.file}:${f.line}:${f.col}  ${f.what}`);
    say(`      ${f.text}`);
  }
  if (raws.length) for (const l of REMEDY) say(l);
  if (guards.length) for (const l of REMEDY_GUARD) say(l);
  if (missing.length) for (const l of REMEDY_MISSING) say(l);

  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const md = [
      '### ❌ lint-entrypoint-output',
      '',
      raws.length ? `${raws.length} raw stdout/stderr write(s) in action entrypoints. \`process.exit()\` does not drain an async write, so the output truncates at 64 KiB on macOS pipes.` : '',
      guards.length ? `${guards.length} crash guard(s) registered after the main invocation — dead code that has never run.` : '',
      missing.length ? `${missing.length} executed entrypoint(s) with no crash guard — a fault in the tool blocks a report-mode caller and arrives looking like a finding about their site.` : '',
      '',
      '| file | line | finding |',
      '| --- | --- | --- |',
      ...findings.map((f) => {
        const label = { 'dead-crash-guard': ' — dead crash guard', 'missing-crash-guard': ' — missing crash guard' }[f.kind] || '';
        return `| \`${f.file}\` | ${f.line} | \`${f.what}\`${label} |`;
      }),
      '',
      raws.length ? 'Fix: emit through `say`/`sayErr` (`fs.writeSync`) or `fs.appendFileSync(summaryFile, …)`.' : '',
      guards.length ? 'Fix: hoist the `process.on(...)` registration above the main IIFE invocation.' : '',
      missing.length ? 'Fix: add a guard that reports the fault and exits `FAIL_ON_X ? 1 : 0`, or annotate with `lint-allow-no-crash-guard: <reason>`.' : '',
      '',
    ].join('\n');
    try { fs.appendFileSync(summary, md + '\n'); } catch { /* summary is best-effort */ }
  }

  return 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  process.exit(main());
}
