#!/usr/bin/env node
// ---------------------------------------------------------------------------
// lint-entrypoint-output — repo-internal hygiene gate (NOT a shipped action).
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
// Action entrypoints only: `<dir-with-an-action.yml>/scripts/*.mjs`, minus
// `selftest.mjs`. Discovery is by `action.yml` presence rather than a hardcoded
// list, so a new action's entrypoint is covered the day it lands — and so this
// script's own directory (`.github/scripts/`, no action.yml) is structurally out
// of scope. The scan is NON-recursive, which also keeps test fixtures like
// `test-suite/scripts/selftest/*/vitest-stub.mjs` out.
//
// The six `*/scripts/selftest.mjs` files legitimately end in `console.log(...)`
// then `process.exit(...)`. They are exempt because they CANNOT hit the bug:
// measured output is 2100–4117 bytes (contract-check 2534, seo-aeo 3043,
// form-protection 3396, security-baseline 2100, deps-currency 2577, test-suite
// 4117) — an order of magnitude under the 65,536-byte pipe buffer. Do not
// "fix" them; the exemption is the finding, not an oversight.
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
        findings.push({ file, line: i + 1, col: m.index + 1, what: name(m), text: rawLines[i].trim() });
      }
    }
  }
  return findings;
}

// ---------- entrypoint discovery ----------
// An "action entrypoint" is any top-level `<action>/scripts/*.mjs` where
// `<action>/action.yml` exists, except `selftest.mjs`. Non-recursive.
export function discoverEntrypoints(root) {
  const files = [];
  for (const dir of fs.readdirSync(root, { withFileTypes: true })) {
    if (!dir.isDirectory() || dir.name.startsWith('.')) continue;
    if (!fs.existsSync(path.join(root, dir.name, 'action.yml'))) continue;
    const scripts = path.join(root, dir.name, 'scripts');
    if (!fs.existsSync(scripts)) continue;
    for (const e of fs.readdirSync(scripts, { withFileTypes: true })) {
      if (!e.isFile() || !e.name.endsWith('.mjs') || e.name === 'selftest.mjs') continue;
      files.push(path.posix.join(dir.name, 'scripts', e.name));
    }
  }
  return files.sort();
}

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

  const findings = [];
  for (const rel of files) {
    findings.push(...lintSource(fs.readFileSync(path.join(root, rel), 'utf8'), rel));
  }

  if (findings.length === 0) {
    // Name every file scanned: a green run has to be auditable, or "0 findings"
    // is indistinguishable from "scanned nothing".
    say(`lint-entrypoint-output: ✅ clean — ${files.length} action entrypoint(s), no raw stdout/stderr writes`);
    for (const f of files) say(`  · ${f}`);
    return 0;
  }

  say(`lint-entrypoint-output: ❌ ${findings.length} finding(s) across ${files.length} scanned entrypoint(s)`);
  say('');
  for (const f of findings) {
    // Annotation content is derived from our own repo tree, never from input.
    say(`::error file=${f.file},line=${f.line},col=${f.col}::${f.what} in an action entrypoint — output must go through a synchronous write (fs.writeSync), not an async stdout/stderr write. See .github/scripts/lint-entrypoint-output.mjs`);
    say(`  ${f.file}:${f.line}:${f.col}  ${f.what}`);
    say(`      ${f.text}`);
  }
  for (const l of REMEDY) say(l);

  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const md = [
      '### ❌ lint-entrypoint-output',
      '',
      `${findings.length} raw stdout/stderr write(s) in action entrypoints. \`process.exit()\` does not drain an async write, so the output truncates at 64 KiB on macOS pipes.`,
      '',
      '| file | line | call |',
      '| --- | --- | --- |',
      ...findings.map((f) => `| \`${f.file}\` | ${f.line} | \`${f.what}\` |`),
      '',
      'Fix: emit through `say`/`sayErr` (`fs.writeSync`) or `fs.appendFileSync(summaryFile, …)`.',
      '',
    ].join('\n');
    try { fs.appendFileSync(summary, md + '\n'); } catch { /* summary is best-effort */ }
  }

  return 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  process.exit(main());
}
