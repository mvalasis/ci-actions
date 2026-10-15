#!/usr/bin/env node
// ---------------------------------------------------------------------------
// lint-var-pipe — repo-internal hygiene gate (NOT a shipped action).
//
// THE DEFECT CLASS: a variable printed into a reader that stops early.
//     printf '%s\n' "$v" | grep -q x          printf '%s\n' "$v" | head -1
// grep -q (-m, -l, -L) exits at its first match and head at its count, while
// printf or echo may still be writing the rest of a multi-line value; its next
// write hits a closed pipe. Under pipefail the pipeline then FAILS although grep
// matched: 141 where the writer dies of SIGPIPE, 1 on GitHub's runners, which run
// every job with SIGPIPE ignored, so the writer gets EPIPE instead and prints
// "write error: Broken pipe". Pipefail is on in every `shell: bash` step
// (`bash -eo pipefail`, which every composite action step names) and in most
// scripts here; a workflow `run:` with no `shell:` is `bash -e`, where the status
// survives and only the Broken-pipe line prints. Only a LARGE value races, never
// the small fixtures a green run feeds it. Measured with pipefail: a 1.2 MB value
// matching on its first line read as "no match" 50 times in 50 through the pipe
// (rc 141 with SIGPIPE at its default, rc 1 with it ignored), 0 times through a
// here-string. Removed from this tree 2026-10-15: three in
// .github/workflows/linkcheck-selftest.yml, one in pull-tier/scripts/selftest.sh.
//
// THE FIX — feed the reader the value whole:
//     grep -q x <<<"$v"          head -1 <<<"$v"
// The here-string appends one newline, exactly as printf '%s\n' does. Against
// printf '%s' or echo -n it differs only for a pattern that can match an empty
// line, or a reader that counts bytes.
//
// THE RULE: in every shell surface of the repo — each *.sh/*.bash file, and each
// `run:` of a workflow (.github/workflows/) or an action.yml — a printf (not -v)
// or echo in command position with an expansion ($v, ${…}, $(…), `…`) among its
// words, piped by a single `|` into
//   - grep, egrep or fgrep with q, m, l or L in an option cluster, or --quiet,
//     --silent, --max-count, --files-with-matches, --files-without-match;
//   - head, whatever its count.
// Deliberately stricter than the defect, as lint-entrypoint-output's rules 1 and
// 5 are: a one-line value cannot race grep (it matches whole lines), but no lint
// knows a value's lines, and the here-string costs nothing.
//
// The scan is a small shell tokenizer, not a regex over lines: quotes are opaque
// (a `|` inside a printf format is no pipe); the code inside $( ), backticks and
// <( ) is read as its own command list wherever it sits (the pull-tier site was
// inside "$( )"); a `\` newline, or a newline after | && ||, carries a command on;
// comments and heredoc bodies are not code.
//
// `# lint-allow-var-pipe: <reason>` on the producer's line or the line directly
// above it exempts that pipe. A reason is REQUIRED — a bare pragma does not count.
//
// KNOWN LIMITS, stated rather than papered over. Not seen: any other writer
// (`git log | head -1` and `sort | head -n N` take the same EPIPE, but their fix
// is not a here-string); any other reader that stops early (awk … exit, sed … q,
// a while-read loop that breaks); a reader named by a variable; shell inside a
// .mjs or .py string; a script without a .sh/.bash name; and a `case` pattern's
// `)` inside $( ), which ends the substitution early. Seen when it should not be:
// a quoted assignment word ("a=b") taken for a prefix assignment.
//
// ANOTHER REPO'S TREE: `node lint-var-pipe.mjs <root>` lints any tree (the
// 2026-10-15 fleet sweep ran it over every sibling repo). A tree there may hold no
// printf/echo pipe at all (luxairport-frontend once its one finding was fixed); it
// passes on a line of its own, "0 printf/echo pipes to read", never the clean line.
// In ci-actions' own tree, the one this file sits in, that count fails closed.
//
// Repo-internal only: no caller consumes this, so changing it needs no version
// bump and no `v1` tag move.
// ---------------------------------------------------------------------------

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Subject to lint-entrypoint-output's rule 1 in spirit: a variable-length report
// followed by process.exit() goes through a synchronous write.
const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };

const PRAGMA = /#[ \t]*lint-allow-var-pipe:[ \t]*\S/;

// ---------- the tokenizer ----------
// commandLists(s) → every command list in s: the top level first, then one per
// $( ), `…` and <( ), in the order they open. A command is { words, term }: each
// word { text, start, expands } (text with its quotes removed, start its offset
// in s, expands whether an expansion sits anywhere in it), and term the operator
// that ended it: | || && ; & ( ) or a newline. Empty commands are dropped, so a
// pipe's reader is always the next command in its list, across a newline too.
export function commandLists(s) {
  const lists = [];
  const heredocs = [];
  let i = 0;

  // Just past a newline: skip the bodies of the heredocs that line opened.
  function heredocBodies() {
    while (heredocs.length) {
      const { delim, strip } = heredocs.shift();
      while (i < s.length) {
        let j = s.indexOf('\n', i);
        if (j < 0) j = s.length;
        const line = strip ? s.slice(i, j).replace(/^\t+/, '') : s.slice(i, j);
        i = Math.min(j + 1, s.length);
        if (line === delim) break;
      }
    }
  }

  // At `$`: one expansion (or a lone `$`), added to word w.
  function dollar(w) {
    const n = s[i + 1];
    if (n === '(' && s[i + 2] === '(') { w.expands = true; i++; arith(); return; }
    if (n === '(') { w.expands = true; i += 2; parseList(')'); return; }
    if (n === '{') { w.expands = true; i += 2; braceBody(w); return; }
    if (n === "'") { i += 2; ansiC(w); return; }
    if (n !== undefined && /[A-Za-z_]/.test(n)) {
      w.expands = true; i += 2;
      while (i < s.length && /[A-Za-z0-9_]/.test(s[i])) i++;
      return;
    }
    if (n !== undefined && /[0-9@*#?$!-]/.test(n)) { w.expands = true; i += 2; return; }
    w.text += '$'; i++;
  }

  // At the first `(` of `((`: to just past the matching `))`.
  function arith() {
    let depth = 0;
    for (; i < s.length; i++) {
      if (s[i] === '(') depth++;
      else if (s[i] === ')' && --depth === 0) { i++; return; }
    }
  }

  // Just past `${`: to just past its `}`, reading the quotes and substitutions in it.
  function braceBody(w) {
    let depth = 1;
    while (i < s.length) {
      const c = s[i];
      if (c === '\\') { i += 2; continue; }
      if (c === '}') { i++; if (--depth === 0) return; continue; }
      if (c === '{') { depth++; i++; continue; }
      if (c === "'") { const k = s.indexOf("'", i + 1); i = k < 0 ? s.length : k + 1; continue; }
      if (c === '"') { i++; dquote(w); continue; }
      if (c === '$') { dollar(w); continue; }
      if (c === '`') { i++; parseList('`'); continue; }
      i++;
    }
  }

  // Just past an opening `"`: to just past the closing one.
  function dquote(w) {
    while (i < s.length && s[i] !== '"') {
      const c = s[i];
      if (c === '\\') { w.text += s[i + 1] ?? ''; i += 2; continue; }
      if (c === '$') { dollar(w); continue; }
      if (c === '`') { w.expands = true; i++; parseList('`'); continue; }
      w.text += c; i++;
    }
    i++;
  }

  // Just past `$'`: an ANSI-C string, a literal with backslash escapes.
  function ansiC(w) {
    while (i < s.length && s[i] !== "'") {
      if (s[i] === '\\') { w.text += s[i + 1] ?? ''; i += 2; continue; }
      w.text += s[i]; i++;
    }
    i++;
  }

  // At `<<` (not `<<<`): the operator and its delimiter word; the body is skipped
  // at the end of the line.
  function heredoc() {
    let j = i + 2;
    const strip = s[j] === '-';
    if (strip) j++;
    while (s[j] === ' ' || s[j] === '\t') j++;
    let delim = '';
    while (j < s.length && !/[\s;&|()<>]/.test(s[j])) {
      if (s[j] === "'" || s[j] === '"') {
        const k = s.indexOf(s[j], j + 1);
        delim += s.slice(j + 1, k < 0 ? s.length : k);
        j = k < 0 ? s.length : k + 1;
      } else if (s[j] === '\\') { delim += s[j + 1] ?? ''; j += 2; } else { delim += s[j]; j++; }
    }
    if (delim) heredocs.push({ delim, strip });
    i = j;
  }

  // Commands until `closer` — `)` for $( ) and <( ), a backtick for `…` — or the end.
  function parseList(closer) {
    const cmds = [];
    lists.push(cmds);
    let words = [];
    let w = null;
    const word = () => (w ??= { text: '', start: i, expands: false });
    const endWord = () => { if (w) { words.push(w); w = null; } };
    const endCmd = (term) => {
      endWord();
      if (words.length) cmds.push({ words, term });
      words = [];
    };
    while (i < s.length) {
      const c = s[i];
      if (c === '\\') {
        if (s[i + 1] === '\n') { i += 2; continue; }
        word().text += s[i + 1] ?? ''; i += 2; continue;
      }
      if (c === ' ' || c === '\t' || c === '\r') { endWord(); i++; continue; }
      if (c === '\n') { endCmd('\n'); i++; heredocBodies(); continue; }
      if (c === '#' && !w) { while (i < s.length && s[i] !== '\n') i++; continue; }
      if (c === closer) { endCmd(closer); i++; return; }
      if (c === ';') { endCmd(';'); i++; continue; }
      if (c === '|') {
        if (w && /[<>]$/.test(w.text)) { w.text += c; i++; continue; }
        if (s[i + 1] === '|') { endCmd('||'); i += 2; continue; }
        endCmd('|'); i += s[i + 1] === '&' ? 2 : 1; continue;
      }
      if (c === '&') {
        if (s[i + 1] === '&') { endCmd('&&'); i += 2; continue; }
        if ((w && /[<>]$/.test(w.text)) || s[i + 1] === '>') { word().text += c; i++; continue; }
        endCmd('&'); i++; continue;
      }
      if ((c === '<' || c === '>') && s[i + 1] === '(') { word().expands = true; i += 2; parseList(')'); continue; }
      if (c === '(') {
        if (!w && !words.length && s[i + 1] === '(') { arith(); continue; }
        endCmd('('); i++; continue;
      }
      if (c === ')') { endCmd(')'); i++; continue; }
      if (c === '`') { word().expands = true; i++; parseList('`'); continue; }
      if (c === "'") {
        const k = s.indexOf("'", i + 1);
        word().text += s.slice(i + 1, k < 0 ? s.length : k);
        i = k < 0 ? s.length : k + 1; continue;
      }
      if (c === '"') { const x = word(); i++; dquote(x); continue; }
      if (c === '$') { dollar(word()); continue; }
      if (c === '<' && s[i + 1] === '<') {
        if (s[i + 2] === '<') { word().text += '<<<'; i += 3; continue; }
        endWord(); heredoc(); continue;
      }
      word().text += c; i++;
    }
    endCmd('');
  }

  parseList(null);
  return lists;
}

// ---------- the matcher ----------
const RESERVED = new Set(['if', 'then', 'elif', 'else', 'do', 'while', 'until', '!', 'time', '{', '}']);
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/;
const PRODUCERS = new Set(['printf', 'echo']);
const GREPS = new Set(['grep', 'egrep', 'fgrep']);
const GREP_LONG = /^--(quiet|silent|max-count|files-with-matches|files-without-match)(=|$)/;

// The index of the command's name: past reserved words, prefix assignments, and
// `command`, `builtin` or `env` (with env's own options).
function nameAt(words) {
  let k = 0;
  while (k < words.length) {
    const t = words[k].text;
    if (RESERVED.has(t) || ASSIGN.test(t) || t === 'command' || t === 'builtin') { k++; continue; }
    if (t === 'env') { k++; while (k < words.length && words[k].text.startsWith('-')) k++; continue; }
    break;
  }
  return k;
}
const base = (t) => t.slice(t.lastIndexOf('/') + 1);

function isProducer(cmd) {
  const k = nameAt(cmd.words);
  if (k >= cmd.words.length || !PRODUCERS.has(base(cmd.words[k].text))) return false;
  if (base(cmd.words[k].text) === 'printf' && cmd.words[k + 1]?.text === '-v') return false;
  return cmd.words.slice(k + 1).some((w) => w.expands);
}

// The reader's name when it stops at a match or a count, else ''.
function earlyReader(cmd) {
  const ws = cmd.words;
  const k = nameAt(ws);
  if (k >= ws.length) return '';
  const name = base(ws[k].text);
  if (name === 'head') return 'head';
  if (!GREPS.has(name)) return '';
  for (let m = k + 1; m < ws.length; m++) {
    const x = ws[m].text;
    if (x === '--') return '';
    if (GREP_LONG.test(x)) return `${name} ${x}`;
    if (!/^-[A-Za-z0-9]/.test(x)) continue;
    for (let j = 1; j < x.length; j++) {
      if ('qmlL'.includes(x[j])) return `${name} ${x}`;
      // An option that takes an argument: the rest of the cluster, or the next word.
      if ('efABCDd'.includes(x[j])) { if (j === x.length - 1) m++; break; }
    }
  }
  return '';
}

// Every printf/echo-of-an-expansion pipe in shell source s: { pipes, hits }, each
// hit { at, producer, reader } with `at` the producer's offset in s.
export function scanShell(s) {
  let pipes = 0;
  const hits = [];
  for (const cmds of commandLists(s)) {
    for (let n = 0; n < cmds.length - 1; n++) {
      if (cmds[n].term !== '|' || !isProducer(cmds[n])) continue;
      pipes++;
      const reader = earlyReader(cmds[n + 1]);
      if (!reader) continue;
      const k = nameAt(cmds[n].words);
      hits.push({ at: cmds[n].words[k].start, producer: base(cmds[n].words[k].text), reader });
    }
  }
  return { pipes, hits: hits.sort((a, b) => a.at - b.at) };
}

// ---------- the YAML `run:` blocks ----------
// Each `run:` of a workflow or action.yml, as { line, col, text }: line is the
// file line `text` starts on, col the column it starts at. A block scalar
// (`run: |`, `|-`, `>` …) runs to the first non-blank line indented no deeper
// than the `run` key; anything else is a one-line command.
export function runBlocks(yml) {
  const lines = yml.split('\n');
  const out = [];
  for (let n = 0; n < lines.length; n++) {
    const m = /^(\s*(?:-\s+)?)run:(?:[ \t]+(.*?))?[ \t]*\r?$/.exec(lines[n]);
    if (!m) continue;
    const key = m[1].length;
    const val = m[2] || '';
    if (/^[|>][-+0-9]*(\s+#.*)?$/.test(val)) {
      const body = [];
      let indent = -1;
      let k = n + 1;
      for (; k < lines.length; k++) {
        const l = lines[k];
        if (/^\s*$/.test(l)) { body.push(''); continue; }
        const ind = l.length - l.trimStart().length;
        if (ind <= key) break;
        if (indent < 0) indent = ind;
        body.push(l.slice(Math.min(indent, ind)));
      }
      out.push({ line: n + 2, col: Math.max(indent, 0) + 1, text: body.join('\n') });
      n = k - 1;
    } else if (val) {
      const q = val[0];
      const quoted = (q === "'" || q === '"') && val.endsWith(q) && val.length > 1;
      let text = val;
      if (quoted) {
        text = val.slice(1, -1);
        text = q === "'" ? text.replaceAll("''", "'") : text.replace(/\\(["\\])/g, '$1');
      }
      out.push({ line: n + 1, col: lines[n].indexOf(val) + (quoted ? 2 : 1), text });
    }
  }
  return out;
}

// ---------- one file ----------
// { pipes, waived, findings } for one file's source; findings carry file, line,
// col, what and the raw line.
export function lintFile(src, file = '<input>') {
  const isYml = /\.ya?ml$/.test(file);
  const snippets = isYml ? runBlocks(src) : [{ line: 1, col: 1, text: src }];
  const raw = src.split('\n');
  let pipes = 0, waived = 0;
  const findings = [];
  for (const sn of snippets) {
    const r = scanShell(sn.text);
    pipes += r.pipes;
    for (const h of r.hits) {
      // Every line of a run: block lost the same indent, so one column offset fits all.
      const before = sn.text.slice(0, h.at).split('\n');
      const line = sn.line + before.length - 1;
      const col = sn.col + before[before.length - 1].length;
      if (PRAGMA.test(raw[line - 1] || '') || PRAGMA.test(raw[line - 2] || '')) { waived++; continue; }
      findings.push({ file, line, col, what: `${h.producer} … | ${h.reader}`, text: (raw[line - 1] || '').trim() });
    }
  }
  return { pipes, waived, findings, snippets: snippets.length };
}

// ---------- discovery ----------
// Every *.sh/*.bash file, every workflow, every top-level action's action.yml.
// Dot-directories other than .github are skipped, and node_modules everywhere.
export function discover(root) {
  const shell = [], yaml = [];
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (e.name === 'node_modules' || (e.name.startsWith('.') && r !== '.github')) continue;
        walk(r);
      } else if (e.isFile()) {
        if (/\.(sh|bash)$/.test(e.name)) shell.push(r);
        else if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(r) || /^[^/.][^/]*\/action\.ya?ml$/.test(r)) yaml.push(r);
      }
    }
  };
  walk('');
  return { shell: shell.sort(), yaml: yaml.sort() };
}

const REMEDY = [
  '',
  'Why this is a finding:',
  '  grep -q (-m, -l, -L) exits at its first match and head at its count, while printf',
  '  or echo may still be writing the rest of a multi-line value. Under pipefail (every',
  '  `shell: bash` step, every composite action step, most scripts here) the pipeline',
  '  then fails although grep matched: 141 where the writer dies of SIGPIPE, 1 on',
  '  GitHub\'s runners, which ignore SIGPIPE, so printf prints "write error: Broken',
  '  pipe" instead. Only a large value races, so a green run on small fixtures proves',
  '  nothing.',
  '',
  'Fix — feed the reader the value whole:',
  '  grep -q x <<<"$v"          head -1 <<<"$v"',
  '  (the here-string appends the newline printf \'%s\\n\' would)',
  '',
  'The pipe must stay? Annotate it (a reason is required):',
  '  # lint-allow-var-pipe: <why this value cannot race the reader>',
  '  (on the producer\'s line or the line directly above it)',
];

// ci-actions' own tree: the one this file sits in, two levels above .github/scripts/.
// Compared by real path, so a relative or symlinked root still matches.
const OWN_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const realPath = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };

function main() {
  const root = process.argv[2] || process.cwd();
  const { shell, yaml } = discover(root);

  // Fail CLOSED on an empty scan: a restructured tree must not silently pass a
  // blocking gate.
  if (shell.length === 0 || yaml.length === 0) {
    say(`::error::lint-var-pipe: found ${shell.length} shell file(s) and ${yaml.length} workflow/action YAML file(s) under ${root} — discovery is broken, refusing to pass`);
    return 2;
  }

  let pipes = 0, waived = 0, blocks = 0;
  const findings = [];
  const rows = [];
  for (const rel of [...shell, ...yaml]) {
    const r = lintFile(fs.readFileSync(path.join(root, rel), 'utf8'), rel);
    pipes += r.pipes; waived += r.waived; findings.push(...r.findings);
    if (rel.endsWith('.yml') || rel.endsWith('.yaml')) blocks += r.snippets;
    rows.push(`  · ${rel} (${r.pipes} pipe(s))`);
  }

  // Fail CLOSED again on no run: block read, in any tree. In ci-actions' own tree,
  // which holds printf/echo pipes into readers that read everything (tr, sed, wc),
  // reading no pipe fails too: the tokenizer or the run: extraction broke —
  // indistinguishable, in a green run, from a clean tree.
  if (blocks === 0 || (pipes === 0 && realPath(root) === realPath(OWN_ROOT))) {
    say(`::error::lint-var-pipe: read ${blocks} run: block(s) and ${pipes} printf/echo pipe(s) under ${root} — the scan is broken, refusing to pass`);
    return 2;
  }

  // Another repo's tree may hold no printf/echo pipe at all. It passes, on a line no
  // sweep can take for the clean one: nothing was checked, so nothing was found.
  if (pipes === 0) {
    say(`lint-var-pipe: ⚪ 0 printf/echo pipes to read — ${shell.length} shell file(s), ${blocks} run: block(s) in ${yaml.length} YAML file(s) under ${root}: nothing to check, not a clean scan (allowed outside ci-actions' own tree, where it fails closed)`);
    for (const r of rows) say(r);
    return 0;
  }

  const scanned = `${shell.length} shell file(s), ${blocks} run: block(s) in ${yaml.length} YAML file(s), ${pipes} printf/echo pipe(s) read, ${waived} waived`;
  if (findings.length === 0) {
    say(`lint-var-pipe: ✅ clean — ${scanned}; none feeds a variable into a reader that stops early`);
    for (const r of rows) say(r);
    return 0;
  }

  say(`lint-var-pipe: ❌ ${findings.length} finding(s) — ${scanned}`);
  say('');
  for (const f of findings) {
    // Annotation content is derived from our own repo tree, never from input.
    say(`::error file=${f.file},line=${f.line},col=${f.col}::${f.file}:${f.line}: ${f.what} — a variable printed into a reader that stops early; under pipefail a large value reads as no match. Feed it a here-string (grep -q x <<<"$v", head -1 <<<"$v"), or annotate with \`lint-allow-var-pipe: <reason>\`. See .github/scripts/lint-var-pipe.mjs`);
    say(`  ${f.file}:${f.line}:${f.col}  ${f.what}`);
    say(`      ${f.text}`);
  }
  for (const l of REMEDY) say(l);

  const summary = process.env.GITHUB_STEP_SUMMARY !== '/dev/stdout' && process.env.GITHUB_STEP_SUMMARY;
  if (summary) {
    const md = [
      '### ❌ lint-var-pipe',
      '',
      `${findings.length} variable(s) printed into a reader that stops early (\`grep -q\`/\`-m\`/\`-l\`/\`-L\`, \`head\`). Under pipefail a large value reads as no match.`,
      '',
      '| file | line | finding |',
      '| --- | --- | --- |',
      ...findings.map((f) => `| \`${f.file}\` | ${f.line} | \`${f.what}\` |`),
      '',
      'Fix: feed it a here-string (`grep -q x <<<"$v"`, `head -1 <<<"$v"`), or annotate with `lint-allow-var-pipe: <reason>`.',
      '',
    ].join('\n');
    try { fs.appendFileSync(summary, md + '\n'); } catch { /* summary is best-effort */ }
  }
  return 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  process.exit(main());
}
