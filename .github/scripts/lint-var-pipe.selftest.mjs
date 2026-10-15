#!/usr/bin/env node
// Offline fixture suite for lint-var-pipe. Pins BOTH directions:
//   - it fires on every spelling of the defect, including the four sites removed
//     on 2026-10-15 verbatim, one of them inside "$( )";
//   - it does NOT fire on the here-string fix, on a reader that reads everything,
//     on `||`, on a value with no expansion, on comments, quoted messages or
//     heredoc bodies.
// The tokenizer fixtures are the load-bearing ones: a quote, a `<<` or a `$(( ))`
// misread would derail the scan and hide every pipe after it, which is why most
// negatives are followed by a positive that must still fire.
//
// A blocking gate whose scan is wrong fails silently in the permissive direction,
// so this suite runs in CI ahead of the lint itself.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { commandLists, scanShell, runBlocks, lintFile, discover } from './lint-var-pipe.mjs';

const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };

let failed = 0;
function check(name, cond, detail = '') {
  if (cond) say(`  ✅ ${name}`);
  else { say(`  ❌ ${name} ${detail}`); failed++; }
}

const src = (...lines) => lines.join('\n');
const hits = (...lines) => scanShell(src(...lines)).hits.length;
const BAD = `printf '%s' "$v" | grep -q x`;

// ---------------------------------------------------------------------------
say('\n# the defect fires');

const FIRES = {
  'printf into grep -q': `printf '%s\\n' "$v" | grep -q x`,
  'echo into grep -q': 'echo "$v" | grep -q x',
  'an unquoted expansion': 'echo $v | grep -qx y',
  'printf into head': `printf '%s\\n' "$v" | head -1`,
  'head with no count': 'echo "$v" | head',
  'inside $( )': `num=$(printf '%s\\n' "$raw" | head -1)`,
  'inside backticks': 'x=`echo "$v" | head -n 2`',
  'q in a later option cluster': `printf '%s' "$v" | grep -E -q 'a|b'`,
  '--quiet': `printf '%s' "$v" | grep --quiet x`,
  '-m1': `printf '%s' "$v" | grep -m1 x`,
  '--max-count=1': `printf '%s' "$v" | grep --max-count=1 x`,
  '-l': `printf '%s' "$v" | grep -l x`,
  '-L': `printf '%s' "$v" | grep -L x`,
  'egrep': `printf '%s' "$v" | egrep -q x`,
  'fgrep': `printf '%s' "$v" | fgrep -q x`,
  'grep by path': `printf '%s' "$v" | /usr/bin/grep -q x`,
  'an array expansion': `printf '%s\\n' "\${arr[@]}" | grep -q x`,
  'a substitution as the value': `printf '%s' "$(cat f)" | grep -q x`,
  'an Actions expression as the value': 'echo "${{ inputs.list }}" | head -1',
  'a | inside the printf format': `printf '%s|%s\\n' "$a" "$b" | grep -q x`,
  'a prefix assignment on the reader': `printf '%s' "$v" | LC_ALL=C grep -q x`,
  'command grep': `printf '%s' "$v" | command grep -q x`,
  'a prefix assignment on the producer': `LC_ALL=C printf '%s' "$v" | grep -q x`,
  'a redirect on the producer': `printf '%s' "$v" 2>/dev/null | grep -q x`,
  '|&': `printf '%s' "$v" |& grep -q x`,
  'a reader in { }': `printf '%s' "$v" | { grep -q x; }`,
  'a reader in ( )': `printf '%s' "$v" | (grep -q x)`,
  'after &&': `[ -n "$x" ] && printf '%s' "$v" | grep -q x`,
  'after if': `if printf '%s' "$v" | grep -q x; then :; fi`,
  'printf --': `printf -- '%s' "$v" | grep -q x`,
  'a \\-newline before the pipe': `printf '%s' "$v" \\\n  | grep -q x`,
  'a trailing | and the reader on the next line': `printf '%s' "$v" |\n  grep -q x`,
  'a \\-newline between a prefix and the producer': `LC_ALL=C \\\n  printf '%s' "$v" | grep -q x`,
};
for (const [name, s] of Object.entries(FIRES)) check(name, hits(s) === 1, `(${hits(s)} hit(s) in ${JSON.stringify(s)})`);

// The four sites this lint was written for, verbatim from origin/main before the fix.
const SITES = [
  `            num=$(printf '%s\\n' "$raw" | head -1)`,
  `          printf '%s' "$comments" | grep -qF 'Resolved' \\\n            || { echo "::error::#$ISSUE closed without the resolved-clean comment"; exit 1; }`,
  `            printf '%s\\n' "$nums" | grep -qx "$ISSUE" || nums="$(printf '%s\\n%s' "$nums" "$ISSUE")"`,
  `check "control: git prints the Greek path C-quoted without -z (else the next check is vacuous)" "$(printf '%s\\n' "$quoted" | grep -q '^"src/lib/[\\]' && echo 0 || echo 1)"`,
];
check('the four removed sites each fire', SITES.every((s) => hits(s) === 1), JSON.stringify(SITES.map((s) => hits(s))));

const r = scanShell(src('a=1', `  x=$(printf '%s' "$v" | head -1)`));
check('a hit carries the producer, the reader and its offset',
  r.hits.length === 1 && r.hits[0].producer === 'printf' && r.hits[0].reader === 'head' && r.hits[0].at === 10,
  JSON.stringify(r.hits));

// ---------------------------------------------------------------------------
say('\n# it does not fire');

const QUIET = {
  'the here-string fix (grep)': 'grep -q x <<<"$v"',
  'the here-string fix (head)': 'num=$(head -1 <<<"$raw")',
  'printf -v writes no stdout, piped or not': `printf -v out '%s' "$v" | grep -q x`,
  '||, not a pipe': `printf '%s' "$v" || grep -q x`,
  'no expansion in the value': 'echo hit | grep -q hit',
  'grep -c reads everything': `printf '%s\\n' "$v" | grep -c x`,
  'grep -E with no q reads everything': `printf '%s\\n' "$v" | grep -E '^[0-9]+$'`,
  'wc, tr, sed, sort, python read everything': src(
    `printf '%s\\n' "$v" | wc -l`, `printf '%s' "$v" | tr '\\n' ' '`, `printf '%s\\n' "$v" | sed -n 1p`,
    `printf '%s\\n' "$v" | sort -u`, `printf '%s\\n' "$v" | python3 f.py`),
  'a while-read loop (a known limit, not a hit)': `printf '%s\\n' "$v" | while IFS= read -r l; do :; done`,
  'a reader in a substitution of the value': `echo "$(printf '%s' "$v" | tr a b)"`,
  'grep -e -q: -q is the pattern': `printf '%s' "$v" | grep -e -q`,
  'grep -- -q: -q is the pattern': `printf '%s' "$v" | grep -- -q`,
  'a comment line': `# ${BAD}`,
  'a trailing comment': `true  # ${BAD}`,
  'a single-quoted message': `echo 'never ${BAD.replaceAll("'", '')}'`,
  'a double-quoted message': 'echo "never printf \\"\\$v\\" | grep -q x"',
  'a file argument, no pipe': `printf '%s' "$v" > f; grep -q x f`,
};
for (const [name, s] of Object.entries(QUIET)) check(name, hits(s) === 0, `(${hits(s)} hit(s) in ${JSON.stringify(s)})`);

check('a heredoc body is not code, and the scan resumes after it',
  hits('cat <<\'EOF\' > f.sh', BAD, 'EOF', BAD) === 1
  && hits('cat <<-EOF', `\t${BAD}`, '\tEOF', BAD) === 1
  && hits('cat <<"EOF" | grep -q x', BAD, 'EOF') === 0);
check('a here-string is not a heredoc', hits('grep -q a <<<"$v"', BAD) === 1);
check('<< in $(( )) and (( )) is not a heredoc', hits('n=$(( 1 << 2 ))', BAD) === 1 && hits('(( x <<= 1 ))', BAD) === 1);
check('a quote does not desync the scan', hits(`echo "it's" '"'`, BAD) === 1 && hits('echo \\"', BAD) === 1);
check('an array assignment does not end the command list', hits('arr=(a "b c")', BAD) === 1 && hits(`arr=($(printf '%s\\n' "$v" | head -3))`) === 1);
check('a case pattern\'s ) does not end the scan', hits('case "$f" in $pat) echo hit; return 0 ;; esac', BAD) === 1);

// ---------------------------------------------------------------------------
say('\n# the tokenizer');

const terms = commandLists('a | b; c && d || e & f')[0].map((c) => c.term);
check('terminators', JSON.stringify(terms) === JSON.stringify(['|', ';', '&&', '||', '&', '']), JSON.stringify(terms));
check('$( ), backticks, <( ) and "$( )" each get their own list',
  commandLists('x=$(a | b) `c` <(d) "$(e)"').length === 5, `(${commandLists('x=$(a | b) `c` <(d) "$(e)"').length})`);
const ws = commandLists(`printf '%s|x' "$v" 2>&1`)[0][0].words;
check('quotes come off, redirects stay one word, expansions are marked',
  JSON.stringify(ws.map((w) => [w.text, w.expands])) === JSON.stringify([['printf', false], ['%s|x', false], ['', true], ['2>&1', false]]),
  JSON.stringify(ws.map((w) => [w.text, w.expands])));

// ---------------------------------------------------------------------------
say('\n# run: blocks');

const YML = src(
  'jobs:',
  '  t:',
  '    steps:',
  '      - name: printf "$v" | grep -q x',
  '        run: |',
  '          a=1',
  '',
  `          ${BAD}`,
  '        shell: bash',
  '      - run: |-',
  `          ${BAD}`,
  '      - run: echo "$v" | head -1',
  `      - run: '${BAD.replaceAll("'", "''")}'`,
  'defaults:',
  '  run:',
  '    shell: bash',
);
const blocks = runBlocks(YML);
check('four run: values, the empty defaults one skipped', blocks.length === 4, JSON.stringify(blocks));
check('a block ends at its sibling key, keeps its blank lines and loses its indent',
  blocks[0].line === 6 && blocks[0].col === 11 && blocks[0].text === src('a=1', '', BAD), JSON.stringify(blocks[0]));
check('a one-line run: keeps its column; a quoted one is unquoted',
  blocks[2].line === 12 && blocks[2].col === 14 && blocks[2].text === 'echo "$v" | head -1'
  && blocks[3].col === 15 && blocks[3].text === BAD,
  JSON.stringify(blocks.slice(2)));
const fy = lintFile(YML, 'w.yml').findings;
check('a YAML finding names the file line and column of its producer; a name: is not shell',
  JSON.stringify(fy.map((f) => [f.line, f.col])) === JSON.stringify([[8, 11], [11, 11], [12, 14], [13, 15]]),
  JSON.stringify(fy.map((f) => [f.line, f.col])));

// ---------------------------------------------------------------------------
say('\n# the pragma');

const lf = (...lines) => lintFile(src(...lines), 'x.sh');
const same = lf(`${BAD}  # lint-allow-var-pipe: one line, checked above`);
const above = lf('# lint-allow-var-pipe: the value is one issue number', BAD);
check('a pragma with a reason, on the line or the one above, waives', same.findings.length === 0 && same.waived === 1 && above.findings.length === 0 && above.waived === 1);
check('a bare pragma does not', lf('# lint-allow-var-pipe:', BAD).findings.length === 1);
check('a pragma two lines up does not', lf('# lint-allow-var-pipe: too far', 'true', BAD).findings.length === 1);

// ---------------------------------------------------------------------------
say('\n# the premise, executed');
// Why the lint exists, run rather than asserted: with pipefail a match on the first
// line of a large value reads as no match through the pipe, and as a match through a
// here-string — with SIGPIPE ignored, as GitHub's runners run every job, the writer
// also prints "write error: Broken pipe".
const premise = (trap) => spawnSync('bash', ['-c', `set -o pipefail; ${trap}
v="Resolved"$'\\n'"$(seq 1 200000)"
printf '%s' "$v" | grep -qF Resolved; echo "pipe=$?"
grep -qF Resolved <<<"$v"; echo "here=$?"`], { encoding: 'utf8' });
const ign = premise("trap '' PIPE"), dfl = premise('');
check('SIGPIPE ignored: the pipe misses with the Broken-pipe line, the here-string matches',
  /pipe=[1-9]/.test(ign.stdout) && /here=0/.test(ign.stdout) && /Broken pipe/.test(ign.stderr), JSON.stringify([ign.stdout, ign.stderr.slice(0, 120)]));
check('SIGPIPE at its default: the pipe misses, the here-string matches',
  /pipe=[1-9]/.test(dfl.stdout) && /here=0/.test(dfl.stdout), JSON.stringify(dfl.stdout));

// ---------------------------------------------------------------------------
say('\n# main() fails closed, and blocks');

const lint = path.join(path.dirname(fileURLToPath(import.meta.url)), 'lint-var-pipe.mjs');
const tree = (files) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-var-pipe-'));
  for (const [f, body] of Object.entries(files)) {
    fs.mkdirSync(path.join(d, path.dirname(f)), { recursive: true });
    fs.writeFileSync(path.join(d, f), body);
  }
  return d;
};
const run = (d) => {
  const env = { ...process.env };
  delete env.GITHUB_STEP_SUMMARY;
  const p = spawnSync(process.execPath, [lint, d], { encoding: 'utf8', env });
  fs.rmSync(d, { recursive: true, force: true });
  return p;
};
const OK_YML = 'runs:\n  steps:\n    - run: |\n        printf \'%s\\n\' "$v" | wc -l\n      shell: bash\n';
const clean = run(tree({ 'a/action.yml': OK_YML, 'a/scripts/x.sh': 'echo "$v" | tr a b\n' }));
check('a clean tree exits 0', clean.status === 0, JSON.stringify([clean.status, clean.stdout.slice(0, 200)]));
const dirty = run(tree({ 'a/action.yml': OK_YML, 'a/scripts/x.sh': `true\n${BAD}\n` }));
check('a dirty tree exits 1 with an annotation at the producer',
  dirty.status === 1 && dirty.stdout.includes('::error file=a/scripts/x.sh,line=2,col=1::'), JSON.stringify([dirty.status, dirty.stdout.slice(0, 300)]));
check('an empty tree exits 2', run(tree({ 'README.md': 'x\n' })).status === 2);
check('a tree with no printf/echo pipe at all exits 2 (the scan reads nothing)',
  run(tree({ 'a/action.yml': 'runs:\n  steps:\n    - run: true\n', 'a/scripts/x.sh': 'true\n' })).status === 2);

// ---------------------------------------------------------------------------
say('\n# the live tree is clean (the lint is wired as blocking)');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const { shell, yaml } = discover(root);
check('discovery reaches the four sites\' files, a composite action and the 13 shell files',
  shell.includes('pull-tier/scripts/selftest.sh') && yaml.includes('.github/workflows/linkcheck-selftest.yml')
  && yaml.includes('linkcheck/action.yml') && shell.length >= 13,
  JSON.stringify({ shell: shell.length, yaml: yaml.length }));
let live = 0, livePipes = 0;
for (const rel of [...shell, ...yaml]) {
  const x = lintFile(fs.readFileSync(path.join(root, rel), 'utf8'), rel);
  live += x.findings.length; livePipes += x.pipes;
}
check(`all ${shell.length + yaml.length} files lint clean, ${livePipes} pipe(s) read`, live === 0 && livePipes > 0, `(${live} finding(s))`);

// Clean because the shapes are gone, not because the scan cannot reach them: put
// each removed line back into the LIVE file and it fires, at its own line.
const UNDO = [
  ['.github/workflows/linkcheck-selftest.yml', 'num=$(head -1 <<<"$raw")', `num=$(printf '%s\\n' "$raw" | head -1)`],
  ['.github/workflows/linkcheck-selftest.yml', `grep -qF 'Resolved' <<<"$comments"`, `printf '%s' "$comments" | grep -qF 'Resolved'`],
  ['.github/workflows/linkcheck-selftest.yml', 'grep -qx "$ISSUE" <<<"$nums"', `printf '%s\\n' "$nums" | grep -qx "$ISSUE"`],
  ['pull-tier/scripts/selftest.sh', `grep -q '^"src/lib/[\\]' <<<"$quoted"`, `printf '%s\\n' "$quoted" | grep -q '^"src/lib/[\\]'`],
];
const undone = UNDO.map(([f, now, was]) => {
  const raw = fs.readFileSync(path.join(root, f), 'utf8');
  const at = raw.indexOf(now);
  if (at < 0) return `${f}: fixed line not found`;
  const line = raw.slice(0, at).split('\n').length;
  const got = lintFile(raw.replace(now, was), f).findings.map((x) => x.line);
  return JSON.stringify(got) === JSON.stringify([line]) ? 'ok' : `${f}: ${JSON.stringify(got)} vs [${line}]`;
});
check('each removed site, put back in its live file, fires at its line', undone.every((u) => u === 'ok'), JSON.stringify(undone));

say(failed === 0 ? '\n✅ all lint-var-pipe self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
