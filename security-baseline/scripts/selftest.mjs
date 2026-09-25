// Offline self-test for the security-baseline tier engine. No network, no real scanners — feeds
// canned findings to the pure engine and asserts the tiering / promotion / block decision and
// the redaction disclosure guard; then runs the real scan.mjs against stub scanners to assert
// what reaches the job log. Run: node scripts/selftest.mjs (also runs in CI). Exits
// non-zero on any regression — the gate's own regression guard, mirroring seo-aeo/selftest.mjs.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SEV, CHECKS, T0_CHECKS, T1_CHECKS, T2_CHECKS, RESERVED_CHECKS, evaluate, parsePromote,
  isPromotable, baseSev, safe, redact, escapeData, escapeProperty, annotation, annotations,
} from './tiers.mjs';
import { firstPartyOwners, ownerOf, parseOwners, refFromText, readLineFromDisk, filterFirstPartyGha } from './firstparty.mjs';

// The checkIds a scanner adapter in scan.mjs actually emits (kept in sync by the coverage
// assertion below — a new CHECKS id must be either wired here or explicitly RESERVED).
const EMITTED = new Set([
  'sast-critical', 'secret-pattern', 'secret-verified', 'secrets-history',
  'sca-critical', 'sca-high', 'sca-moderate', 'sca-low',
  'wp-nonce-missing', 'wp-cap-missing', 'wp-sql-unprepared', 'wp-unserialize', 'wp-file-include',
  'wp-rest-error-detail', 'wp-rest-error-detail-laundered', 'wp-weak-crypto', 'turnstile-test-key', 'wp-unescaped-output', 'wp-rest-wp-error-detail',
  'ts-dangerous-html', 'ts-eval', 'ts-child-process', 'ts-public-secret-leak', 'ts-ssrf',
  'ts-open-redirect', 'ts-secret-in-log', 'rn-insecure-storage', 'rn-cleartext-http', 'ts-cors-wildcard',
  'gha-unpinned-action', 'gha-script-injection', 'gha-pr-target', 'dockerfile-lint',
]);

let failed = 0;
function check(name, cond, detail = '') { if (cond) console.log(`  ✅ ${name}`); else { console.log(`  ❌ ${name} ${detail}`); failed++; } }
const F = (checkId, extra = {}) => ({ checkId, file: 'x.php', line: 1, msg: 'm', tool: 't', ...extra });

console.log('\n# tier model');
// every checkId maps to exactly one tier; sets are disjoint
{
  const all = Object.keys(CHECKS);
  const inSets = all.filter((k) => T0_CHECKS.has(k) || T1_CHECKS.has(k) || T2_CHECKS.has(k));
  check('every CHECK is in exactly one tier set', inSets.length === all.length);
  check('the CRITICAL core is tiny (exactly 3 T0 ids)', T0_CHECKS.size === 3, `got ${[...T0_CHECKS]}`);
  check('T0 = {sast-critical, secret-pattern, secret-verified}', ['sast-critical', 'secret-pattern', 'secret-verified'].every((k) => T0_CHECKS.has(k)));
  // coverage: every CHECKS id is either WIRED (emitted by a scanner) or explicitly RESERVED — no
  // dead declaration, and no id can silently become unintended-blocking.
  const covered = all.every((k) => EMITTED.has(k) || RESERVED_CHECKS.has(k));
  check('every CHECK is wired (emitted) or explicitly reserved', covered, `uncovered: ${all.filter((k) => !EMITTED.has(k) && !RESERVED_CHECKS.has(k))}`);
  check('emitted ∩ reserved = ∅', [...EMITTED].every((k) => !RESERVED_CHECKS.has(k)));
  check('no reserved id is T0 (a reserved id can never block)', [...RESERVED_CHECKS].every((k) => !T0_CHECKS.has(k)));
}

console.log('\n# the never-newly-block INVARIANT (table-driven over the whole CHECKS map)');
{
  // Under default opts (no promotion), a finding blocks IFF its checkId is T0 — for EVERY id.
  let ok = true; let bad = '';
  for (const id of Object.keys(CHECKS)) {
    const blocked = evaluate([F(id)]).blocked;
    if (blocked !== T0_CHECKS.has(id)) { ok = false; bad = id; break; }
  }
  check('∀ checkId: evaluate([id]).blocked === isT0(id)', ok, `violated by ${bad}`);
  check('an unknown id never blocks by default', evaluate([F('totally-unknown')]).blocked === false);
}

console.log('\n# default tiering & block-by-default');
{
  // T0 blocks by default
  const r = evaluate([F('sast-critical'), F('secret-pattern'), F('secret-verified')]);
  check('three T0 findings → crit=3', r.crit === 3, `crit=${r.crit}`);
  check('T0 blocks by default (fail-on-critical defaults TRUE)', r.blocked === true);
}
{
  // T1 is WARN and does NOT block by default — the never-newly-block guarantee
  const r = evaluate([F('sca-critical'), F('wp-sql-unprepared'), F('gha-unpinned-action'), F('ts-ssrf')]);
  check('T1 findings → warn, crit=0', r.crit === 0 && r.warn === 4, `crit=${r.crit} warn=${r.warn}`);
  check('T1 alone never blocks (no newly-block on the @v1 move)', r.blocked === false);
}
{
  // T2 advisory: sca-moderate/low are INFO; secrets-history is WARN; none block
  const r = evaluate([F('sca-moderate'), F('sca-low'), F('secrets-history'), F('wp-unescaped-output')]);
  check('sca-moderate/low → info', r.info === 2, `info=${r.info}`);
  check('T2 never blocks', r.blocked === false && r.crit === 0);
}

console.log('\n# per-caller promotion (critical-checks)');
{
  // promoting a T1 id lifts it to CRITICAL and blocks
  const r = evaluate([F('sca-critical'), F('wp-sql-unprepared')], { promote: ['sca-critical'] });
  check('promoted T1 (sca-critical) → crit', r.crit === 1, `crit=${r.crit}`);
  check('the non-promoted T1 stays warn', r.warn === 1);
  check('a promoted critical blocks under fail-on-critical', r.blocked === true);
}
{
  // a T2 id passed to critical-checks is IGNORED (never silently promotable)
  const p = parsePromote('secrets-history, sca-moderate, wp-unescaped-output, sca-critical, bogus-id');
  check('parsePromote keeps only T1 ids', p.promote.length === 1 && p.promote[0] === 'sca-critical', JSON.stringify(p));
  check('parsePromote reports T2/unknown ids as ignored', p.ignored.includes('secrets-history') && p.ignored.includes('bogus-id') && p.ignored.includes('sca-moderate'));
  const r = evaluate([F('secrets-history')], { promote: ['secrets-history'] });
  check('a T2 id cannot be promoted to block', r.crit === 0 && r.blocked === false);
  check('isPromotable: T1 yes, T2 no, T0 no', isPromotable('sca-high') && !isPromotable('secrets-history') && !isPromotable('secret-verified'));
  // evaluate()'s OWN promote filter (independent of parsePromote) must refuse T0/T2 ids passed directly
  const t2direct = evaluate([F('ts-cors-wildcard')], { promote: ['ts-cors-wildcard'] });
  check('evaluate() refuses a T2 id in opts.promote (stays non-crit)', t2direct.crit === 0 && t2direct.blocked === false);
  // promoting a T0 id is a no-op: it stays critical but is NOT marked promoted (it was already crit)
  const t0prom = evaluate([F('secret-verified')], { promote: ['secret-verified'] });
  check('promoting a T0 id is a no-op (crit, promoted=false)', t0prom.crit === 1 && t0prom.graded[0].promoted === false);
}

console.log('\n# report-mode escape hatch');
{
  // report-mode: even a T0 critical does not block (onboarding a heavy-debt repo)
  const r = evaluate([F('secret-verified')], { reportMode: true });
  check('report-mode: T0 critical reported but NOT blocked', r.crit === 1 && r.blocked === false && r.reportMode === true);
}
{
  // fail-on-critical:false also turns blocking off (report-first)
  const r = evaluate([F('sast-critical')], { failOnCritical: false });
  check('fail-on-critical:false → crit reported, not blocked', r.crit === 1 && r.blocked === false);
}

console.log('\n# unknown checkId is safe (a new rule never newly-blocks)');
{
  const r = evaluate([F('some-brand-new-rule-id')]);
  check('unknown checkId defaults to WARN (never CRITICAL)', r.warn === 1 && r.crit === 0 && r.blocked === false);
  check('baseSev(unknown) = warn', baseSev('zzz') === SEV.WARN);
}

console.log('\n# redaction disclosure guard (raw secret never reaches output)');
{
  const raw = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const red = redact(raw);
  check('redact keeps only first4…last4', red === 'ghp_…6789', red);
  check('redact NEVER contains the full secret', !red.includes(raw) && red.length < raw.length);
  check('short secret fully masked', redact('abc') === '****');
  check('gitleaks double-redaction floor: redact("REDACTED") = ****', redact('REDACTED') === '****');
  // composed guard: safe(redact(secret-with-markdown-chars)) carries no structural chars
  check('safe∘redact strips structural chars from a redacted token', !/[`|<>[\]()]/.test(safe(redact('`|<script>alert</script>`|'))));
}

console.log('\n# safe() neutralizes report-spoofing');
{
  check('safe strips newlines (no forged verdict line)', !safe('a\nBLOCKED').includes('\n'));
  check('safe strips markdown-structural chars + parens', safe('`x`|<img>[y](z)') === 'ximgyz');
  check('safe defangs URLs (no auto-link beacon)', safe('see https://evil.tld/x') === 'see https[:]//evil.tld/x');
  check('safe caps length', safe('x'.repeat(500), 50).length === 50);
}

console.log('\n# first-party owner resolution (the 2026-08 ownership split)');
{
  // (a) caller's owner ∪ (b) the ACTION's own owner ∪ (c) the first-party-owners input.
  // (b) is the whole point: after 11 repos moved to `creme-ypsilon` while mvalasis/ci-actions
  // stayed put, the caller's owner alone no longer identifies the fleet's own shared actions.
  const split = firstPartyOwners({ repository: 'creme-ypsilon/lampakia-astro', actionRepository: 'mvalasis/ci-actions' });
  check('owner set spans BOTH sides of the split', split.has('creme-ypsilon') && split.has('mvalasis'), [...split].join(','));
  check('extra owners from the input are merged', firstPartyOwners({ repository: 'a/b', extra: 'Foo, bar baz' }).size === 4);
  check('owner comparison is lowercased', firstPartyOwners({ repository: 'MVALASIS/ci-actions' }).has('mvalasis'));
  check('ownerOf takes the owner segment only', ownerOf('mvalasis/ci-actions/linkcheck') === 'mvalasis');
  // An EMPTY action_repository (the local `./` invocation used by this repo's own smoke job) must
  // contribute NOTHING. An '' in the set would match every ref whose owner failed to parse.
  const localRef = firstPartyOwners({ repository: 'mvalasis/ci-actions', actionRepository: '' });
  check('empty action_repository adds no owner (no ""-owner)', localRef.size === 1 && !localRef.has(''), [...localRef].join(','));
  check('a fully empty context yields an EMPTY set, not {""}', firstPartyOwners().size === 0);
  check('parseOwners drops empties from ragged input', parseOwners(' , a,,  b , ').join('|') === 'a|b');
}

console.log('\n# gha-unpinned-action post-filter (first-party noise, fail-toward-reporting)');
{
  const R = (ref, extra = {}) => ({
    path: '.github/workflows/x.yml', start: { line: 7 },
    extra: { metadata: { checkId: 'gha-unpinned-action' }, lines: `      - uses: ${ref}` }, ...extra,
  });
  // Injected reader: no disk, no cwd dependence — the test owns the "file contents" outright.
  const reader = (text) => () => text;
  const owners = firstPartyOwners({ repository: 'creme-ypsilon/lampakia-astro', actionRepository: 'mvalasis/ci-actions' });

  const fp = filterFirstPartyGha([R('mvalasis/ci-actions/linkcheck@v1')], owners, reader('      - uses: mvalasis/ci-actions/linkcheck@v1'));
  check('first-party THREE-segment ref is suppressed', fp.length === 0, JSON.stringify(fp));
  const own = filterFirstPartyGha([R('creme-ypsilon/shared-actions/build@v2')], owners, reader('      - uses: creme-ypsilon/shared-actions/build@v2'));
  check('the CALLER\'s own org is suppressed too', own.length === 0);
  // The real victim: three segments, genuinely third-party, must survive the filter.
  const tp = filterFirstPartyGha([R('gradle/actions/setup-gradle@v4')], owners, reader('      - uses: gradle/actions/setup-gradle@v4'));
  check('third-party THREE-segment ref is KEPT', tp.length === 1);
  // Unrecoverable: the disk read throws AND extra.lines carries no ref → fail toward REPORTING.
  const boom = () => { throw new Error('ENOENT'); };
  const lost = filterFirstPartyGha([{ path: 'gone.yml', start: { line: 3 }, extra: { metadata: { checkId: 'gha-unpinned-action' }, lines: '' } }], owners, boom);
  check('unrecoverable ref is KEPT (never fails toward silence)', lost.length === 1);
  // …but extra.lines IS the fallback when the read fails and the text is there.
  const viaLines = filterFirstPartyGha([R('mvalasis/ci-actions/seo-aeo@v1')], owners, boom);
  check('extra.lines is the fallback when the disk read throws', viaLines.length === 0);
  // THE POISON CASE: an empty owner set must suppress NOTHING (not everything).
  const noOwners = filterFirstPartyGha([R('gradle/actions/setup-gradle@v4'), R('mvalasis/ci-actions/linkcheck@v1')], firstPartyOwners(), reader(''));
  check('empty owner set suppresses NOTHING', noOwners.length === 2, `kept ${noOwners.length}`);
  const emptyActionOwner = firstPartyOwners({ repository: '', actionRepository: '', extra: '' });
  check('empty action-owner does not suppress everything', filterFirstPartyGha([R('gradle/actions/setup-gradle@v4')], emptyActionOwner, reader('')).length === 1);
  // An owner that will not parse (a ref beginning with `/`) is the SECOND fail-toward-reporting
  // guard in the filter, and an unasserted guard is one that can be inverted with nothing going
  // red — which is how a suppression path turns into a silent drop.
  const noOwner = filterFirstPartyGha([R('/ci-actions/linkcheck@v1')], owners, reader('      - uses: /ci-actions/linkcheck@v1'));
  check('a ref with an unparseable owner is KEPT', noOwner.length === 1);
  // Other gha rules are none of this filter's business. The recovered line here is deliberately a
  // FIRST-PARTY `uses:` — with the original `run: echo` the assertion still passed after deleting
  // the checkId guard entirely (the ref simply failed to recover, so the finding survived for the
  // wrong reason), i.e. it asserted nothing. Now removing the guard makes this finding suppressible
  // and the check goes red, which is the only version of it worth having.
  const otherLine = '      - uses: mvalasis/ci-actions/linkcheck@v1';
  const other = filterFirstPartyGha([{ path: 'x.yml', start: { line: 1 }, extra: { metadata: { checkId: 'gha-script-injection' }, lines: otherLine } }], owners, reader(otherLine));
  check('a non-gha-unpinned finding passes through untouched', other.length === 1);
  // THE DISK READ IS THE PRIMARY SOURCE, AND IT MUST BE LINE-EXACT. `extra.lines` is blanked so
  // only the reader can answer, and the reader returns a first-party ref at the finding's line and
  // a third-party one everywhere else. A `recoverRef` that lost its disk branch stops suppressing;
  // one that reads a neighbouring line judges the WRONG step — and in a steps: list the neighbour
  // is very often another `uses:`, so a ±1 slip silently drops a genuine supply-chain finding
  // rather than merely reporting a spurious one. Neither shows up in the assertions above, which
  // all hand the same text to both the reader and `extra.lines`.
  const atLine = (n) => (_file, line) => (line === n ? '      - uses: mvalasis/ci-actions/linkcheck@v1' : '      - uses: gradle/actions/setup-gradle@v4');
  const bare = { path: '.github/workflows/x.yml', start: { line: 7 }, extra: { metadata: { checkId: 'gha-unpinned-action' }, lines: '' } };
  check('the disk read is the PRIMARY source (extra.lines empty, still suppressed)', filterFirstPartyGha([bare], owners, atLine(7)).length === 0);
  check('the disk read is LINE-EXACT (a ±1 slip stops suppressing, never mis-suppresses)',
    filterFirstPartyGha([bare], owners, atLine(8)).length === 1 && filterFirstPartyGha([bare], owners, atLine(6)).length === 1);
  check('refFromText reads a quoted, dashed uses: line', refFromText("  - uses: 'a/b/c@v1'  # note") === 'a/b/c@v1');
  check('refFromText refuses prose (no accidental suppression)', refFromText('this line mentions uses of things') === '');
}

console.log('\n# readLineFromDisk — the 1-indexed line lookup the post-filter actually ships with');
{
  // semgrep reports 1-indexed lines; a JS array is 0-indexed; that single `- 1` decides WHICH step
  // gets judged. Every assertion above injects its own reader, so the shipped default reader was
  // the one piece of new code with no coverage at all — an off-by-one there passes the whole suite.
  // Asserted against a real file because the indexing IS the filesystem contract.
  const tmp = path.join(os.tmpdir(), `sb-firstparty-selftest-${process.pid}.yml`);
  fs.writeFileSync(tmp, '      - uses: mvalasis/ci-actions/linkcheck@v1\n      - uses: gradle/actions/setup-gradle@v4\n');
  try {
    check('readLineFromDisk(f, 1) is the FIRST line, not the second', readLineFromDisk(tmp, 1).includes('mvalasis/ci-actions/linkcheck@v1'));
    check('readLineFromDisk(f, 2) is the second line', readLineFromDisk(tmp, 2).includes('gradle/actions/setup-gradle@v4'));
    // Past EOF must be '' and not undefined: refFromText would still cope, but '' is what makes
    // "unrecoverable → keep the finding" the outcome instead of a throw inside the filter.
    check('readLineFromDisk past EOF is "" (unrecoverable → reported, never a crash)', readLineFromDisk(tmp, 99) === '');
  } finally { try { fs.unlinkSync(tmp); } catch { /* best effort — a leftover tmp file fails nothing */ } }
}

console.log('\n# rules/gha.yaml — the three-segment `uses:` regex, proven without semgrep');
{
  // CI runs the real `semgrep --test` against rules/selftest/gha.yml, but semgrep is a Python
  // install that most dev machines lack, so the regex — the actual defect surface — would only be
  // exercised post-push. Read the LIVE regex out of the rule file and apply it here. The constructs
  // used (anchor, negative lookahead, class, {40}, \b, non-capturing group) are identical in JS
  // RegExp and Python `re`, and both were cross-checked by hand when this landed.
  const yaml = fs.readFileSync(new URL('../rules/gha.yaml', import.meta.url), 'utf8');
  const blk = yaml.split(/^\s*-\s+id:\s*/m).slice(1).find((b) => b.startsWith('gha-unpinned-third-party-action')) || '';
  const m = blk.match(/regex:\s*'((?:[^']|'')*)'/);
  check('the unpinned rule still declares a metavariable-regex', !!m);
  // The post-filter matches on this exact string; a rename here silently disables suppression
  // (→ 55 refs of noise) and a tier change could make it BLOCK. Pin both to the rule file.
  check('rule still emits checkId gha-unpinned-action', /checkId:\s*gha-unpinned-action\b/.test(blk));
  check('rule is still tier T1 (WARN — can never newly-block)', /tier:\s*T1\b/.test(blk));
  const re = new RegExp((m ? m[1] : 'x^').replace(/''/g, "'"));
  const SHA = '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d';
  const cases = [
    ['webfactory/ssh-agent@v0.10.0', true, 'two-segment mutable tag (the case that always worked)'],
    ['gradle/actions/setup-gradle@v4', true, 'THREE-segment third party — the false NEGATIVE this fixes'],
    ['mvalasis/ci-actions/linkcheck@v1', true, 'three-segment first party fires here; suppressed downstream'],
    [`cloudflare/wrangler-action@${SHA}`, false, 'two-segment SHA pin'],
    [`some-org/some-actions/setup@${SHA}`, false, 'THREE-segment SHA pin must stay silent'],
    ['actions/checkout@v4', false, 'actions/* exempt'],
    ['github/codeql-action/analyze@v3', false, 'three-segment github/* exempt'],
    ['./security-baseline', false, 'local ./ ref'],
    ['docker://alpine:3', false, 'docker ref'],
  ];
  for (const [ref, want, why] of cases) check(`${want ? 'flags' : 'ignores'} ${ref} — ${why}`, re.test(ref) === want);
}

console.log('\n# the OWNERSHIP WIRING — scan.mjs + action.yml, not just the pure module');
{
  // Everything above tests firstparty.mjs in isolation, and firstparty.mjs can be perfect while the
  // CLI feeds it only the CALLER's owner — which IS the 2026-08 bug, restored, with the entire
  // suite green. scan.mjs runs a top-level IIFE so it cannot be imported for a behavioural test;
  // assert the wiring against its SOURCE instead, the same way the block above reads the live regex
  // out of rules/gha.yaml rather than trusting a copy of it.
  const scan = fs.readFileSync(new URL('./scan.mjs', import.meta.url), 'utf8');
  const call = (scan.match(/firstPartyOwners\(\{[\s\S]*?\}\)/) || [''])[0];
  check('scan.mjs feeds the CALLER owner into the set', /repository:\s*env\.GITHUB_REPOSITORY\b/.test(call));
  check('scan.mjs feeds the ACTION owner into the set (clause (b) — the split fix)', /actionRepository:\s*env\.ACTION_REPOSITORY\b/.test(call));
  check('scan.mjs falls back to the runner\'s ambient GITHUB_ACTION_REPOSITORY', /actionRepository:[^,]*\|\|\s*env\.GITHUB_ACTION_REPOSITORY\b/.test(call));
  check('scan.mjs feeds the first-party-owners input into the set', /extra:\s*env\.FIRST_PARTY_OWNERS\b/.test(call));
  check('scan.mjs routes the gha results THROUGH the post-filter', /filterFirstPartyGha\(\s*gha\.results/.test(scan));
  // …and the env the CLI reads has to actually arrive. action.yml passes these explicitly rather
  // than leaning on the runner's ambient defaults, so a dropped line here is a silent revert to
  // caller-owner-only on every caller, with nothing red anywhere.
  const act = fs.readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
  for (const key of ['GITHUB_REPOSITORY', 'ACTION_REPOSITORY', 'FIRST_PARTY_OWNERS']) {
    check(`action.yml wires ${key} into the Scan step`, new RegExp(`^\\s+${key}:\\s*\\$\\{\\{`, 'm').test(act));
  }
  // The fallback above is only a fallback if action.yml leaves the ambient copy alone. Writing
  // `GITHUB_ACTION_REPOSITORY: ${{ … }}` here would overwrite the runner's value with the context's
  // — and if the context is empty inside a composite action's own step (undocumented either way),
  // that shadow silently restores the pre-split behaviour with two green sources of truth.
  check('action.yml does NOT shadow the ambient GITHUB_ACTION_REPOSITORY', !/^\s+GITHUB_ACTION_REPOSITORY:/m.test(act));
  check('action.yml declares the first-party-owners input', /^\s{2}first-party-owners:/m.test(act));
}

console.log('\n# workflow-command encoding + annotations (pure)');
{
  check('escapeData encodes % CR LF', escapeData('a%b\r\nc') === 'a%25b%0D%0Ac');
  check('escapeProperty also encodes : and ,', escapeProperty('a:b,c%') === 'a%3Ab%2Cc%25');
  const f = { checkId: 'secret-pattern', rule: 'generic-api-key', file: 'app/config.php', line: 3, msg: 'generic-api-key (abcd…wxyz)', sev: SEV.CRIT };
  const want = '::error file=app/config.php,line=3,title=security-baseline secret-pattern::secret-pattern generic-api-key at app/config.php:3';
  check('annotation = file, line, title + `<checkId> <rule> at <file>:<line>`', annotation(f) === want, annotation(f));
  check('annotation never carries msg (a secret is named by rule id, never by value)', !annotation(f).includes('abcd') && !annotation(f).includes('wxyz'));
  check('annotation level is the caller\'s', annotation(f, 'warning').startsWith('::warning file='));
  const hist = annotation({ ...f, checkId: 'secrets-history', file: '(history)', line: 0 });
  check("'(history)' is not a path: no file=/line=, no location", hist === '::error title=security-baseline secrets-history::secrets-history generic-api-key', hist);
  check('line 0 drops line= but keeps file=', annotation({ ...f, line: 0 }) === '::error file=app/config.php,title=security-baseline secret-pattern::secret-pattern generic-api-key at app/config.php');
  // A HOSTILE path must stay one command with exactly the three properties we set. Unescaped, the `,`
  // would add `line=1` and the newline would start a second command that stops command processing.
  const evil = annotation({ ...f, file: 'x.php,line=1::forged\n::stop-commands::tok' });
  const props = (evil.match(/^::error (.*?)::/) || [])[1] || '';
  check('a hostile path stays ONE line', !/[\r\n]/.test(evil));
  check('a hostile path cannot add or rewrite a property', props.split(',').map((p) => p.split('=')[0]).join(',') === 'file,line,title', props);
  check('a hostile path is carried escaped, not dropped', props.startsWith('file=x.php%2Cline=1%3A%3Aforged%0A%3A%3Astop-commands%3A%3Atok,line=3,'), props);
  const many = Array.from({ length: 12 }, (_, i) => ({ ...f, line: i + 1 }));
  const warnOnly = { ...f, checkId: 'sca-high', rule: 'GHSA-x', sev: SEV.WARN };
  const out = annotations([...many, warnOnly]);
  check('annotations: 10 CRITICALs (GitHub\'s per-step cap) + one overflow line', out.length === 11 && out.slice(0, 10).every((l) => l.startsWith('::error ')) && /^security-baseline: 2 more critical/.test(out[10]), `got ${out.length}`);
  check('annotations: a WARN finding is never annotated', !out.some((l) => l.includes('sca-high')) && annotations([warnOnly]).length === 0);
}

console.log('\n# scan.mjs end to end — the job log carries the report; secret values reach neither output');
{
  // scan.mjs runs a top-level IIFE, so it is exercised as a PROCESS: stub scanners on disk, a
  // two-commit git repo, the real CLI. Nothing needs semgrep/gitleaks/trufflehog installed, and no
  // real scanner can run (every *_BIN points at a stub), so nothing leaves the machine.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-e2e-'));
  try {
    // Planted values are minted at run time: a secret-shaped literal in this file would trip the
    // very scan it tests (luxairportlu 739c623 was blocked by exactly such a canary constant).
    const mint = (tag) => `${tag}${crypto.randomBytes(15).toString('hex').toUpperCase()}`;
    const planted = { diff: mint('GLDIFF'), hist: mint('GLHIST'), live: mint('THLIVE') };
    // A leak is any 8-char run of a planted value: redact() keeps first4…last4 around an ellipsis, so
    // no 8 contiguous characters of a value can reach an output through it.
    const leaked = (text) => Object.values(planted).some((v) => {
      for (let i = 0; i + 8 <= v.length; i++) if (text.includes(v.slice(i, i + 8))) return true;
      return false;
    });

    const bin = path.join(tmp, 'bin');
    fs.mkdirSync(bin);
    const stub = (name, body) => {
      const p = path.join(bin, name);
      fs.writeFileSync(p, `#!/bin/sh\n[ "$1" = "--version" ] && { echo 0.0.0-stub; exit 0; }\n${body}\n`);
      fs.chmodSync(p, 0o755);
      return p;
    };
    const argvLog = path.join(tmp, 'gitleaks-argv.log');
    // Worst case: a gitleaks that IGNORED --redact, so Secret/Match/Line carry the raw value; the
    // diff range (--log-opts) and the full-history pass answer with different findings.
    const glFinding = (file, line, rule, value) => ({
      RuleID: rule, Description: 'stub', File: file, StartLine: line, EndLine: line,
      Secret: value, Match: `key = "${value}"`, Line: `$key = '${value}';`, Commit: '0'.repeat(40),
    });
    // Vendored rules arrive with semgrep's config-path prefix on check_id, as they do on a runner.
    const vendored = (id) => `home.runner.work._actions.mvalasis.ci-actions.v1.security-baseline.rules.${id}`;
    const stubs = {
      SEMGREP_BIN: stub('semgrep', [
        'case "$*" in',
        `  *--severity*) cat <<'JSON'\n${JSON.stringify({ results: [{ check_id: 'php.lang.security.stub-rule', path: 'app/login.php', start: { line: 7 }, extra: { message: 'stub finding', metadata: { cwe: ['CWE-89'] } } }] })}\nJSON`,
        '  ;;',
        `  *wp-php.yaml*) cat <<'JSON'\n${JSON.stringify({ results: [
          { check_id: vendored('wp-rest-exception-detail'), path: 'app/login.php', start: { line: 12 }, extra: { message: 'exception detail in a REST body', metadata: { checkId: 'wp-rest-error-detail', cwe: ['CWE-209'] } } },
          { check_id: vendored('wp-nonce-missing'), path: 'app/login.php', start: { line: 20 }, extra: { message: 'no nonce check', metadata: { checkId: 'wp-nonce-missing' } } },
        ] })}\nJSON`,
        '  ;;',
        `  *) echo '{"results":[]}' ;;`,
        'esac',
      ].join('\n')),
      GITLEAKS_BIN: stub('gitleaks', [
        `printf '%s\\n' "$*" >> '${argvLog}'`,
        'case "$*" in *--log-opts*) which=diff ;; *) which=hist ;; esac',
        'out=""',
        'while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && { shift; out="$1"; }; shift; done',
        `if [ "$which" = diff ]; then cat > "$out" <<'JSON'\n${JSON.stringify([glFinding('app/config.php', 3, 'generic-api-key', planted.diff)])}\nJSON`,
        `else cat > "$out" <<'JSON'\n${JSON.stringify([glFinding('old/legacy.php', 9, 'aws-access-token', planted.hist)])}\nJSON`,
        'fi',
      ].join('\n')),
      // trufflehog's JSON always carries the raw credential (Raw/RawV2) — it has no --redact.
      TRUFFLEHOG_BIN: stub('trufflehog', `cat <<'JSON'\n${JSON.stringify({ SourceMetadata: { Data: { Git: { file: 'app/config.php', line: 3 } } }, DetectorName: 'Github', Verified: true, Raw: planted.live, RawV2: planted.live, Redacted: planted.live })}\nJSON`),
      OSV_BIN: stub('osv-scanner', `echo '{"results":[]}'`),
      HADOLINT_BIN: stub('hadolint', 'echo "[]"'),
    };

    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    const base = { PATH: process.env.PATH, HOME: tmp, TMPDIR: tmp, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
    const git = (...a) => spawnSync('git', ['-c', 'user.name=selftest', '-c', 'user.email=selftest@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd: repo, env: base, encoding: 'utf8' });
    const put = (rel, text) => { fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true }); fs.writeFileSync(path.join(repo, rel), text); };
    git('init', '-q');
    put('README.md', 'base\n');
    git('add', '.'); git('commit', '-q', '-m', 'base');
    put('app/config.php', '<?php // fixture\n');
    put('app/login.php', '<?php // fixture\n');
    git('add', '.'); git('commit', '-q', '-m', 'change');
    check('fixture repo has two commits (else every assertion below is vacuous)', (git('rev-list', '--count', 'HEAD').stdout || '').trim() === '2');

    const summaryPath = path.join(tmp, 'summary.md');
    const scan = (extra) => {
      try { fs.rmSync(summaryPath, { force: true }); } catch { /* fresh file per run */ }
      const r = spawnSync(process.execPath, [fileURLToPath(new URL('./scan.mjs', import.meta.url))], {
        cwd: repo, encoding: 'utf8', timeout: 60000,
        env: {
          ...base, ...stubs, GITHUB_ACTION_PATH: fileURLToPath(new URL('..', import.meta.url)),
          SCAN_SCOPE: 'diff', BASE_REF: 'HEAD~1', VERIFIED_SECRETS: 'on', ENABLE_SECRETS_HISTORY: 'true', ENABLE_SCA: 'false',
          ...extra,
        },
      });
      const summary = fs.existsSync(summaryPath) ? fs.readFileSync(summaryPath, 'utf8') : '';
      return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', summary };
    };
    const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l));
    const expected = (level, promoted = false) => [
      `::${level} file=app/login.php,line=7,title=security-baseline sast-critical::sast-critical php.lang.security.stub-rule at app/login.php:7`,
      ...(promoted ? [`::${level} file=app/login.php,line=12,title=security-baseline wp-rest-error-detail::wp-rest-error-detail wp-rest-exception-detail at app/login.php:12`] : []),
      `::${level} file=app/config.php,line=3,title=security-baseline secret-pattern::secret-pattern generic-api-key at app/config.php:3`,
      `::${level} file=app/config.php,line=3,title=security-baseline secret-verified::secret-verified Github at app/config.php:3`,
    ];

    // (A) On Actions, lux-shaped (one T1 promoted): summary + job log + annotations.
    const a = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', CRITICAL_CHECKS: 'wp-rest-error-detail' });
    check('Actions run: three T0 + one promoted T1 BLOCK (exit 1)', a.status === 1, `exit ${a.status}`);
    check('the step summary is the report, verdict included', a.summary.startsWith('## 🔒 security-baseline') && a.summary.includes('\nBLOCKED — 4 critical finding(s).'));
    check('the job log carries the WHOLE report, byte for byte', a.summary.length > 0 && a.stdout.includes(a.summary));
    check('the report reaches the log once, not twice', a.stdout.split('## 🔒 security-baseline').length === 2);
    check('the fixtures reached the report (rule + file:line of each secret finding)',
      /app\/config\.php:3 — generic-api-key/.test(a.stdout) && /old\/legacy\.php:9 — aws-access-token/.test(a.stdout) && /app\/config\.php:3 — 🔴 VERIFIED-LIVE Github/.test(a.stdout));
    check('one ::error per CRITICAL (the promoted T1 by its bare rule id), none for a WARN, nothing else command-shaped',
      JSON.stringify(commands(a.stdout)) === JSON.stringify(expected('error', true)), JSON.stringify(commands(a.stdout)));
    check('annotations stay out of the step summary', commands(a.summary).length === 0);
    check('NO planted secret value in the job log, the step summary or stderr', !leaked(a.stdout) && !leaked(a.summary) && !leaked(a.stderr));
    const argv = fs.existsSync(argvLog) ? fs.readFileSync(argvLog, 'utf8').trim().split('\n') : [];
    check('gitleaks ran twice (diff + history), both times with --redact', argv.length === 2 && argv.every((l) => /(^| )--redact( |$)/.test(l)), `${argv.length} call(s)`);

    // (B) Off Actions (a local run): stdout is the only output — the report prints once, with no
    // commands. spawnSync hands the child a SOCKET as stdout, which is the case that caught the old
    // `appendFileSync('/dev/stdout')` fallback: on Linux that open fails with ENXIO, the scan crashed
    // with nothing printed, and its exit 1 still matched the verdict. macOS dups the fd and passed.
    const once = (r) => r.stdout.split('## 🔒 security-baseline').length === 2 && r.stdout.includes('\nBLOCKED — 3 critical finding(s).') && !r.stdout.includes('crashed');
    const why = (r) => `exit ${r.status}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
    for (const [label, extra] of [['local run', {}], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', { GITHUB_STEP_SUMMARY: '/dev/stdout' }]]) {
      const b = scan(extra);
      check(`${label}: the report prints exactly once, verdict included, no crash`, b.status === 1 && once(b), why(b));
      check(`${label}: no workflow commands`, b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
      check(`${label}: NO planted secret value`, b.stdout.length > 0 && !leaked(b.stdout) && !leaked(b.stderr), why(b));
    }

    // (C) report-mode: the same criticals annotate as ::warning, and nothing blocks.
    const c = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', REPORT_MODE: 'true' });
    check('report-mode: exit 0', c.status === 0, `exit ${c.status}`);
    check('report-mode: the criticals annotate as ::warning, never ::error', JSON.stringify(commands(c.stdout)) === JSON.stringify(expected('warning')), JSON.stringify(commands(c.stdout)));
    check('report-mode: the log still carries the whole report', c.summary.length > 0 && c.stdout.includes(c.summary));

    // (D) The summary sink itself fails: the report is already in the log (it is echoed first), the
    // fault is named there, and the exit is the caller's setting — our fault never blocks report-mode.
    const sinkDir = path.join(tmp, 'summary-is-a-dir');
    fs.mkdirSync(sinkDir);
    const d = scan({ GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true', REPORT_MODE: 'true' });
    check('unwritable summary: the report still reaches the job log', d.stdout.includes('## 🔒 security-baseline') && d.stdout.includes('⚠️ REPORT-MODE — 3 critical finding(s) would BLOCK'));
    check('unwritable summary: the fault is named in the log', /security-baseline crashed: .*EISDIR/.test(d.stdout));
    check('unwritable summary: the crash re-flush echoes only the new line, not the report again', d.stdout.split('## 🔒 security-baseline').length === 2);
    check('unwritable summary under report-mode: exit 0, not an unhandled throw', d.status === 0, `exit ${d.status}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(failed === 0 ? '\n✅ all engine self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
