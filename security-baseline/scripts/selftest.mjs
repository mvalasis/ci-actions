// Offline self-test for the security-baseline tier engine. No network, no real scanners — feeds
// canned findings to the pure engine and asserts the tiering / promotion / block decision and
// the redaction disclosure guard, and canned scanner PROCESSES to outcome.mjs to assert that one
// which could not look never reads as one that found nothing; then runs the real scan.mjs against
// stub scanners to assert what reaches the job log and the exit code. Run: node scripts/selftest.mjs
// (also runs in CI). Exits non-zero on any regression — the gate's own regression guard, mirroring
// seo-aeo/selftest.mjs.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SEV, CHECKS, T0_CHECKS, T1_CHECKS, T2_CHECKS, RESERVED_CHECKS, evaluate, parsePromote,
  isPromotable, baseSev, safe, redact, escapeData, escapeProperty, annotation, annotations,
  canBeCritical, faultAnnotation, shortSha,
} from './tiers.mjs';
import { LEGS, semgrepOutcome, gitleaksOutcome, trufflehogOutcome, osvOutcome, hadolintOutcome, gitLogOutcome, scrub, errorLine } from './outcome.mjs';
import { firstPartyOwners, ownerOf, parseOwners, refFromText, readLineFromDisk, filterFirstPartyGha } from './firstparty.mjs';
import { findArgvSecrets, argvLang, argvTargets, argvFinding } from './argv-secret.mjs';

// The checkIds a scanner adapter in scan.mjs actually emits (kept in sync by the coverage
// assertion below — a new CHECKS id must be either wired here or explicitly RESERVED).
const EMITTED = new Set([
  'sast-critical', 'secret-pattern', 'secret-verified', 'secrets-history',
  'sca-critical', 'sca-high', 'sca-moderate', 'sca-low',
  'wp-nonce-missing', 'wp-cap-missing', 'wp-sql-unprepared', 'wp-unserialize', 'wp-file-include',
  'wp-rest-error-detail', 'wp-rest-error-detail-laundered', 'wp-weak-crypto', 'turnstile-test-key', 'wp-unescaped-output', 'wp-rest-wp-error-detail',
  'ts-dangerous-html', 'ts-eval', 'ts-child-process', 'ts-public-secret-leak', 'ts-ssrf',
  'ts-open-redirect', 'ts-secret-in-log', 'rn-insecure-storage', 'rn-cleartext-http', 'ts-cors-wildcard',
  'gha-unpinned-action', 'gha-script-injection', 'gha-pr-target', 'dockerfile-lint', 'argv-secret',
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

console.log('\n# outcome.mjs — a scanner that could not look never reads as one that found nothing');
{
  // Canned PROCESSES, shaped like scan.mjs's run() result. Values that could look like a credential
  // are minted per run, never spelled here: this file is itself scanned by the gate.
  const R = (o) => ({ missing: false, status: 0, signal: '', error: '', stdout: '', stderr: '', ...o });
  const minted = (tag) => `${tag}${crypto.randomBytes(15).toString('hex')}`;
  const hit = { check_id: 'php.lang.x', path: 'a.php', start: { line: 1 } };
  const sg = (status, body, extra = {}) => semgrepOutcome(R({ status, stdout: typeof body === 'string' ? body : JSON.stringify(body), ...extra }));

  check('semgrep exit 0 with results: looked, every result kept', sg(0, { results: [hit], errors: [] }).looked === true && sg(0, { results: [hit], errors: [] }).results.length === 1);
  check('semgrep exit 0 with nothing found: looked (found nothing is not could-not-look)', sg(0, { results: [], errors: [] }).looked === true);
  // The shapes below are semgrep 1.178.0's own, measured: a registry config that will not download
  // exits 7 with two error entries; no network at all exits 2 with no JSON and a traceback.
  const registry = { results: [], errors: [
    { code: 2, level: 'error', type: 'SemgrepError', message: 'Failed to download configuration from https://semgrep.dev/c/p/security-audit HTTP 503.' },
    { code: 7, level: 'error', type: 'SemgrepError', message: 'invalid configuration file found (1 configs were invalid)' },
  ] };
  const down = sg(7, registry);
  check('semgrep exit 7 (a registry config that did not download): could not look; the reason names the exit and the FIRST error',
    down.looked === false && down.reason === 'exit 7: SemgrepError — Failed to download configuration from https[:]//semgrep.dev/c/p/security-audit HTTP 503.', down.reason);
  const offline = sg(2, '', { stderr: [
    '/venv/lib/python3.12/site-packages/urllib3/__init__.py:35: NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+',
    '  warnings.warn(',
    'Traceback (most recent call last):',
    '  File "/venv/lib/python3.12/site-packages/requests/adapters.py", line 723, in send',
    "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='semgrep.dev', port=443): Max retries exceeded with url: /c/p/security-audit",
    '',
  ].join('\n') });
  check('semgrep with no network (exit 2, no JSON): could not look; the reason is the exception, not a warning',
    offline.looked === false && offline.reason.startsWith('exit 2: requests.exceptions.ConnectionError: HTTPSConnectionPool'), offline.reason);
  check('semgrep exit 7 on a rule schema it rejects (no message on the entry): could not look',
    sg(7, { results: [], errors: [{ code: 4, level: 'error', type: 'InvalidRuleSchemaError', message: null }, registry.errors[1]] }).reason === 'exit 7: InvalidRuleSchemaError');
  const ruleErr = sg(0, { results: [hit], errors: [{ code: 4, level: 'error', type: 'Rule parse error', message: 'Invalid pattern', rule_id: 'r' }] });
  check('semgrep exit 0 with a level "error" entry (a rule that did not load): could not look, results kept',
    ruleErr.looked === false && ruleErr.reason === 'exit 0 with 1 error — Rule parse error — Invalid pattern' && ruleErr.results.length === 1, ruleErr.reason);
  const partial = sg(0, { results: [hit], errors: [{ code: 3, level: 'warn', type: ['PartialParsing', [{ path: 'b.php' }]], path: 'b.php', message: 'Syntax error' }] });
  check('semgrep exit 0 with a per-file "warn" (a file it could not fully parse): looked, that file listed',
    partial.looked === true && partial.skipped.join() === 'b.php' && partial.results.length === 1, JSON.stringify(partial));
  check('semgrep: a traceback on stdout is could-not-look, not []', sg(1, 'Traceback (most recent call last):').looked === false);
  check('semgrep: exit 0 with no stdout is could-not-look (no report is not an empty report)', sg(0, '').looked === false);
  check('semgrep: JSON without a results array is could-not-look', sg(0, { errors: [] }).looked === false);
  check('semgrep exit 1 WITH results and no error entry: looked (the --error findings exit)', sg(1, { results: [hit], errors: [] }).looked === true);
  check('semgrep exit 1 with NO results: could not look (a findings exit without findings)', sg(1, { results: [], errors: [] }).looked === false);
  const died = sg(2, { results: [hit], errors: [{ level: 'error', type: 'Fatal error', message: 'x' }] });
  check('semgrep exit 2 keeps the findings it did report (a half-failed scan un-finds nothing)', died.looked === false && died.results.length === 1);
  check('a scanner that is not installed: could not look', semgrepOutcome(R({ missing: true, status: 127 })).reason === 'not installed');
  check('a timeout: could not look, even behind a complete-looking report', semgrepOutcome(R({ status: 1, error: 'ETIMEDOUT', signal: 'SIGTERM', stdout: '{"results":[]}' })).reason === 'timed out');
  check('the 64 MB output cap: could not look', semgrepOutcome(R({ status: 1, error: 'ENOBUFS', signal: 'SIGTERM', stdout: '{"results":[' })).reason === 'output over the 64 MB buffer');
  check('killed by a signal: could not look', semgrepOutcome(R({ status: 1, signal: 'SIGKILL', stdout: '{"results":[]}' })).reason === 'killed by SIGKILL');
  check('a run of 10 s or more says how long it took (a registry stall leaves no other trace)',
    semgrepOutcome(R({ status: 2, ms: 98400 })).reason === 'exit 2 after 98 s: no JSON report' && semgrepOutcome(R({ status: 2, ms: 9000 })).reason === 'exit 2: no JSON report'
    && semgrepOutcome(R({ status: 1, error: 'ETIMEDOUT', signal: 'SIGTERM', ms: 420003 })).reason === 'timed out after 420 s');

  const gl = (status, report, stderr = '') => gitleaksOutcome(R({ status, stderr }), report);
  check('gitleaks exit 0, report []: looked, nothing found', gl(0, '[]\n').looked === true && gl(0, '[]\n').results.length === 0);
  check('gitleaks exit 0, report null: looked, nothing found', gl(0, 'null\n').looked === true && gl(0, 'null\n').results.length === 0);
  check('gitleaks exit 0 with a finding: looked', gl(0, '[{"RuleID":"x"}]').results.length === 1);
  const glDied = gl(1, null, "noise\n10:00AM FTL failed to scan Git repository error=\"fatal: bad revision 'a..HEAD'\"");
  check('gitleaks exit 1 with no report: could not look; the reason names the exit and its error', glDied.looked === false && /^exit 1: 10:00AM FTL failed to scan Git repository.*bad revision/.test(glDied.reason), glDied.reason);
  check('gitleaks exit 1 WITH a report on disk: could not look (the run failed, whatever the file says)', gl(1, '[]').looked === false);
  check('gitleaks exit 0 that wrote no report: could not look', gl(0, null).looked === false && gl(0, null).reason === 'exit 0 but wrote no report');
  check('gitleaks report that is empty or not an array: could not look', gl(0, '').looked === false && gl(0, '{"a":1}').looked === false);

  const th = (status, stdout, stderr = '') => trufflehogOutcome(R({ status, stdout, stderr }));
  check('trufflehog exit 0 with JSON lines: looked, all kept', th(0, '{"Verified":true}\n{"Verified":false}\n').results.length === 2 && th(0, '').looked === true);
  const logged = minted('THLOG');
  const thDied = th(1, '', `error running scan: ${logged}`);
  check('trufflehog exit 1: could not look, and its stderr is never quoted (not even redacted)',
    thDied.looked === false && thDied.reason.startsWith('exit 1 — ') && !thDied.reason.includes(logged.slice(0, 8)) && !thDied.reason.includes(redact(logged)), thDied.reason);
  check('trufflehog: a JSON line cut short is could-not-look', th(0, '{"Verified":true}\n{"Verif').looked === false);
  check('trufflehog: a stdout line that is not JSON is skipped, not a fault', th(0, 'banner\n{"Verified":true}\n').looked === true);

  const osv = (status, stdout, stderr = '') => osvOutcome(R({ status, stdout, stderr }));
  check('osv-scanner exit 0 {"results":[]}: looked', osv(0, '{"results":[]}').looked === true);
  check('osv-scanner exit 1 with results: looked (vulnerabilities found is not a failure)', osv(1, '{"results":[{"packages":[]}]}').looked === true);
  check('osv-scanner exit 128 (no package manifest): looked, nothing to audit', osv(128, '', 'No package sources found').looked === true);
  // v2.4.0 exits 128 for three trees (measured): no lockfile, lockfiles holding no package, and
  // lockfiles it could not read. scan.mjs passes the tracked lockfiles and the root osv scanned.
  const at = (stderr, lockfiles) => osvOutcome(R({ status: 128, stdout: '', stderr }), { lockfiles, root: '/home/runner/work/x/x' });
  const extract = at('Scanning dir .\nError during extraction: (extracting as javascript/packagelockjson) home/runner/work/x/x/web/package-lock.json: could not extract: unexpected end of JSON input\nNo package sources found', ['web/package-lock.json']);
  check('osv-scanner exit 128 with an extraction error: could not look, osv\'s error the reason, the root cut off',
    extract.looked === false && extract.reason === 'exit 128: Error during extraction: extracting as javascript/packagelockjson web/package-lock.json: could not extract: unexpected end of JSON input', JSON.stringify(extract));
  const unread = at('No package sources found', ['bun.lockb']);
  check('osv-scanner exit 128 having read none of the tracked lockfiles (a bun.lockb): could not look, the lockfile named',
    unread.looked === false && unread.reason === "exit 128: it read none of the tree's lockfiles: bun.lockb", JSON.stringify(unread));
  const EXTRACT = 'Error during extraction: (extracting as javascript/packagelockjson) home/runner/work/x/x/web/package-lock.json: could not extract: unexpected end of JSON input';
  check('osv-scanner exit 128 with an extraction error and no lockfile listed (a failed git listing): still could not look', at(EXTRACT, []).looked === false);
  check('…and beside a lockfile it read and found empty: still could not look',
    at(`Scanned /home/runner/work/x/x/package-lock.json file and found 0 packages\n${EXTRACT}`, ['package-lock.json', 'web/package-lock.json']).looked === false);
  check('…a long lockfile list is cut to three', at('No package sources found', ['a', 'b', 'c', 'd', 'e']).reason === "exit 128: it read none of the tree's lockfiles: a, b, c and 2 more");
  check('…without a root, the path in the reason stays whole', String(osvOutcome(R({ status: 128, stdout: '', stderr: EXTRACT }), {}).reason || '').includes('home/runner/work/x/x/web/package-lock.json'));
  check('osv-scanner exit 128 with every tracked lockfile read and empty: looked, nothing to audit',
    at('Scanned /home/runner/work/x/x/package-lock.json file and found 0 packages\nNo package sources found', ['package-lock.json']).looked === true
      && at('Scanned /w/composer.lock file and found 1 package', ['composer.lock']).looked === true);
  check('osv-scanner exit 127 (a general error): could not look, reason names it', osv(127, '', 'failed to query osv.dev').reason === 'exit 127: failed to query osv.dev');
  check('osv-scanner exit 0 with unparseable output: could not look', osv(0, 'garbage').looked === false);
  check('osv-scanner exit 1 with no results: could not look', osv(1, '{"results":[]}').looked === false);
  check('osv-scanner exit 2 with a valid-looking report: could not look (the status decides, not the JSON)', osv(2, '{"results":[]}').looked === false);

  const hd = (status, stdout, stderr = '') => hadolintOutcome(R({ status, stdout, stderr }));
  check('hadolint exit 1 with a finding: looked (a rule firing is not a failure)', hd(1, '[{"code":"DL3007","level":"warning"}]').looked === true);
  check('hadolint exit 0 with []: looked', hd(0, '[]').looked === true);
  check('hadolint with no JSON (a file it could not open): could not look', hd(1, '', 'openBinaryFile: does not exist').looked === false);
  check('hadolint exit 2 with a valid-looking array: could not look', hd(2, '[]').looked === false);

  // The git log a secret scanner reads, run first (v1.20.1): git 2.54's own answers, measured on a
  // repository that lacks one of the range's blobs and on one whose blob does not inflate.
  const lg = (o) => gitLogOutcome(R(o));
  const lost = crypto.createHash('sha1').update('a blob the range lacks').digest('hex');
  check('git log that finished: read', lg({ status: 0 }).read === true && lg({ status: 0 }).reason === undefined);
  const lacks = lg({ status: 128, stderr: `fatal: unable to read ${lost}\n` });
  check("git log exit 128 on an object the repository lacks: not read, git's fatal: line the reason, the sha cut to first4…last4",
    lacks.read === false && lacks.reason === `exit 128: fatal: unable to read ${redact(lost)}`, JSON.stringify(lacks));
  const inflate = lg({ status: 128, stderr: `error: inflate: data stream error (incorrect data check)\nerror: unable to unpack ${lost} header\nfatal: unable to read ${lost}\n` });
  check('git log on a blob that does not inflate: not read, its first error line the reason',
    inflate.read === false && inflate.reason === 'exit 128: error: inflate: data stream error incorrect data check', JSON.stringify(inflate));
  check('git log killed, timed out or not found: not read, and why', lg({ status: 1, signal: 'SIGKILL' }).reason === 'killed by SIGKILL'
    && lg({ status: 1, error: 'ETIMEDOUT', signal: 'SIGTERM', ms: 300000 }).reason === 'timed out after 300 s' && lg({ missing: true, status: 127 }).reason === 'not installed');
  check('git log exit 1 with nothing on stderr: not read (only exit 0 is a finished log)', lg({ status: 1 }).read === false && lg({ status: 1 }).reason === 'exit 1');

  const tok = minted('ghp_');
  check('scrub: a letters+digits run of 20+ is cut to first4…last4', !scrub(`auth failed for ${tok}`).includes(tok.slice(0, 8)) && scrub(`auth failed for ${tok}`).includes(redact(tok)));
  check('scrub: a URL\'s userinfo is dropped', !scrub('dial postgres://admin:hunter2@db.internal/x').includes('hunter2'));
  check('scrub: a letters-only rule id stays readable', scrub('rule wp-rest-error-detail-laundered failed').includes('wp-rest-error-detail-laundered'));
  check('scrub: one line, structural characters stripped (it is safe() underneath)', !/[\n`|<>]/.test(scrub('a\n`b`|<c>')));
  check('errorLine: git\'s fatal: line, not the usage hint printed after it',
    errorLine("fatal: ambiguous argument 'x...HEAD': unknown revision\nUse '--' to separate paths from revisions, like this:\n'git <command> [<revision>...] -- [<file>...]'") === "fatal: ambiguous argument 'x...HEAD': unknown revision");
  check('errorLine: a Python warning printed last is skipped for the line before it',
    errorLine('boom: the scan failed\n/v/urllib3/__init__.py:35: NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+\n  warnings.warn(') === 'boom: the scan failed');
}

console.log('\n# which legs can take the verdict away (canBeCritical + LEGS)');
{
  check('a T0 leg can always block: semgrep community, gitleaks, trufflehog on the diff',
    canBeCritical(LEGS.community.checks) && canBeCritical(LEGS.gitleaks.checks) && canBeCritical(LEGS.trufflehog.checks));
  check('a T1 leg only warns until the caller promotes one of ITS checks',
    !canBeCritical(LEGS.custom.checks) && canBeCritical(LEGS.custom.checks, ['wp-rest-error-detail']) && !canBeCritical(LEGS.custom.checks, ['sca-critical']));
  check('osv-scanner, hadolint, argv-secret, gha: WARN until promoted', !canBeCritical(LEGS.osv.checks) && canBeCritical(LEGS.osv.checks, ['sca-critical'])
    && !canBeCritical(LEGS.hadolint.checks) && !canBeCritical(LEGS.argvSecret.checks) && canBeCritical(LEGS.argvSecret.checks, ['argv-secret']) && !canBeCritical(LEGS.gha.checks));
  check('a T2 leg can never block, not even "promoted" (the history baselines)',
    !canBeCritical(LEGS.gitleaksHistory.checks, ['secrets-history']) && !canBeCritical(LEGS.trufflehogHistory.checks, ['secrets-history']));
  check('the changed-file list can always block (it feeds sast-critical)', canBeCritical(LEGS.diff.checks));
  check('the diff-scoped secret legs claim secrets-history too: what they find in a commit the base already holds',
    LEGS.gitleaks.checks.includes('secrets-history') && LEGS.trufflehog.checks.includes('secrets-history'));
  // A checkId a leg emits but does not claim would turn that leg's failure into a silent PASS for a
  // caller who promoted it. Every rule pack's metadata.checkId, read live, must belong to its leg.
  const packIds = (f) => [...fs.readFileSync(new URL(`../rules/${f}`, import.meta.url), 'utf8').matchAll(/checkId:\s*([\w-]+)/g)].map((m) => m[1]);
  const claims = (leg, list) => list.length > 0 && list.every((id) => leg.checks.includes(id));
  check('every checkId in wp-php.yaml and astro-ts.yaml belongs to the rule-packs leg', claims(LEGS.custom, [...packIds('wp-php.yaml'), ...packIds('astro-ts.yaml')]));
  check('every checkId in gha.yaml belongs to the gha leg', claims(LEGS.gha, packIds('gha.yaml')));
  const claimed = new Set(Object.values(LEGS).flatMap((l) => l.checks));
  check('every emitted checkId belongs to a leg', [...EMITTED].every((id) => claimed.has(id)), [...EMITTED].filter((id) => !claimed.has(id)).join(','));
  check('every leg check is a real CHECKS id', [...claimed].every((id) => Object.prototype.hasOwnProperty.call(CHECKS, id)));
  check('the changed-file list claims every diff-scoped leg\'s checks',
    [LEGS.community, LEGS.custom, LEGS.hadolint, LEGS.argvSecret].every((l) => l.checks.every((id) => LEGS.diff.checks.includes(id))));

  const fa = faultAnnotation('semgrep community SAST', 'semgrep exit 2: x');
  check('faultAnnotation: one ::error, a fixed title, the leg and why', fa === '::error title=security-baseline could not look::semgrep community SAST could not look — semgrep exit 2: x', fa);
  const evil = faultAnnotation('leg', 'x\n::stop-commands::tok', 'warning');
  check('faultAnnotation: a hostile reason stays one line and cannot add a property',
    !/[\r\n]/.test(evil) && (evil.match(/^::warning (.*?)::/) || [])[1] === 'title=security-baseline could not look', evil);
  const sha = crypto.createHash('sha1').update('introducing commit').digest('hex');
  check('shortSha: a full sha → its first 7; the all-zero sha, a short one or nothing → ""',
    shortSha(sha.toUpperCase()) === sha.slice(0, 7) && shortSha('0'.repeat(40)) === '' && shortSha(sha.slice(0, 12)) === '' && shortSha(undefined) === '');
  check('an annotation names the commit a secret was found in (its line is that commit\'s line)',
    annotation({ checkId: 'secret-pattern', rule: 'generic-api-key', file: 'a.php', line: 75, commit: sha }).endsWith(`secret-pattern generic-api-key at a.php:75 in commit ${sha.slice(0, 7)}`));
}

console.log('\n# argv-secret — a secret spelled into a child\'s argv (argv-secret.mjs)');
{
  const hits = (lang, ...lines) => findArgvSecrets(lines.join('\n'), lang);
  const n = (lang, ...lines) => hits(lang, ...lines).length;
  // The shapes the fleet actually shipped, each fixed by hand before this check existed.
  check('a shell array on a line that never names curl (a11y-audit before v1.15.1)',
    n('sh', '[ -n "${VERIFY_TOKEN:-}" ] && hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")') === 1);
  check('a shell array handed to curl lines later',
    n('sh', 'CURL_HEADER_ARGS=(-H "X-Verify-Source: $VERIFY_HOMEPAGE_TOKEN")', 'curl "${CURL_HEADER_ARGS[@]}" "$u"') === 1);
  check('a ${VAR:+-H "Name: $VAR"} expansion on a continued curl line',
    n('sh', 'code=$(curl -sL ${VERIFY_HOMEPAGE_TOKEN:+-H "X-Verify-Source: $VERIFY_HOMEPAGE_TOKEN"} \\', '  -o /dev/null "$url")') === 1);
  check('a Python argv list with an f-string (linkcheck before v1.15.2)',
    n('py', '    return ["-H", f"X-Verify-Source: {TOKEN}"] if (TOKEN and is_internal(url)) else []') === 1);
  check('a Python list exploded one element per line',
    n('py', 'cmd = [', '    "curl",', '    "-H",', '    f"X-Verify-Source: {TOKEN}",', '    url,', ']') === 1);
  check('a workflow run: step expanding ${{ secrets.* }} inside the header',
    n('yaml', '        run: |', '          curl -s -X POST "https://api.example.invalid/purge" \\', '            -H "Authorization: Bearer ${{ secrets.DEPLOY_API_KEY }}" \\', '            -H "Content-Type: application/json"') === 1);
  check('a workflow --header with a shell variable',
    n('yaml', '          curl -sS \\', '            --header "X-Verify-Source: ${VERIFY_HOMEPAGE_TOKEN}" \\', '            "$u"') === 1);
  check('a JS spawn with a template literal',
    n('js', "spawnSync('curl', ['-H', `X-Verify-Source: ${process.env.VERIFY_TOKEN}`, url]);") === 1);
  check('a "Name: " + VAR concatenation',
    n('py', 'cmd += ["-H", "X-Verify-Source: " + TOKEN]') === 1);
  const h = hits('yaml', 'steps:', '  - run: |', '      curl -H "Authorization: Bearer ${{ secrets.DEPLOY_API_KEY }}" "$u"');
  check('a hit names the header and the VARIABLE (never a value) at the line the value sits on',
    h.length === 1 && h[0].flag === '-H' && h[0].header === 'Authorization' && h[0].secret === 'secrets.DEPLOY_API_KEY' && h[0].line === 3, JSON.stringify(h));
  // What must NOT fire.
  check('NOT the fix: -H "@file" from a mode-600 file',
    n('sh', 'hdr=(-H "@$workdir/token-header")') === 0 && n('py', 'cmd += ["-H", "@" + _token_header()]') === 0);
  check('NOT a header whose value expands no secret-named variable',
    n('sh', 'curl -H "Content-Type: application/json" -H "X-Request-Id: $REQ_ID" "$u"') === 0);
  check('NOT ssh-keyscan -H (a flag with no Name: value after it)',
    n('yaml', '          ssh-keyscan -p ${{ steps.env.outputs.port }} -H ${{ secrets.SSH_HOST }} >> ~/.ssh/known_hosts') === 0);
  check('NOT a whole-line # comment, in shell, Python or YAML',
    n('sh', '# never `-H "X-Verify-Source: $VERIFY_TOKEN"`') === 0
    && n('py', '    # never -H "X-Verify-Source: {TOKEN}"') === 0
    && n('yaml', '      # -H "Authorization: Bearer ${{ secrets.DEPLOY_API_KEY }}"') === 0);
  check('NOT a // comment in JavaScript', n('js', "run(); // not ['-H', `X-Verify-Source: ${token}`]") === 0);
  check('a pragma with a reason, on the line above, waives it',
    n('sh', '# lint-allow-argv-secret: a cache key, not a credential', 'curl -H "X-Cache-Key: $CACHE_KEY" "$u"') === 0);
  check('a bare pragma (no reason) does not',
    n('sh', '# lint-allow-argv-secret:', 'curl -H "X-Cache-Key: $CACHE_KEY" "$u"') === 1);

  // Which files the fleet check grades.
  const L = argvLang;
  check('languages: .sh/.bash → sh, .py → py, .mjs/.js/.ts → js',
    L('scripts/a.sh') === 'sh' && L('scripts/a.bash') === 'sh' && L('tools/a.py') === 'py'
    && L('scripts/a.mjs') === 'js' && L('scripts/a.js') === 'js' && L('scripts/a.ts') === 'js');
  check('an extensionless file, by its shebang',
    L('bin/tool', '#!/usr/bin/env bash') === 'sh' && L('bin/tool', '#!/usr/bin/env python3') === 'py'
    && L('bin/tool', '#!/usr/bin/env node') === 'js' && L('bin/tool', 'plain text') === null);
  check('.github YAML and a composite action.yml → yaml; other YAML is not graded',
    L('.github/workflows/deploy.yml') === 'yaml' && L('.github/actions/x/action.yaml') === 'yaml'
    && L('my-action/action.yml') === 'yaml' && L('config/app.yml') === null);
  check('not graded: prose, UI components, vendored or minified code',
    [L('README.md'), L('src/Page.tsx'), L('src/Page.astro'), L('vendor/lib/x.sh'), L('node_modules/p/x.js'), L('wp-includes/x.js'), L('public/app.min.js')].every((v) => v === null));
  check('not graded: selftest and fixture corpora, which must spell the banned form',
    [L('a/scripts/selftest.mjs'), L('a/scripts/selftest-rules.sh'), L('.github/scripts/x.selftest.mjs'), L('rules/selftest/gha.yml'), L('tests/fixtures/x.sh')].every((v) => v === null));
  const tracked = ['scripts/changed.sh', 'scripts/untouched.sh', '.github/workflows/deploy.yml', 'README.md'];
  const files = (changed) => argvTargets({ changed, tracked }).map((t) => t.file).sort();
  check('diff scope: the changed script and every .github YAML, never an untouched script',
    JSON.stringify(files(['scripts/changed.sh', 'README.md'])) === JSON.stringify(['.github/workflows/deploy.yml', 'scripts/changed.sh']), JSON.stringify(files(['scripts/changed.sh', 'README.md'])));
  check('diff scope with nothing changed: the .github YAML is still graded',
    JSON.stringify(files([])) === JSON.stringify(['.github/workflows/deploy.yml']));
  check('full scope: every graded tracked file',
    JSON.stringify(files(null)) === JSON.stringify(['.github/workflows/deploy.yml', 'scripts/changed.sh', 'scripts/untouched.sh']));
  const asked = [];
  const t = argvTargets({ changed: ['bin/tool', 'scripts/x.sh'], tracked: [], headOf: (f) => { asked.push(f); return '#!/bin/sh'; } });
  check('only an extensionless file has its head read', t.length === 2 && JSON.stringify(asked) === '["bin/tool"]', JSON.stringify(asked));

  // What the engine receives: T1 WARN, promotable, value-free.
  const fnd = argvFinding('.github/workflows/deploy.yml', h[0]);
  check('argv-secret is T1 and promotable', CHECKS['argv-secret'] && CHECKS['argv-secret'].tier === 'T1' && isPromotable('argv-secret'));
  check('unpromoted: WARN, never blocks', evaluate([fnd]).blocked === false && evaluate([fnd]).warn === 1);
  check('promoted via critical-checks: CRITICAL, blocks', evaluate([fnd], { promote: ['argv-secret'] }).blocked === true);
  const ann = annotation({ ...fnd, sev: SEV.CRIT });
  check('its annotation names the check, header, variable, file and line',
    ann === '::error file=.github/workflows/deploy.yml,line=3,title=security-baseline argv-secret::argv-secret -H Authorization ← secrets.DEPLOY_API_KEY at .github/workflows/deploy.yml:3', ann);
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
    // Each finding names the commit that introduced it, as gitleaks' does (a full sha). The diff's is
    // the range's own commit, HEAD, read when the stub runs: whether the base holds it is asked of git
    // (v1.19.8), which knows no minted sha. The history pass's is minted here.
    const shaOf = (s) => crypto.createHash('sha1').update(s).digest('hex');
    const SHA = { diff: '', hist: shaOf('a commit long ago') };   // diff: HEAD, once the fixture repo has it
    const glFinding = (file, line, rule, value, commit) => ({
      RuleID: rule, Description: 'stub', File: file, StartLine: line, EndLine: line,
      Secret: value, Match: `key = "${value}"`, Line: `$key = '${value}';`, Commit: commit,
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
        `if [ "$which" = diff ]; then sed "s/@HEAD@/$(git rev-parse HEAD)/" > "$out" <<'JSON'\n${JSON.stringify([glFinding('app/config.php', 3, 'generic-api-key', planted.diff, '@HEAD@')])}\nJSON`,
        `else cat > "$out" <<'JSON'\n${JSON.stringify([glFinding('old/legacy.php', 9, 'aws-access-token', planted.hist, SHA.hist)])}\nJSON`,
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
    // argv-secret fixtures. The workflow and the untouched script predate the diff range: the
    // workflow must be reported anyway (.github YAML is graded on every run), the script must not.
    put('.github/workflows/deploy.yml', [
      'on: push', 'jobs:', '  purge:', '    runs-on: ubuntu-latest', '    steps:', '      - run: |',
      '          curl -s -X POST "https://api.example.invalid/purge" \\',
      '            -H "Authorization: Bearer ${{ secrets.DEPLOY_API_KEY }}"', '',
    ].join('\n'));
    put('scripts/untouched.sh', '#!/bin/sh\ncurl -H "X-Api-Key: $OLD_API_KEY" "$u"\n');
    git('add', '.'); git('commit', '-q', '-m', 'base');
    put('app/config.php', '<?php // fixture\n');
    put('app/login.php', '<?php // fixture\n');
    put('scripts/smoke.sh', '#!/bin/sh\nhdr=(-H "X-Verify-Source: $VERIFY_TOKEN")\ncurl "${hdr[@]}" "$u"\n');
    put('scripts/selftest.sh', '#!/bin/sh\nhdr=(-H "X-Verify-Source: $VERIFY_TOKEN")\n');   // a fixture corpus: never graded
    put('Dockerfile', 'FROM alpine:latest\n');   // puts hadolint in scope (its stub above finds nothing)
    git('add', '.'); git('commit', '-q', '-m', 'change');
    check('fixture repo has two commits (else every assertion below is vacuous)', (git('rev-list', '--count', 'HEAD').stdout || '').trim() === '2');
    SHA.diff = (git('rev-parse', 'HEAD').stdout || '').trim();

    const summaryPath = path.join(tmp, 'summary.md');
    const scan = (extra, cwd = repo) => {
      try { fs.rmSync(summaryPath, { force: true }); } catch { /* fresh file per run */ }
      const r = spawnSync(process.execPath, [fileURLToPath(new URL('./scan.mjs', import.meta.url))], {
        cwd, encoding: 'utf8', timeout: 60000,
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
      `::${level} file=app/config.php,line=3,title=security-baseline secret-pattern::secret-pattern generic-api-key at app/config.php:3 in commit ${SHA.diff.slice(0, 7)}`,
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
    check('each gitleaks finding names the commit it was found in (under full scope its line is that commit\'s, not the tip\'s)',
      new RegExp(`app/config\\.php:3 — generic-api-key \\S+ in commit ${SHA.diff.slice(0, 7)}`).test(a.stdout)
      && new RegExp(`old/legacy\\.php:9 — aws-access-token in history \\S+ in commit ${SHA.hist.slice(0, 7)} — rotate`).test(a.stdout));
    check('findings are not faults: a run full of findings has no leg that could not look', a.stdout.length > 0 && !a.stdout.includes('could not look'));
    check('argv-secret: a T1 WARN group in the report', a.stdout.includes('### ⚠️ `argv-secret` · T1 · 2 finding(s)'));
    check('argv-secret: the untouched workflow IS reported (.github YAML is graded on every run)',
      a.stdout.includes("- ⚠️ .github/workflows/deploy.yml:8 — -H Authorization expands secrets.DEPLOY_API_KEY into a child's argv"));
    check('argv-secret: the changed script is reported', a.stdout.includes('- ⚠️ scripts/smoke.sh:2 — -H X-Verify-Source expands VERIFY_TOKEN'));
    check('argv-secret: an untouched script is NOT graded in diff scope, nor a selftest fixture ever',
      !a.stdout.includes('scripts/untouched.sh') && !a.stdout.includes('scripts/selftest.sh'));

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

    // (E) argv-secret promoted by the caller: it blocks, and each finding annotates by header ←
    // variable name — the scan never sees a value, so none can reach an annotation.
    const e = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', CRITICAL_CHECKS: 'argv-secret' });
    const argvCmds = commands(e.stdout).filter((l) => l.includes('argv-secret')).sort();
    check('argv-secret promoted: BLOCK, one ::error per finding, naming header ← variable', e.status === 1 && JSON.stringify(argvCmds) === JSON.stringify([
      '::error file=.github/workflows/deploy.yml,line=8,title=security-baseline argv-secret::argv-secret -H Authorization ← secrets.DEPLOY_API_KEY at .github/workflows/deploy.yml:8',
      '::error file=scripts/smoke.sh,line=2,title=security-baseline argv-secret::argv-secret -H X-Verify-Source ← VERIFY_TOKEN at scripts/smoke.sh:2',
    ]), `exit ${e.status} ${JSON.stringify(argvCmds)}`);

    // (F) Full scope grades every tracked script, the untouched one included — still never a fixture.
    const f = scan({ GITHUB_STEP_SUMMARY: summaryPath, SCAN_SCOPE: 'full' });
    check('full scope: argv-secret grades the untouched script too', f.stdout.includes('### ⚠️ `argv-secret` · T1 · 3 finding(s)')
      && f.stdout.includes('- ⚠️ scripts/untouched.sh:2 — -H X-Api-Key expands OLD_API_KEY'), f.stdout.split('\n').filter((l) => l.includes('argv')).join(' | '));
    check('full scope: a selftest fixture is still never graded', f.stdout.length > 0 && !f.stdout.includes('scripts/selftest.sh'));
    // Under full scope trufflehog reads all history: a verified key there is pre-existing, a WARN.
    check('full scope: a verified live key is secrets-history, a WARN — never secret-verified',
      f.stdout.includes('- ⚠️ app/config.php:3 — 🔴 VERIFIED-LIVE Github — ROTATE NOW pre-existing in history — WARN, not a block; rotate then scrub history')
      && !f.stdout.includes('`secret-verified`'), f.stdout.split('\n').filter((l) => l.includes('VERIFIED-LIVE') || l.includes('secret-verified')).join(' | '));

    // ---- a scanner that could not look: FAULT under fail-on-critical, never PASS (v1.19.0) ----
    // A CLEAN stub set: every scanner runs and finds nothing (hadolint's one rule firing exits 1, as
    // hadolint does, and must stay a WARN). Each case below breaks exactly one scanner, so a verdict
    // other than PASS can only come from that scanner. (G) proves the set is clean — without it every
    // FAULT assertion below could pass for the wrong reason.
    planted.glerr = mint('GLERR');
    planted.therr = mint('THERR');
    const reportPath = 'out=""\nwhile [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && { shift; out="$1"; }; shift; done';
    const clean = {
      SEMGREP_BIN: stub('semgrep-clean', `echo '{"results":[],"errors":[]}'`),
      GITLEAKS_BIN: stub('gitleaks-clean', `${reportPath}\nprintf '[]\\n' > "$out"`),
      TRUFFLEHOG_BIN: stub('trufflehog-clean', `printf '%s\\n' "$*" >> '${path.join(tmp, 'trufflehog-argv.log')}'`),
      OSV_BIN: stub('osv-clean', `echo '{"results":[]}'`),
      HADOLINT_BIN: stub('hadolint-clean', `echo '[{"code":"DL3007","level":"warning","line":1,"message":"Using latest is prone to errors"}]'\nexit 1`),
    };
    const broken = (over, extra = {}, cwd = repo) => scan({ ...clean, ENABLE_SCA: 'true', ...over, ...extra }, cwd);
    const verdict = (r) => `exit ${r.status}: ${r.stdout.split('\n').filter((l) => /^(PASS|BLOCKED|FAULT|report-only|⚠️ REPORT-MODE|- (❌|⚠️) .* — )/.test(l)).join(' | ')}`;
    const semgrepAnswers = (severityLeg, packLeg = `echo '{"results":[],"errors":[]}'`) => [
      'case "$*" in', `  *--severity*) ${severityLeg} ;;`, `  *wp-php.yaml*) ${packLeg} ;;`, `  *) echo '{"results":[],"errors":[]}' ;;`, 'esac',
    ].join('\n');

    const g = broken({}, { GITHUB_ACTIONS: 'true' });
    check('(G) clean stubs: PASS, exit 0, no leg that could not look, no annotation', g.status === 0 && g.stdout.includes('\nPASS — no critical findings.\n')
      && !g.stdout.includes('could not look') && commands(g.stdout).length === 0, verdict(g));
    check('(G) findings are not failures: hadolint exit 1 with a finding is a WARN, not a fault', g.stdout.includes('### ⚠️ `dockerfile-lint` · T1 · 1 finding(s)'));
    const thArgv = fs.existsSync(path.join(tmp, 'trufflehog-argv.log')) ? fs.readFileSync(path.join(tmp, 'trufflehog-argv.log'), 'utf8') : '';
    check('(G) trufflehog runs with --fail-on-scan-errors (without it a --since-commit it cannot resolve exits 0, scanning nothing)',
      /(^| )--fail-on-scan-errors( |$)/m.test(thArgv), thArgv);
    // Off a pull_request the walk is HEAD back to the base, both as commit ids: trufflehog resolves
    // them in its own clone, where a ref name may not exist (see (T)).
    const revOf = (rev) => (git('rev-parse', rev).stdout || '').trim();
    check('(G) trufflehog walks HEAD back to the base (BASE_REF HEAD~1), both handed over as shas',
      new RegExp(`(^| )--branch ${revOf('HEAD')} --since-commit ${revOf('HEAD~1')}( |$)`, 'm').test(thArgv), thArgv);

    // (H) The registry fetch for the default p/security-audit fails.
    // semgrep 1.178.0's own answer, measured: exit 7 and two error entries.
    const registryDown = JSON.stringify({ results: [], errors: [
      { code: 2, level: 'error', type: 'SemgrepError', message: 'Failed to download configuration from https://semgrep.dev/c/p/security-audit HTTP 503.' },
      { code: 7, level: 'error', type: 'SemgrepError', message: 'invalid configuration file found (1 configs were invalid)' },
    ] });
    const sgDown = stub('semgrep-registry-down', semgrepAnswers(`echo '${registryDown}'; exit 7`));
    const why503 = 'semgrep exit 7: SemgrepError — Failed to download configuration from https[:]//semgrep.dev/c/p/security-audit HTTP 503.';
    const h = broken({ SEMGREP_BIN: sgDown }, { GITHUB_ACTIONS: 'true', GITHUB_STEP_SUMMARY: summaryPath });
    check('(H) semgrep exit 7 under fail-on-critical: FAULT, exit 1 — not PASS', h.status === 1
      && h.stdout.includes('\nFAULT — 1 scanner leg(s) that could have blocked could not look (semgrep community SAST). No verdict: a tool fault in security-baseline, not a finding about this repository.\n')
      && !h.stdout.includes('PASS'), verdict(h));
    check('(H) the note names the scanner, its exit and its error — in the log and the summary',
      h.stdout.includes(`- ❌ semgrep community SAST — ${why503}`) && h.summary.includes(`- ❌ semgrep community SAST — ${why503}`), verdict(h));
    check('(H) a tool fault, never a finding: critical 0, no BLOCKED, never the clean line',
      h.stdout.includes('**critical: 0 · ') && h.stdout.includes(' · could not look: 1**') && !h.stdout.includes('BLOCKED') && !h.stdout.includes('✅ no findings across'));
    check('(H) one ::error for the leg, naming it and why — nothing else command-shaped',
      JSON.stringify(commands(h.stdout)) === JSON.stringify([`::error title=security-baseline could not look::semgrep community SAST could not look — ${why503}`]), JSON.stringify(commands(h.stdout)));
    const hr = broken({ SEMGREP_BIN: sgDown }, { GITHUB_ACTIONS: 'true', REPORT_MODE: 'true' });
    check('(H) the same under report-mode: exit 0, still reported, annotated as ::warning', hr.status === 0
      && hr.stdout.includes('\n⚠️ REPORT-MODE — 1 scanner leg(s) that could have blocked could not look (semgrep community SAST); enforcing, this run would FAULT.\n')
      && JSON.stringify(commands(hr.stdout)) === JSON.stringify([`::warning title=security-baseline could not look::semgrep community SAST could not look — ${why503}`]), verdict(hr));
    const hn = broken({ SEMGREP_BIN: sgDown }, { FAIL_ON_CRITICAL: 'false' });
    check('(H) the same under fail-on-critical: false: exit 0, "would FAULT"', hn.status === 0
      && hn.stdout.includes('\nreport-only — 1 scanner leg(s) that could have blocked could not look (semgrep community SAST); under `fail-on-critical: true` this run would FAULT.\n'), verdict(hn));

    // (I) gitleaks dies before writing its report — here on a config whose parse error quotes a value.
    const glDead = stub('gitleaks-dead', `echo "10:00AM FTL unable to load gitleaks config, err: toml: line 3: expected a quote near ${planted.glerr}" >&2\nexit 1`);
    const i = broken({ GITLEAKS_BIN: glDead }, { GITHUB_ACTIONS: 'true' });
    check('(I) gitleaks exit 1 with no report: FAULT, exit 1 — not PASS', i.status === 1
      && i.stdout.includes('\nFAULT — 1 scanner leg(s) that could have blocked could not look (gitleaks secret scan).') && !i.stdout.includes('PASS'), verdict(i));
    check('(I) the note names gitleaks, its exit and its error; the history pass that also died only warns',
      i.stdout.includes('- ❌ gitleaks secret scan — gitleaks exit 1: 10:00AM FTL unable to load gitleaks config, err: toml: line 3: expected a quote near ')
      && i.stdout.includes('- ⚠️ gitleaks full-history baseline — gitleaks exit 1: ') && commands(i.stdout).length === 1, verdict(i));
    check('(I) a value quoted in the error is cut to first4…last4 — no 8-character run in any output',
      !leaked(i.stdout) && !leaked(i.stderr) && i.stdout.includes(redact(planted.glerr)));
    const ir = broken({ GITLEAKS_BIN: glDead }, { REPORT_MODE: 'true' });
    check('(I) the same under report-mode: exit 0', ir.status === 0
      && ir.stdout.includes('⚠️ REPORT-MODE — 1 scanner leg(s) that could have blocked could not look (gitleaks secret scan); enforcing, this run would FAULT.'), verdict(ir));

    // (J) A rule pack that does not load: its checks only warn — until the caller promotes one.
    const packBroken = JSON.stringify({ results: [], errors: [
      { code: 4, level: 'error', type: 'InvalidRuleSchemaError', message: null },
      { code: 7, level: 'error', type: 'SemgrepError', message: 'invalid configuration file found (1 configs were invalid)' },
    ] });
    const sgPack = stub('semgrep-pack-broken', semgrepAnswers(`echo '{"results":[],"errors":[]}'`, `echo '${packBroken}'; exit 7`));
    const j = broken({ SEMGREP_BIN: sgPack });
    check('(J) a leg whose checks only warn here: reported ⚠️, PASS stands, exit 0', j.status === 0
      && j.stdout.includes('- ⚠️ semgrep WP/PHP + Astro/TS rule packs — semgrep exit 7: InvalidRuleSchemaError (its checks only warn for this caller: reported, not a fault)')
      && j.stdout.includes('\nPASS — no critical findings. 1 scanner leg(s) that only warn here could not look (above).\n'), verdict(j));
    const jp = broken({ SEMGREP_BIN: sgPack }, { CRITICAL_CHECKS: 'wp-rest-error-detail' });
    check('(J) the same leg with one of its checks promoted (the five lux-shaped callers): FAULT, exit 1', jp.status === 1
      && jp.stdout.includes('\nFAULT — 1 scanner leg(s) that could have blocked could not look (semgrep WP/PHP + Astro/TS rule packs).'), verdict(jp));

    // (K) trufflehog dies on the diff range (T0). Its log is never quoted, so nothing it printed —
    // a live credential included — can reach the report, not even redacted.
    const thDead = stub('trufflehog-dead', `echo "error running scan: verification of ${planted.therr} failed" >&2\nexit 1`);
    const k = broken({ TRUFFLEHOG_BIN: thDead });
    check('(K) trufflehog exit 1 on the diff: FAULT, exit 1', k.status === 1
      && k.stdout.includes('- ❌ trufflehog verified-live secrets — trufflehog exit 1 — its log is not quoted here, rerun trufflehog to read it'), verdict(k));
    check('(K) nothing from its stderr reaches any output, not even redacted', !leaked(k.stdout) && !leaked(k.stderr) && !k.stdout.includes(redact(planted.therr)));

    // (L) osv-scanner: 128 (no manifest) and 1 (vulnerabilities) both looked; 127 could not.
    const l1 = broken({ OSV_BIN: stub('osv-none', `echo 'No package sources found, --help for usage information.' >&2\nexit 128`) });
    check('(L) osv-scanner exit 128 (no package manifest): nothing to audit, not a fault', l1.status === 0 && !l1.stdout.includes('could not look'), verdict(l1));
    const vuln = JSON.stringify({ results: [{ source: { path: 'package-lock.json' }, packages: [{ package: { name: 'lodash', version: '4.17.20' }, groups: [{ ids: ['GHSA-35jh-r3h4-6jhm'], max_severity: '7.2' }] }] }] });
    const l2 = broken({ OSV_BIN: stub('osv-vuln', `echo '${vuln}'\nexit 1`) });
    check('(L) osv-scanner exit 1 with a vulnerability: a finding (sca-high WARN), not a fault', l2.status === 0
      && l2.stdout.includes('### ⚠️ `sca-high` · T1 · 1 finding(s)') && !l2.stdout.includes('could not look'), verdict(l2));
    const osvDead = stub('osv-dead', `echo 'failed to query osv.dev: 503' >&2\nexit 127`);
    const l3 = broken({ OSV_BIN: osvDead });
    check('(L) osv-scanner exit 127: reported ⚠️, PASS stands (its checks only warn)', l3.status === 0
      && l3.stdout.includes('- ⚠️ osv-scanner dependency audit — osv-scanner exit 127: failed to query osv.dev: 503 (its checks only warn'), verdict(l3));
    const l4 = broken({ OSV_BIN: osvDead }, { CRITICAL_CHECKS: 'sca-critical' });
    check('(L) osv-scanner exit 127 with sca-critical promoted: FAULT', l4.status === 1 && l4.stdout.includes('could not look (osv-scanner dependency audit).'), verdict(l4));

    // (L) Exit 128 in a tree that tracks a lockfile (v1.19.5). v2.4.0 exits 128 for a lockfile it could
    // not parse (`Error during extraction`), for one it does not read at all (a bun.lockb, nothing on
    // stderr), and for one it read and found no package in: only the last looked. The list leaves
    // out node_modules, which osv-scanner skips too — force-added here so the rule is exercised.
    const locked = path.join(tmp, 'repo-locked');
    fs.mkdirSync(path.join(locked, 'web'), { recursive: true });
    fs.mkdirSync(path.join(locked, 'node_modules', 'dep'), { recursive: true });
    const gitL = (...a) => spawnSync('git', ['-c', 'user.name=selftest', '-c', 'user.email=selftest@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd: locked, env: base, encoding: 'utf8' });
    gitL('init', '-q');
    fs.writeFileSync(path.join(locked, 'README.md'), 'base\n');
    gitL('add', '.'); gitL('commit', '-q', '-m', 'base');
    fs.writeFileSync(path.join(locked, 'web', 'package-lock.json'), '{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17');
    fs.writeFileSync(path.join(locked, 'node_modules', 'dep', 'package-lock.json'), '{}\n');
    gitL('add', '-f', '.'); gitL('commit', '-q', '-m', 'lockfile');
    check('(L) the lockfile fixture tracks both lockfiles (else the node_modules exclusion is untested)',
      (gitL('ls-files').stdout || '').split('\n').filter((f) => f.endsWith('package-lock.json')).length === 2);
    const realLocked = fs.realpathSync(locked);
    const osv128 = (name, ...lines) => stub(name, `${lines.map((l) => `echo '${l}' >&2`).join('\n')}\nexit 128`);
    const NONE = 'No package sources found, --help for usage information.';
    const osvExtract = osv128('osv-extract-error', 'Scanning dir .', `Error during extraction: (extracting as javascript/packagelockjson) ${realLocked.slice(1)}/web/package-lock.json: could not extract: unexpected end of JSON input`, NONE);
    const l5 = broken({ OSV_BIN: osvExtract }, {}, locked);
    check('(L) osv-scanner exit 128 with an extraction error: could not look, osv\'s error named, PASS stands (its checks only warn)', l5.status === 0
      && l5.stdout.includes('- ⚠️ osv-scanner dependency audit — osv-scanner exit 128: Error during extraction: extracting as javascript/packagelockjson web/package-lock.json: could not extract: unexpected end of JSON input (its checks only warn'), verdict(l5));
    const l6 = broken({ OSV_BIN: osvExtract }, { CRITICAL_CHECKS: 'sca-critical' }, locked);
    check('(L) osv-scanner exit 128 with an extraction error, sca-critical promoted: FAULT', l6.status === 1 && l6.stdout.includes('could not look (osv-scanner dependency audit).'), verdict(l6));
    const l7 = broken({ OSV_BIN: osv128('osv-read-none', 'Scanning dir .', NONE) }, {}, locked);
    check('(L) osv-scanner exit 128 having read none of the tracked lockfiles: could not look, the lockfile named — node_modules left out',
      l7.status === 0 && l7.stdout.includes("- ⚠️ osv-scanner dependency audit — osv-scanner exit 128: it read none of the tree's lockfiles: web/package-lock.json (its checks only warn"), verdict(l7));
    const l8 = broken({ OSV_BIN: osv128('osv-read-empty', 'Scanning dir .', `Scanned ${realLocked}/web/package-lock.json file and found 0 packages`, NONE) }, {}, locked);
    check('(L) osv-scanner exit 128 having read the lockfile and found no package: nothing to audit, not a fault', l8.status === 0 && !l8.stdout.includes('could not look') && /\nPASS/.test(l8.stdout), verdict(l8));

    // (M) semgrep not installed — "not installed" used to be a scanner note under a PASS.
    const m = broken({ SEMGREP_BIN: path.join(tmp, 'no-such-dir', 'semgrep') });
    check('(M) semgrep not installed: FAULT, exit 1', m.status === 1 && m.stdout.includes('- ❌ semgrep community SAST — semgrep not installed'), verdict(m));

    // (N) A diff base git cannot resolve: the changed-file list failed, it is not an empty diff.
    const n = broken({}, { BASE_REF: 'no-such-ref' });
    check('(N) an unresolvable diff base: FAULT on the changed-file list, exit 1', n.status === 1
      && n.stdout.includes("- ❌ changed-file list — git diff no-such-ref...HEAD failed, exit 128: fatal: ambiguous argument 'no-such-ref...HEAD': unknown revision"), verdict(n));
    check('(N) trufflehog is not run on it (unscoped it would walk all history under a T0 leg): its leg says why',
      n.stdout.includes(`- ❌ trufflehog verified-live secrets — no commit to stop the walk at: git merge-base no-such-ref ${revOf('HEAD').slice(0, 7)} failed, exit 128: fatal: `), verdict(n));

    // (O) A collector that throws: its legs could not look (was a scanner note under a PASS).
    const o = broken({ SEMGREP_BIN: stub('semgrep-null-result', `echo '{"results":[null],"errors":[]}'`) });
    check('(O) a collector that crashes: FAULT naming it, exit 1', o.status === 1 && /\n- ❌ semgrep community SAST — collectSemgrep crashed: /.test(o.stdout), verdict(o));

    // (P) A scanner killed mid-run (the timeout path sends SIGTERM): run() hands outcome.mjs the signal.
    const p = broken({ GITLEAKS_BIN: stub('gitleaks-killed', 'kill -KILL $$') });
    check('(P) a scanner killed by a signal: FAULT naming the signal, exit 1', p.status === 1 && p.stdout.includes('- ❌ gitleaks secret scan — gitleaks killed by SIGKILL'), verdict(p));

    // (Q) With no finding at all, "✅ no findings across SAST, secrets, SCA, and CI supply-chain" is a
    // claim about every scanner, so a leg that could not look must replace it. The fixture repo above
    // always has WARN findings (argv-secret, hadolint), so it never reaches that line: a bare repo does.
    const bare = path.join(tmp, 'bare');
    fs.mkdirSync(bare);
    const gitBare = (...a) => spawnSync('git', ['-c', 'user.name=selftest', '-c', 'user.email=selftest@example.invalid', '-c', 'commit.gpgsign=false', ...a], { cwd: bare, env: base, encoding: 'utf8' });
    gitBare('init', '-q');
    fs.writeFileSync(path.join(bare, 'README.md'), 'base\n'); gitBare('add', '.'); gitBare('commit', '-q', '-m', 'base');
    fs.writeFileSync(path.join(bare, 'index.php'), '<?php // fixture\n'); gitBare('add', '.'); gitBare('commit', '-q', '-m', 'change');
    const q0 = broken({}, {}, bare);
    check('(Q) control: a bare repo with every scanner clean prints the ✅ clean line', q0.status === 0 && q0.stdout.includes('\n- ✅ no findings across SAST, secrets, SCA, and CI supply-chain.\n'), verdict(q0));
    const q = broken({ SEMGREP_BIN: sgDown }, {}, bare);
    check('(Q) the same repo with a leg that could not look: never the ✅ clean line', q.status === 1
      && q.stdout.includes('\n- no findings from the scanners that looked — the legs that could not are listed below.\n') && !q.stdout.includes('✅ no findings across'), verdict(q));

    // (R) Outside a git repository gitleaks exits 0 with `[]` (measured on 8.30.1): never a clean result.
    const nogit = path.join(tmp, 'not-a-repo');
    fs.mkdirSync(nogit);
    fs.writeFileSync(path.join(nogit, 'index.php'), '<?php // fixture\n');
    const r = broken({}, {}, nogit);
    check('(R) no git history: the gitleaks legs could not look — FAULT, exit 1', r.status === 1
      && r.stdout.includes('- ❌ gitleaks secret scan — no git history here — not a git repository, or no commit — so gitleaks would read nothing'), verdict(r));

    // (S) The registry stall measured on 1.178.0: ~100 s, then exit 2 with nothing on stdout or stderr.
    // The time is the only clue left, so the reason carries it (10 s here keeps the suite quick).
    const stall = broken({ SEMGREP_BIN: stub('semgrep-stall', semgrepAnswers('sleep 10; exit 2')) });
    check('(S) a stalled registry fetch: FAULT, and the reason says how long it took', stall.status === 1
      && /\n- ❌ semgrep community SAST — semgrep exit 2 after 1\d s: no JSON report\n/.test(stall.stdout), verdict(stall));

    // (T) The pull_request checkout (v1.19.6). Every case above runs on a branch, with a sha or HEAD~1
    // for a base, as a push does. actions/checkout leaves a pull_request run DETACHED on GitHub's test
    // merge (refs/remotes/pull/N/merge) with no local branch, and the base arrives as a ref NAME:
    // GITHUB_BASE_REF → origin/<base>, BASE_REF empty, which is the env of every PR run that faulted.
    // Here the PR is one commit off main, older than main's tip, and main moved again after GitHub
    // computed the merge, so origin/main's tip is not in HEAD's history either. The stub is trufflehog
    // 3.95.6 as measured and as its source reads: it clones the file:// repository it is given as
    // trufflehog does (every ref, under refs/remotes/origin/), or with --trust-local-git-config scans
    // that repository in place; resolves --branch and --since-commit THERE (as given, then under
    // refs/heads/ and refs/remotes/origin/), takes their merge base when given both, walks `git log`
    // from --branch (every ref without it) and stops at the base. It appends each commit it walks to
    // the walk log, and under TH_EMIT reports a verified finding for every `.live` file a walked
    // commit adds (none for a merge, which `git log -p` shows no patch for).
    const walkLog = path.join(tmp, 'trufflehog-walk.log');
    const realArgv = path.join(tmp, 'trufflehog-as-measured-argv.log');
    const thAsMeasured = stub('trufflehog-as-measured', [
      `printf '%s\\n' "$*" >> '${realArgv}'`,
      `: >> '${walkLog}'`,
      'uri=""; branch=""; since=""; trust=""',
      'while [ $# -gt 0 ]; do case "$1" in file://*) uri="${1#file://}" ;; --branch) shift; branch="$1" ;; --since-commit) shift; since="$1" ;; --trust-local-git-config) trust=1 ;; esac; shift; done',
      'if [ -n "$trust" ]; then c="$uri"; else',
      '  d=$(mktemp -d "$TMPDIR/th-clone.XXXXXX") || exit 1',
      '  trap \'rm -rf "$d"\' EXIT',
      '  src=$(cd "$uri" && pwd) || exit 1',
      '  git clone -q -c \'remote.origin.fetch=+refs/*:refs/remotes/origin/*\' "file://$src" "$d/c" 2>/dev/null || exit 1',
      '  c="$d/c"',
      'fi',
      'resolve() { for p in "" refs/heads/ refs/remotes/origin/; do git -C "$c" rev-parse -q --verify "$p$1^{commit}" && return 0; done; return 1; }',
      'base=""; head="--all"',
      'if [ -n "$since" ]; then base=$(resolve "$since") || { echo "unable to resolve ref: no base refs succeeded for base: \\"$since\\"" >&2; exit 1; }; fi',
      'if [ -n "$branch" ]; then head=$(resolve "$branch") || exit 1; if [ -n "$base" ]; then base=$(git -C "$c" merge-base "$head" "$base") || exit 1; fi; fi',
      `git -C "$c" log --format=%H $head | while read -r x; do`,
      '  [ "$x" = "$base" ] && break',
      `  echo "$x" >> '${walkLog}'`,
      '  [ -z "$TH_EMIT" ] || git -C "$c" diff-tree --no-commit-id --name-only -r --root "$x" | grep \'\\.live$\' | while read -r f; do',
      '    printf \'{"SourceMetadata":{"Data":{"Git":{"commit":"%s","file":"%s","line":1}}},"DetectorName":"Github","Verified":true}\\n\' "$x" "$f"',
      '  done',
      'done',
      // …and, as 3.95.6 does, deletes a repository it read in place whose path starts with
      // $TMPDIR/trufflehog, the prefix of its own clones.
      'if [ -n "$trust" ]; then case "$c" in "${TMPDIR%/}/trufflehog"*) rm -rf "$c" ;; esac; fi',
    ].join('\n'));
    const walked = () => (fs.existsSync(walkLog) ? fs.readFileSync(walkLog, 'utf8').split('\n').filter(Boolean) : null);
    const gitAt = (dir, iso) => (...a) => spawnSync('git', ['-c', 'user.name=selftest', '-c', 'user.email=selftest@example.invalid', '-c', 'commit.gpgsign=false', ...a],
      { cwd: dir, env: { ...base, ...(iso ? { GIT_AUTHOR_DATE: iso, GIT_COMMITTER_DATE: iso } : {}) }, encoding: 'utf8' });
    const shaIn = (dir, rev) => (gitAt(dir)('rev-parse', rev).stdout || '').trim();
    const up = path.join(tmp, 'pr-upstream');     // the caller's repository on GitHub
    const prRepo = path.join(tmp, 'pr-checkout'); // what actions/checkout leaves a pull_request run on
    fs.mkdirSync(up);
    fs.mkdirSync(prRepo);
    const commitIn = (iso, file, msg) => {
      fs.writeFileSync(path.join(up, file), '<?php // fixture\n');
      gitAt(up)('add', file);
      gitAt(up, iso)('commit', '-q', '-m', msg);
      return shaIn(up, 'HEAD');
    };
    gitAt(up)('init', '-q', '-b', 'main');
    const forkPoint = commitIn('2026-09-01T10:00:00Z', 'README.md', 'where the PR leaves main');
    gitAt(up)('checkout', '-q', '-b', 'feature');
    const prCommit = commitIn('2026-09-01T11:00:00Z', 'pr.php', 'the PR, older than main tip');
    gitAt(up)('checkout', '-q', 'main');
    const mainTip = commitIn('2026-09-01T12:00:00Z', 'main.php', 'main moves on');
    const pr = gitAt(prRepo);
    pr('init', '-q');
    pr('fetch', '-q', '--no-tags', up, '+refs/heads/*:refs/remotes/origin/*');
    pr('checkout', '-q', '--detach', 'refs/remotes/origin/main');
    gitAt(prRepo, '2026-09-01T13:00:00Z')('merge', '-q', '--no-ff', '--no-edit', 'refs/remotes/origin/feature');
    pr('update-ref', 'refs/remotes/pull/1/merge', 'HEAD');
    pr('checkout', '-q', '--detach', 'refs/remotes/pull/1/merge');
    const mainLater = commitIn('2026-09-01T14:00:00Z', 'later.php', 'main moves on after the merge was computed');
    pr('fetch', '-q', '--no-tags', up, '+refs/heads/*:refs/remotes/origin/*');
    check('(T) the fixture is a pull_request checkout: detached on the test merge, no local branch, origin/main past it',
      pr('symbolic-ref', '-q', 'HEAD').status !== 0 && (pr('for-each-ref', 'refs/heads').stdout || '') === ''
      && shaIn(prRepo, 'HEAD^1') === mainTip && shaIn(prRepo, 'HEAD^2') === prCommit && shaIn(prRepo, 'refs/remotes/origin/main') === mainLater
      && pr('merge-base', '--is-ancestor', mainLater, 'HEAD').status === 1);
    // Controls: the stub reproduces both defects, so the passing case below cannot pass vacuously.
    const thBy = (...args) => {
      fs.rmSync(walkLog, { force: true });
      const res = spawnSync(thAsMeasured, ['git', 'file://.', '--only-verified', '--no-update', '--json', '--fail-on-scan-errors', ...args], { cwd: prRepo, env: base, encoding: 'utf8' });
      return { status: res.status, walked: walked() };
    };
    const asV1195 = thBy('--since-commit', 'origin/main');
    check("(T) control: v1.19.5's argv (--since-commit origin/main) does not resolve in trufflehog's clone — exit 1", asV1195.status === 1, JSON.stringify(asV1195));
    // trufflehog's clone carries every ref of the checkout (origin/main as refs/remotes/origin/remotes/
    // origin/main), so the tip's sha resolves; with no --branch the walk starts from every ref, and
    // that tip is the newest commit there: it stops before walking anything. Measured on 3.95.6.
    const asTipSha = thBy('--since-commit', mainLater);
    check("(T) control: origin/main's tip as a sha resolves in the clone, and the walk stops on it before any commit — exit 0, nothing walked",
      asTipSha.status === 0 && Array.isArray(asTipSha.walked) && asTipSha.walked.length === 0, JSON.stringify(asTipSha));
    const fromMerge = thBy('--since-commit', mainTip);   // merge-base(origin/main, HEAD): resolves, and walks the wrong commits
    check('(T) control: walked from the test merge back to the base tip it looks, and never reaches the PR commit',
      fromMerge.status === 0 && Array.isArray(fromMerge.walked) && fromMerge.walked.length > 0 && !fromMerge.walked.includes(prCommit), JSON.stringify(fromMerge));
    // The run, with the env of the faulting runs plus the PR head action.yml now passes.
    const prEnv = { BASE_REF: '', GITHUB_BASE_REF: 'main', GITHUB_EVENT_BEFORE: '', PR_HEAD_SHA: prCommit };
    // One scan through the as-measured stub: what it walked (every walk, in order) and each argv.
    const walkScan = (cwd, env, extra = {}, bin = thAsMeasured) => {
      fs.rmSync(walkLog, { force: true });
      fs.rmSync(realArgv, { force: true });
      const res = broken({ TRUFFLEHOG_BIN: bin }, { ...env, ...extra }, cwd);
      const argvs = fs.existsSync(realArgv) ? fs.readFileSync(realArgv, 'utf8').split('\n').filter(Boolean) : [];
      return { ...res, walked: walked() || [], argvs };
    };
    const tpr = walkScan(prRepo, prEnv);
    check('(T) a pull_request checkout: trufflehog looks — PASS, exit 0, no leg that could not look',
      tpr.status === 0 && tpr.stdout.includes('\nPASS — no critical findings.\n') && !tpr.stdout.includes('could not look'), verdict(tpr));
    check("(T) it walks exactly the PR's commit: not main's newer tip, not the test merge, nothing before the fork",
      JSON.stringify(tpr.walked) === JSON.stringify([prCommit]), JSON.stringify({ walked: tpr.walked, prCommit }));
    const prArgv = tpr.argvs[tpr.argvs.length - 1] || '';
    check('(T) handed over as shas: --branch the PR head, --since-commit where it left origin/main',
      new RegExp(`(^| )--branch ${prCommit} --since-commit ${forkPoint}( |$)`).test(prArgv), prArgv);
    // v1.19.7: scan.mjs clones the checkout once and names that clone, never file://.
    const cloneOf = (argv) => ((argv.match(/(?:^| )file:\/\/(\S+)/) || [])[1] || '');
    const prClone = cloneOf(prArgv);
    check('(T) a linear range is one walk, on a clone of the checkout named with --trust-local-git-config, and no note',
      tpr.argvs.length === 1 && / --trust-local-git-config /.test(prArgv) && path.basename(prClone) === 'repo'
      && path.basename(path.dirname(prClone)).startsWith('sb-trufflehog-') && !tpr.stdout.includes('segment tips'), JSON.stringify(tpr.argvs));
    check('(T) and that clone is gone once the walks are done', prClone !== '' && !fs.existsSync(path.dirname(prClone)), prClone);
    // A PR head the checkout does not hold (a caller checking out something else): noted, walked from
    // HEAD, the test merge. The PR head is that merge's in-range parent, so it gets a walk of its own.
    const noSuchHead = shaOf('a PR head this checkout never fetched');
    const tnh = walkScan(prRepo, { ...prEnv, PR_HEAD_SHA: noSuchHead });
    check('(T) a PR head not in the checkout: a scanner note, the walk starts at HEAD, and it still looks',
      tnh.status === 0 && tnh.stdout.includes(`- trufflehog: the PR head ${noSuchHead.slice(0, 7)} is not in this checkout, so the walk starts at HEAD`)
      && !tnh.stdout.includes('could not look'), verdict(tnh));
    check("(T) walked from the test merge, the PR's commit is walked still, and nothing of main's",
      tnh.walked.includes(prCommit) && ![mainTip, mainLater, forkPoint].some((c) => tnh.walked.includes(c)), JSON.stringify(tnh.walked));
    const actYml = fs.readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
    check('(T) action.yml wires the pull_request head into the Scan step as PR_HEAD_SHA',
      /^\s+PR_HEAD_SHA:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}\s*$/m.test(actYml));

    // ---- (T) a range that holds a merge (v1.19.7) ----
    // One walk holds both parents of a merge and takes the newer first, so it stops before the other
    // side's commits dated earlier: a PR that merged its base in, and on a push a branch merged onto
    // the base. Every commit below that matters adds a `.live` file, and TH_EMIT makes the stub report
    // each as a verified finding: the report shows what was walked, and a base commit's never blocks.
    const upstream = (name) => {
      const dir = path.join(tmp, name);
      fs.mkdirSync(dir);
      gitAt(dir)('init', '-q', '-b', 'main');
      return {
        dir,
        on: (...a) => gitAt(dir)('checkout', '-q', ...a),
        commit: (iso, file, text = `${file}\n`) => { fs.writeFileSync(path.join(dir, file), text); gitAt(dir)('add', file); gitAt(dir, iso)('commit', '-q', '-m', file); return shaIn(dir, 'HEAD'); },
        merge: (iso, ...a) => { gitAt(dir, iso)('merge', '-q', '--no-ff', '--no-edit', ...a); return shaIn(dir, 'HEAD'); },
      };
    };
    // What actions/checkout leaves a pull_request run on, as above: feature into main, detached.
    const prCheckout = (up, name) => {
      const dir = path.join(tmp, name);
      fs.mkdirSync(dir);
      gitAt(dir)('init', '-q');
      gitAt(dir)('fetch', '-q', '--no-tags', up.dir, '+refs/heads/*:refs/remotes/origin/*');
      gitAt(dir)('checkout', '-q', '--detach', 'refs/remotes/origin/main');
      gitAt(dir, '2026-09-10T00:00:00Z')('merge', '-q', '--no-ff', '--no-edit', 'refs/remotes/origin/feature');
      gitAt(dir)('update-ref', 'refs/remotes/pull/1/merge', 'HEAD');
      gitAt(dir)('checkout', '-q', '--detach', 'refs/remotes/pull/1/merge');
      return dir;
    };
    const thIn = (cwd, ...args) => {
      fs.rmSync(walkLog, { force: true });
      const res = spawnSync(thAsMeasured, ['git', 'file://.', '--only-verified', '--no-update', '--json', '--fail-on-scan-errors', ...args], { cwd, env: base, encoding: 'utf8' });
      return { status: res.status, walked: walked() || [] };
    };
    const sameSet = (a, b) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());
    const live = (r, file, sha) => r.stdout.includes(`- ❌ ${file}:1 — 🔴 VERIFIED-LIVE Github in commit ${sha.slice(0, 7)} — ROTATE NOW`);

    // (T-a) A PR that merged its base in: one PR commit older than the base commit it merged, one newer
    // (the head's walk reaches that one too, so two walks meet in it).
    const ua = upstream('merged-base-up');
    const aFork = ua.commit('2026-09-02T10:00:00Z', 'fork.live');
    ua.on('-b', 'feature');
    const aOld = ua.commit('2026-09-02T10:30:00Z', 'pr-old.live');
    const aMid = ua.commit('2026-09-02T12:30:00Z', 'pr-mid.live');
    ua.on('main');
    const aBase = ua.commit('2026-09-02T12:00:00Z', 'base-merged.live');
    ua.on('feature');
    const aMerge = ua.merge('2026-09-02T13:00:00Z', 'main');
    const aHead = ua.commit('2026-09-02T14:00:00Z', 'pr-new.live');
    ua.on('main');
    ua.commit('2026-09-02T15:00:00Z', 'main-after.live');
    const pa = prCheckout(ua, 'merged-base-pr');
    const aCtl = thIn(pa, '--branch', aHead, '--since-commit', aBase);
    check("(T-a) control: v1.19.6's one walk from the PR head stops at the base commit it merged, before the PR's older commit",
      aCtl.status === 0 && sameSet(aCtl.walked, [aHead, aMerge, aMid]), JSON.stringify(aCtl));
    const ta = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, { TH_EMIT: '1' });
    check("(T-a) the walks cover exactly the PR's commits, the older one too: never the base commit it merged, main's later one or the fork",
      sameSet(ta.walked, [aHead, aMerge, aMid, aOld]), JSON.stringify({ walked: ta.walked, want: [aHead, aMerge, aMid, aOld] }));
    check('(T-a) two walks: the PR head back to the base commit it merged, the in-range parent of its merge back to the fork',
      ta.argvs.length === 2 && new RegExp(` --branch ${aHead} --since-commit ${aBase}$`).test(ta.argvs[0])
      && new RegExp(` --branch ${aMid} --since-commit ${aFork}$`).test(ta.argvs[1]), JSON.stringify(ta.argvs));
    check('(T-a) both walks on ONE clone, named with --trust-local-git-config: one clone a scan, however many walks',
      ta.argvs.every((l) => / --trust-local-git-config /.test(l)) && new Set(ta.argvs.map(cloneOf)).size === 1
      && path.basename(path.dirname(cloneOf(ta.argvs[0]))).startsWith('sb-trufflehog-'), JSON.stringify(ta.argvs));
    check("(T-a) the PR's three live keys BLOCK, each named with its commit; the one both walks met in is reported once",
      ta.status === 1 && ta.stdout.includes('\nBLOCKED — 3 critical finding(s). ') && ta.stdout.includes('### ❌ `secret-verified` · T0 · 3 finding(s)')
      && live(ta, 'pr-old.live', aOld) && live(ta, 'pr-mid.live', aMid) && live(ta, 'pr-new.live', aHead)
      && ta.walked.filter((c) => c === aMid).length === 2, verdict(ta));
    check('(T-a) no base commit reaches the report: not the one merged in, not main after it, not the fork',
      ta.stdout.length > 0 && !/base-merged\.live|main-after\.live|fork\.live/.test(ta.stdout), verdict(ta));
    check('(T-a) the report says why there were two walks',
      ta.stdout.includes('- trufflehog: the range holds 1 merge, so it was walked from 2 segment tips, each back to where it left the base'), verdict(ta));

    // (T-b) A push: a branch merged onto main with a merge commit, its commit older than event.before.
    const ub = upstream('merged-branch-push');
    const bFork = ub.commit('2026-09-03T10:00:00Z', 'fork.live');
    ub.on('-b', 'topic');
    const bTopic = ub.commit('2026-09-03T11:00:00Z', 'topic.live');
    ub.on('main');
    const bBefore = ub.commit('2026-09-03T12:00:00Z', 'before.live');
    const bAfter = ub.merge('2026-09-03T13:00:00Z', 'topic');
    const bCtl = thIn(ub.dir, '--branch', bAfter, '--since-commit', bBefore);
    check("(T-b) control: v1.19.6's walk from the pushed merge stops at event.before, before the merged branch's older commit",
      bCtl.status === 0 && sameSet(bCtl.walked, [bAfter]), JSON.stringify(bCtl));
    const tb = walkScan(ub.dir, { BASE_REF: '', GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: bBefore, PR_HEAD_SHA: '' }, { TH_EMIT: '1' });
    check("(T-b) a push: the walks cover exactly the pushed range, the merge and the merged branch's commit, from a walk each",
      sameSet(tb.walked, [bAfter, bTopic]) && tb.argvs.length === 2 && new RegExp(` --branch ${bAfter} --since-commit ${bBefore}$`).test(tb.argvs[0])
      && new RegExp(` --branch ${bTopic} --since-commit ${bFork}$`).test(tb.argvs[1]), JSON.stringify({ walked: tb.walked, argvs: tb.argvs }));
    check("(T-b) the merged branch's live key BLOCKS; event.before's and the fork's never reach the report",
      tb.status === 1 && tb.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && live(tb, 'topic.live', bTopic)
      && !/before\.live|fork\.live/.test(tb.stdout), verdict(tb));

    // (T-c) A skewed commit date: main's commit is dated before its own parent, the fork, so the head's
    // walk takes the fork before it reaches its stop. The fork is pre-existing: a live key the walk
    // meets there warns, and never blocks (v1.19.6 blocked on it).
    const uc = upstream('skewed-up');
    uc.commit('2026-09-04T09:00:00Z', 'root.txt');
    const cFork = uc.commit('2026-09-04T10:00:00Z', 'fork.live');
    uc.on('-b', 'feature');
    const cPr = uc.commit('2026-09-04T11:00:00Z', 'pr.txt');
    uc.on('main');
    const cSkew = uc.commit('2026-09-04T09:30:00Z', 'skewed.txt');
    uc.on('feature');
    const cHead = uc.merge('2026-09-04T12:00:00Z', 'main');
    const pc = prCheckout(uc, 'skewed-pr');
    const cCtl = thIn(pc, '--branch', cHead, '--since-commit', cSkew);
    check('(T-c) control: the walk from the PR head passes through the fork, a base commit, on its way to its stop',
      cCtl.status === 0 && cCtl.walked.includes(cFork) && cCtl.walked.includes(cPr), JSON.stringify(cCtl));
    const tc = walkScan(pc, { ...prEnv, PR_HEAD_SHA: cHead }, { TH_EMIT: '1' });
    check('(T-c) a live key a walk met outside the range is pre-existing: a secrets-history WARN, never a block — PASS, exit 0',
      tc.status === 0 && tc.stdout.includes('\nPASS — no critical findings.\n') && !tc.stdout.includes('`secret-verified`')
      && tc.stdout.includes(`- ⚠️ fork.live:1 — 🔴 VERIFIED-LIVE Github in commit ${cFork.slice(0, 7)} — ROTATE NOW pre-existing in history — WARN, not a block; rotate then scrub history`), verdict(tc));

    // (T-d) A PR that merged an unrelated history in (another repository imported): that side shares
    // no commit with the base, so all of it is in the range, and its tip is walked to its root.
    const ud = upstream('unrelated-up');
    const dFork = ud.commit('2026-09-05T10:00:00Z', 'fork.live');
    ud.on('--orphan', 'imported');
    gitAt(ud.dir)('rm', '-rfq', '.');
    const dImp = ud.commit('2026-09-05T09:00:00Z', 'imported.live');
    ud.on('-b', 'feature', 'main');
    const dPr = ud.commit('2026-09-05T11:00:00Z', 'pr.txt');
    const dHead = ud.merge('2026-09-05T12:00:00Z', '--allow-unrelated-histories', 'imported');
    const pd = prCheckout(ud, 'unrelated-pr');
    const dCtl = thIn(pd, '--branch', dHead, '--since-commit', dFork);
    check("(T-d) control: v1.19.6's walk stops at the fork before the imported root, dated earlier",
      dCtl.status === 0 && sameSet(dCtl.walked, [dHead, dPr]), JSON.stringify(dCtl));
    const td = walkScan(pd, { ...prEnv, PR_HEAD_SHA: dHead }, { TH_EMIT: '1' });
    check('(T-d) an unrelated history merged in is walked from its tip to its root, no --since-commit, and its live key BLOCKS',
      td.status === 1 && sameSet(td.walked, [dHead, dPr, dImp]) && td.argvs.length === 3 && new RegExp(` --branch ${dImp}$`).test(td.argvs[2])
      && live(td, 'imported.live', dImp) && !td.stdout.includes('fork.live') && !td.stdout.includes('could not look'),
      JSON.stringify({ walked: td.walked, argvs: td.argvs, verdict: verdict(td) }));
    check('(T-d) the note says that tip went to its root',
      td.stdout.includes('- trufflehog: the range holds 1 merge, so it was walked from 3 segment tips, each back to where it left the base, or to its root where it shares no commit with the base'), verdict(td));

    // (T-e) A key the change adds on the file and line of a pre-existing one that a walk met FIRST
    // (through a skewed base commit, as in T-c). The two are told apart by commit, so it blocks.
    const ue = upstream('same-line-up');
    ue.commit('2026-09-06T09:00:00Z', 'root.txt');
    const eFork = ue.commit('2026-09-06T10:00:00Z', 'shared.live');
    ue.on('-b', 'side');
    const eSide = ue.commit('2026-09-06T09:50:00Z', 'shared.live', 'shared.live, as the change leaves it\n');
    ue.on('-b', 'feature', eFork);
    ue.commit('2026-09-06T11:00:00Z', 'pr.txt');
    ue.merge('2026-09-06T11:30:00Z', 'side');
    ue.on('main');
    ue.commit('2026-09-06T09:30:00Z', 'skewed.txt');
    ue.on('feature');
    const eHead = ue.merge('2026-09-06T12:00:00Z', 'main');
    const te = walkScan(prCheckout(ue, 'same-line-pr'), { ...prEnv, PR_HEAD_SHA: eHead }, { TH_EMIT: '1' });
    const metFirst = te.walked.includes(eFork) && te.walked.indexOf(eFork) < te.walked.indexOf(eSide);
    check('(T-e) a key the change adds on the file and line of a pre-existing one met before it: BLOCKS, and the old one warns',
      metFirst && te.status === 1 && te.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && live(te, 'shared.live', eSide)
      && te.stdout.includes(`- ⚠️ shared.live:1 — 🔴 VERIFIED-LIVE Github in commit ${eFork.slice(0, 7)} — ROTATE NOW pre-existing in history`),
      JSON.stringify({ walked: te.walked, verdict: verdict(te) }));

    // (T-f) A push of an octopus merge: three branches at once, each dated before event.before, and
    // one branch commit that adds two keys (two findings, not one).
    const uf = upstream('octopus-push');
    const fFork = uf.commit('2026-09-07T10:00:00Z', 'fork.live');
    const fx = {};
    for (const [b, t] of [['a', '10:10'], ['b', '10:20'], ['c', '10:30']]) {
      uf.on('-b', b, fFork);
      if (b === 'a') { fs.writeFileSync(path.join(uf.dir, 'a2.live'), 'a2.live\n'); gitAt(uf.dir)('add', 'a2.live'); }
      fx[b] = uf.commit(`2026-09-07T${t}:00Z`, `${b}.live`);
    }
    uf.on('main');
    const fBefore = uf.commit('2026-09-07T12:00:00Z', 'before.live');
    const fAfter = uf.merge('2026-09-07T13:00:00Z', 'a', 'b', 'c');
    const fCtl = thIn(uf.dir, '--branch', fAfter, '--since-commit', fBefore);
    check("(T-f) control: v1.19.6's walk from a pushed octopus merge stops at event.before, before every branch",
      fCtl.status === 0 && sameSet(fCtl.walked, [fAfter]), JSON.stringify(fCtl));
    const tf = walkScan(uf.dir, { BASE_REF: '', GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: fBefore, PR_HEAD_SHA: '' }, { TH_EMIT: '1' });
    check('(T-f) an octopus merge: one walk per merged branch, every key reported, both of the commit that added two',
      tf.status === 1 && sameSet(tf.walked, [fAfter, fx.a, fx.b, fx.c]) && tf.argvs.length === 4 && tf.stdout.includes('\nBLOCKED — 4 critical finding(s). ')
      && live(tf, 'a.live', fx.a) && live(tf, 'a2.live', fx.a) && live(tf, 'b.live', fx.b) && live(tf, 'c.live', fx.c)
      && !/before\.live|fork\.live/.test(tf.stdout), JSON.stringify({ walked: tf.walked, argvs: tf.argvs, verdict: verdict(tf) }));

    // (T-g) Past a clock skew `git rev-list BASE..head` lists base commits as new: seven base commits
    // dated before everything on the head's side end its walk early. The fork, which the base holds,
    // is judged by ancestry instead, so the key a walk met there only warns.
    const ug = upstream('cutoff-up');
    ug.commit('2026-09-08T09:00:00Z', 'root.txt');
    const gFork = ug.commit('2026-09-08T10:00:00Z', 'fork.live');
    ug.on('-b', 'feature');
    ug.commit('2026-09-08T11:00:00Z', 'pr.txt');
    ug.on('main');
    for (let i = 1; i <= 7; i++) ug.commit(`2026-09-08T08:0${8 - i}:00Z`, `x${i}.txt`);
    ug.on('feature');
    const gHead = ug.merge('2026-09-08T12:00:00Z', 'main');
    const pg = prCheckout(ug, 'cutoff-pr');
    const listed = (gitAt(pg)('rev-list', `refs/remotes/origin/main..${gHead}`).stdout || '').split('\n');
    check("(T-g) control: git's own rev-list of the range lists the fork, which the base holds",
      listed.includes(gFork) && gitAt(pg)('merge-base', '--is-ancestor', gFork, 'refs/remotes/origin/main').status === 0, JSON.stringify(listed));
    const tg = walkScan(pg, { ...prEnv, PR_HEAD_SHA: gHead }, { TH_EMIT: '1' });
    check('(T-g) the key a walk met in that fork is judged by ancestry: a secrets-history WARN, never a block — PASS',
      tg.walked.includes(gFork) && tg.status === 0 && tg.stdout.includes('\nPASS — no critical findings.\n')
      && tg.stdout.includes(`- ⚠️ fork.live:1 — 🔴 VERIFIED-LIVE Github in commit ${gFork.slice(0, 7)} — ROTATE NOW pre-existing in history`), verdict(tg));

    // What could not look: planning the walks, the clone, one walk of several. Each FAULTs.
    // A git on PATH that runs `action` when its argv holds every one of `words`, and is the real git
    // otherwise (an ancestry check, --is-ancestor, always goes through).
    const realGit = (spawnSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).stdout || '').trim();
    let shims = 0;
    const gitShim = (words, action, passAncestry = true) => {
      const dir = path.join(tmp, `git-shim-${++shims}`);
      fs.mkdirSync(dir);
      const pass = `exec '${realGit}' "$@"`;
      const guards = [...(passAncestry ? [`case " $* " in *" --is-ancestor "*) ${pass} ;; esac`] : []), ...words.map((w) => `case " $* " in *" ${w} "*) ;; *) ${pass} ;; esac`)];
      fs.writeFileSync(path.join(dir, 'git'), `#!/bin/sh\n${guards.join('\n')}\n${action}\n`);
      fs.chmodSync(path.join(dir, 'git'), 0o755);
      return { PATH: `${dir}:${process.env.PATH}` };
    };
    const gitRefusing = (...words) => gitShim(words, `echo "fatal: ${words[0]} refused by the selftest" >&2; exit 128`);
    const trl = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, gitRefusing('rev-list'));
    check('(T) a range git cannot list: FAULT before trufflehog runs, naming the git call',
      trl.status === 1 && trl.argvs.length === 0
      && trl.stdout.includes(`- ❌ trufflehog verified-live secrets — git rev-list origin/main..${aHead.slice(0, 7)} failed, exit 128: fatal: rev-list refused by the selftest`), verdict(trl));
    const tcl = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, gitRefusing('clone'));
    check('(T) a checkout git cannot clone: FAULT before trufflehog runs, naming the clone',
      tcl.status === 1 && tcl.argvs.length === 0
      && tcl.stdout.includes('- ❌ trufflehog verified-live secrets — git clone of the checkout for trufflehog failed, exit 128: fatal: clone refused by the selftest'), verdict(tcl));
    const thFailsOnOne = stub('trufflehog-fails-on-one-walk', `case " $* " in *" --branch ${aMid} "*) exit 1 ;; esac\nexec '${thAsMeasured}' "$@"`);
    const tw = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, {}, thFailsOnOne);
    check('(T) one walk of several that cannot look: FAULT, naming that walk and its tip',
      tw.status === 1
      && tw.stdout.includes(`- ❌ trufflehog verified-live secrets — trufflehog walk 2 of 2, from ${aMid.slice(0, 7)}, exit 1 — its log is not quoted here, rerun trufflehog to read it`), verdict(tw));
    // The first walk fails after reporting: what it found stands, and the walk after it still runs.
    const thFailsAfterFirst = stub('trufflehog-fails-after-walk-1', `case " $* " in *" --branch ${aHead} "*) '${thAsMeasured}' "$@"; exit 1 ;; esac\nexec '${thAsMeasured}' "$@"`);
    const tw1 = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, { TH_EMIT: '1' }, thFailsAfterFirst);
    check('(T) a walk that fails keeps what it reported, and the walks after it run: BLOCKED on all three keys, the fault named',
      tw1.status === 1 && tw1.stdout.includes('\nBLOCKED — 3 critical finding(s). ') && live(tw1, 'pr-new.live', aHead) && live(tw1, 'pr-old.live', aOld)
      && tw1.stdout.includes(`- ❌ trufflehog verified-live secrets — trufflehog walk 1 of 2, from ${aHead.slice(0, 7)}, exit 1 — its log is not quoted here, rerun trufflehog to read it`), verdict(tw1));
    // A second tip whose base git cannot find, or a git killed while finding it: never a walk to the
    // root, which is kept for a tip that truly shares no commit with the base (T-d).
    const tmb = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, gitRefusing('merge-base', aMid));
    check("(T) a second tip git cannot find the base of: FAULT before trufflehog runs, naming that tip",
      tmb.status === 1 && tmb.argvs.length === 0
      && tmb.stdout.includes(`- ❌ trufflehog verified-live secrets — no commit to stop the walk at: git merge-base origin/main ${aMid.slice(0, 7)} failed, exit 128: fatal: merge-base refused by the selftest`), verdict(tmb));
    const tkill = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, gitShim(['merge-base', aMid], 'kill -9 $$'));
    check('(T) a git killed while finding a tip\'s base never answered: FAULT, not "they share no commit"',
      tkill.status === 1 && tkill.argvs.length === 0
      && tkill.stdout.includes(`- ❌ trufflehog verified-live secrets — no commit to stop the walk at: git merge-base origin/main ${aMid.slice(0, 7)} failed, killed by SIGKILL`), verdict(tkill));
    // Whether the base holds a finding's commit is asked of git; a git that cannot answer decides
    // nothing: the key blocks as new, and the leg could not look.
    const tanc = walkScan(ub.dir, { BASE_REF: '', GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: bBefore, PR_HEAD_SHA: '' },
      { TH_EMIT: '1', ...gitShim(['--is-ancestor'], 'echo "fatal: ancestry refused by the selftest" >&2; exit 128', false) });
    check("(T) a key whose commit's ancestry git cannot tell: BLOCKS as new, and the leg could not look, naming the check",
      tanc.status === 1 && tanc.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && live(tanc, 'topic.live', bTopic)
      && tanc.stdout.includes(`- ❌ trufflehog verified-live secrets — git merge-base --is-ancestor ${bTopic.slice(0, 7)} ${bBefore} failed, exit 128: fatal: ancestry refused by the selftest — so its key counts as new`), verdict(tanc));
    // A base that shares no commit with the head at all: the walk is not planned. Walked to its root,
    // all of history would sit under the blocking check.
    ud.on('--orphan', 'lonely');
    gitAt(ud.dir)('rm', '-rfq', '.');
    const lonely = ud.commit('2026-09-05T13:00:00Z', 'lonely.txt');
    ud.on('feature');
    const tdj = walkScan(ud.dir, { BASE_REF: lonely, GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: '', PR_HEAD_SHA: '' });
    check('(T) a base that shares no commit with the head: FAULT before trufflehog runs, never all of history',
      tdj.status === 1 && tdj.argvs.length === 0
      && tdj.stdout.includes(`- ❌ trufflehog verified-live secrets — no commit to stop the walk at: git merge-base ${lonely} ${dHead.slice(0, 7)} failed, they share no commit`), verdict(tdj));

    // ---- (V) gitleaks' range past a clock skew (v1.19.8) ----
    // gitleaks reads `git log -p` over `<base>..HEAD`, and past a clock skew git lists base commits in
    // that range (T-g): seven main commits dated before everything on the head's side end git's walk of
    // the base early, so the fork and the root, which the base holds, are listed as new. Until v1.19.8
    // a key already in the fork blocked as the change's own. Now whether the base holds a finding's
    // commit is asked of git (baseHolds), as for trufflehog's, and that key only warns. The gitleaks
    // stub is 8.30.1 as measured and as its source reads (sources/git.go, detect/detect.go): it runs
    // `git log -p -U0` with --log-opts split on spaces (with none, `--full-history --all
    // --diff-filter=tuxdb`), reports each added line holding a GLKEY with the file and line it has in
    // that commit, skips a finding an ignore file lists (--gitleaks-ignore-path, and the source's
    // .gitleaksignore; `<commit>:<file>:<rule>:<line>` or `<file>:<rule>:<line>`), and when its `git
    // log` dies it still exits 0 with `[]`.
    const glArgv = path.join(tmp, 'gitleaks-as-measured-argv.log');
    const glJs = path.join(tmp, 'gitleaks-as-measured.mjs');
    fs.writeFileSync(glJs, [
      "import { spawnSync } from 'node:child_process';",
      "import fs from 'node:fs';",
      'const argv = process.argv.slice(2);',
      "const opt = (n) => { const i = argv.indexOf(n); return i < 0 ? '' : argv[i + 1]; };",
      "if (process.env.GL_ARGV) fs.appendFileSync(process.env.GL_ARGV, JSON.stringify(argv) + '\\n');",
      "const logOpts = opt('--log-opts');",
      "const r = spawnSync('git', ['log', '-p', '-U0', ...(logOpts ? logOpts.split(' ') : ['--full-history', '--all', '--diff-filter=tuxdb'])], { encoding: 'utf8', maxBuffer: 1 << 26 });",
      'const found = [];',
      "let commit = '', file = '', line = 0;",
      "for (const l of r.status === 0 ? r.stdout.split('\\n') : []) {",
      '  let m;',
      '  if ((m = /^commit ([0-9a-f]{40})/.exec(l))) commit = m[1];',
      "  else if ((m = /^\\+\\+\\+ (?:b\\/(.*)|\\/dev\\/null)$/.exec(l))) file = m[1] || '';",
      '  else if ((m = /^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@/.exec(l))) line = +m[1];',
      "  else if (l[0] === '+') { for (const k of l.match(/GLKEY[0-9A-F]{30}/g) || []) found.push({ RuleID: 'generic-api-key', File: file, StartLine: line, EndLine: line, Commit: commit, Secret: k, Match: k, Line: l.slice(1) }); line++; }",
      '}',
      'const ignore = new Set();',
      "for (const f of [opt('--gitleaks-ignore-path'), '.gitleaksignore']) {",
      "  let t = ''; try { t = fs.readFileSync(f, 'utf8'); } catch { continue; }",
      "  for (const raw of t.split('\\n')) { const e = raw.trim(); if (e && !e.startsWith('#')) ignore.add(e); }",
      '}',
      "fs.writeFileSync(opt('--report-path'), JSON.stringify(found.filter((f) => !ignore.has([f.File, f.RuleID, f.StartLine].join(':')) && !ignore.has([f.Commit, f.File, f.RuleID, f.StartLine].join(':')))));",
    ].join('\n'));
    const glAsMeasured = stub('gitleaks-as-measured', `exec '${process.execPath}' '${glJs}' "$@"`);
    const keyFor = (tag) => (planted[tag] = mint('GLKEY'));   // a leak check covers each one
    const glOnce = (cwd, logOpts) => {
      const rep = path.join(tmp, 'gitleaks-once.json');
      fs.rmSync(rep, { force: true });
      spawnSync(glAsMeasured, ['detect', '--report-path', rep, '--log-opts', logOpts], { cwd, env: base, encoding: 'utf8' });
      return JSON.parse(fs.readFileSync(rep, 'utf8'));
    };
    const pushEnv = (before) => ({ BASE_REF: '', GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: before, PR_HEAD_SHA: '' });
    // The shape measured on git 2.54: main's root (09:00), then the fork (10:00), which adds a key; the
    // PR leaves main there with a commit of its own (11:00), with a key or without; main goes on with
    // seven commits dated 08:07 down to 08:01, each older than its parent; the PR merges main in (12:00).
    const cutoff = (name, prKey) => {
      const u = upstream(name);
      const k = { fork: keyFor(`${name}:fork`), pr: prKey ? keyFor(`${name}:pr`) : '' };
      const root = u.commit('2026-09-09T09:00:00Z', 'root.txt');
      const fork = u.commit('2026-09-09T10:00:00Z', 'fork.conf', `token=${k.fork}\n`);
      u.on('-b', 'feature');
      const pr = u.commit('2026-09-09T11:00:00Z', 'pr.conf', prKey ? `token=${k.pr}\n` : 'no key here\n');
      u.on('main');
      let x7 = '';
      for (let i = 1; i <= 7; i++) x7 = u.commit(`2026-09-09T08:0${8 - i}:00Z`, `x${i}.txt`);
      u.on('feature');
      return { u, dir: u.dir, k, root, fork, pr, x7, head: u.merge('2026-09-09T12:00:00Z', 'main') };
    };
    // One scan through the as-measured gitleaks, the other scanners clean: its argv per run, and the report.
    const glScan = (cwd, env, extra = {}) => {
      fs.rmSync(glArgv, { force: true });
      const res = broken({ GITLEAKS_BIN: glAsMeasured }, { GL_ARGV: glArgv, GITHUB_ACTIONS: 'true', ENABLE_SECRETS_HISTORY: 'false', ...env, ...extra }, cwd);
      return { ...res, glArgvs: fs.existsSync(glArgv) ? fs.readFileSync(glArgv, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [] };
    };
    const logOptsOf = (a) => (a.includes('--log-opts') ? a[a.indexOf('--log-opts') + 1] : '');
    const newKey = (file, k, sha) => `- ❌ ${file}:1 — generic-api-key ${redact(k)} in commit ${sha.slice(0, 7)} _(CWE-798)_`;
    const oldKey = (file, k, sha) => `- ⚠️ ${file}:1 — generic-api-key in history ${redact(k)} in commit ${sha.slice(0, 7)} — rotate at the provider, then scrub history _(CWE-798)_`;
    const heldNote = '\n- gitleaks: its range listed a commit the base already holds, as git does past a clock skew, so the finding there is pre-existing: secrets-history, not secret-pattern\n';
    const refuseAncestry = gitShim(['--is-ancestor'], 'echo "fatal: ancestry refused by the selftest" >&2; exit 128', false);

    // (V-a) A push of the PR branch onto main: event.before is main's seventh commit, HEAD the merge.
    const va = cutoff('gl-cutoff-push', true);
    const vaListed = (gitAt(va.dir)('rev-list', `${va.x7}..${va.head}`).stdout || '').split('\n').filter(Boolean);
    check("(V-a) control: git's rev-list of the range lists the fork and the root beside the PR's commits, though the base holds both",
      sameSet(vaListed, [va.head, va.pr, va.fork, va.root])
      && gitAt(va.dir)('merge-base', '--is-ancestor', va.fork, va.x7).status === 0 && gitAt(va.dir)('merge-base', '--is-ancestor', va.root, va.x7).status === 0,
      JSON.stringify({ listed: vaListed, fork: va.fork, root: va.root }));
    const vaRaw = glOnce(va.dir, `${va.x7}..HEAD`);
    check("(V-a) control: gitleaks' range reads the fork's key beside the PR's, and v1.19.7 blocked on both",
      sameSet(vaRaw.map((f) => `${f.File}@${f.Commit}`), [`fork.conf@${va.fork}`, `pr.conf@${va.pr}`]), JSON.stringify(vaRaw.map((f) => [f.File, f.Commit])));
    const tva = glScan(va.dir, pushEnv(va.x7));
    check("(V-a) the PR's key BLOCKS as secret-pattern; the fork's, which the base holds, is secrets-history, a WARN",
      tva.status === 1 && tva.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && tva.stdout.includes('### ❌ `secret-pattern` · T0 · 1 finding(s)')
      && tva.stdout.includes(newKey('pr.conf', va.k.pr, va.pr)) && tva.stdout.includes('### ⚠️ `secrets-history` · T2 · 1 finding(s)')
      && tva.stdout.includes(oldKey('fork.conf', va.k.fork, va.fork)) && !tva.stdout.includes('could not look'), verdict(tva));
    check("(V-a) one ::error, for the PR's key; none for the fork's",
      JSON.stringify(commands(tva.stdout)) === JSON.stringify([`::error file=pr.conf,line=1,title=security-baseline secret-pattern::secret-pattern generic-api-key at pr.conf:1 in commit ${va.pr.slice(0, 7)}`]),
      JSON.stringify(commands(tva.stdout)));
    check('(V-a) the report says why a finding of the range is history', tva.stdout.includes(heldNote), verdict(tva));
    check('(V-a) gitleaks still reads <base>..HEAD: ancestry grades what it found, not what it reads',
      tva.glArgvs.length === 1 && logOptsOf(tva.glArgvs[0]) === `${va.x7}..HEAD`, JSON.stringify(tva.glArgvs));
    check('(V-a) NO planted value reaches the job log or stderr', tva.stdout.length > 0 && !leaked(tva.stdout) && !leaked(tva.stderr));
    const tvaH = glScan(va.dir, pushEnv(va.x7), { ENABLE_SECRETS_HISTORY: 'true' });
    check("(V-a) with the history baseline on, the fork's key is reported once, as the range's WARN, and the verdict stands",
      tvaH.status === 1 && tvaH.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && tvaH.glArgvs.length === 2
      && tvaH.stdout.split(oldKey('fork.conf', va.k.fork, va.fork)).length === 2 && tvaH.stdout.split('fork.conf:').length === 2, verdict(tvaH));

    // (V-b) The same range on a pull_request run: GitHub's test merge of the PR into main, detached, and
    // origin/main, main's seventh commit, for a base.
    const pvb = prCheckout(va.u, 'gl-cutoff-pr');
    const vbListed = (gitAt(pvb)('rev-list', 'refs/remotes/origin/main..HEAD').stdout || '').split('\n').filter(Boolean);
    const tvb = glScan(pvb, { ...prEnv, PR_HEAD_SHA: va.head });
    check("(V-b) a pull_request run lists the fork in its range too: the fork's key warns, the PR's BLOCKS",
      vbListed.includes(va.fork) && tvb.status === 1 && tvb.stdout.includes('\nBLOCKED — 1 critical finding(s). ')
      && tvb.stdout.includes(newKey('pr.conf', va.k.pr, va.pr)) && tvb.stdout.includes(oldKey('fork.conf', va.k.fork, va.fork))
      && tvb.stdout.includes(heldNote) && !tvb.stdout.includes('could not look'), JSON.stringify({ listed: vbListed, verdict: verdict(tvb) }));

    // (V-c) The contract a blocking check keeps: a range whose only key the base already holds passes.
    const vc = cutoff('gl-cutoff-clean', false);
    const tvc = glScan(vc.dir, pushEnv(vc.x7));
    check('(V-c) a range whose only key the base already holds: PASS, exit 0, no annotation; the key a WARN',
      tvc.status === 0 && tvc.stdout.includes('\nPASS — no critical findings.\n') && !tvc.stdout.includes('`secret-pattern`')
      && tvc.stdout.includes(oldKey('fork.conf', vc.k.fork, vc.fork)) && commands(tvc.stdout).length === 0, verdict(tvc));

    // (V-d) A git that cannot say whether the base holds a finding's commit decides nothing: the key
    // blocks as new, the fork's too, and the leg could not look, naming the check.
    const tvd = glScan(va.dir, pushEnv(va.x7), refuseAncestry);
    check("(V-d) keys whose commits' ancestry git cannot tell: both BLOCK as new, and the gitleaks leg could not look, naming the check",
      tvd.status === 1 && tvd.stdout.includes('\nBLOCKED — 2 critical finding(s). ') && tvd.stdout.includes(newKey('fork.conf', va.k.fork, va.fork))
      && tvd.stdout.includes(newKey('pr.conf', va.k.pr, va.pr)) && !tvd.stdout.includes('`secrets-history`')
      && tvd.stdout.includes(`\n- ❌ gitleaks secret scan — git merge-base --is-ancestor ${va.pr.slice(0, 7)} ${va.x7} failed, exit 128: fatal: ancestry refused by the selftest — so its key counts as new\n`)
      && tvd.stdout.includes('could not look (gitleaks secret scan), so the list above may be incomplete.'), verdict(tvd));

    // (V-e) scan-scope: full has no base to ask about: every key in history is graded as before, and git
    // is asked nothing (a git that refuses to answer changes nothing).
    const tve = glScan(va.dir, { ...pushEnv(va.x7), SCAN_SCOPE: 'full' }, refuseAncestry);
    check('(V-e) scan-scope: full reads history with no range and asks no ancestry: both keys secret-pattern, as before',
      tve.status === 1 && tve.stdout.includes('\nBLOCKED — 2 critical finding(s). ') && tve.stdout.includes(newKey('fork.conf', va.k.fork, va.fork))
      && tve.stdout.includes(newKey('pr.conf', va.k.pr, va.pr)) && !tve.stdout.includes('could not look')
      && tve.glArgvs.length === 1 && logOptsOf(tve.glArgvs[0]) === '', JSON.stringify({ argvs: tve.glArgvs, verdict: verdict(tve) }));

    // ---- (U) what a merge commit adds (v1.20.0) ----
    // `git log -p` prints no patch for a merge, and both legs read commits through it, so a key only a
    // merge adds (a conflict resolution, an edit made while merging) was read by neither. It reuses (V)'s
    // gitleaks stub, 8.30.1 as measured: it reads `git log -p -U0` per --log-opts, honours the ignore
    // files, and exits 0 with `[]` when its `git log` dies.
    const repoAt = (name) => { const dir = path.join(tmp, name); fs.mkdirSync(dir); gitAt(dir)('init', '-q', '-b', 'main'); return dir; };
    const commitFiles = (dir, iso, files, msg) => {
      for (const [f, text] of Object.entries(files)) { fs.writeFileSync(path.join(dir, f), text); gitAt(dir)('add', f); }
      gitAt(dir, iso)('commit', '-q', '-m', msg);
      return shaIn(dir, 'HEAD');
    };
    // One scan through both as-measured stubs: gitleaks' argv per run (and its --log-opts), trufflehog's walks.
    const mergeScan = (cwd, env, extra = {}, bin = thAsMeasured) => {
      fs.rmSync(glArgv, { force: true });
      const res = walkScan(cwd, env, { GITLEAKS_BIN: glAsMeasured, GL_ARGV: glArgv, TH_EMIT: '1', ENABLE_SECRETS_HISTORY: 'false', ...extra }, bin);
      const glArgvs = fs.existsSync(glArgv) ? fs.readFileSync(glArgv, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
      return { ...res, glArgvs, logOpts: glArgvs.map((a) => (a.includes('--log-opts') ? a[a.indexOf('--log-opts') + 1] : '')) };
    };
    // The pass commit as specified, computed here in a clone of the fixture (the checkout stays as it
    // was): the merge's tree over git's own merge of its parents (an octopus one head at a time), both
    // by a fixed author and committer at a fixed date, so the same merge gives the same commit each run.
    const passId = {
      GIT_AUTHOR_NAME: 'security-baseline', GIT_AUTHOR_EMAIL: 'security-baseline@invalid', GIT_AUTHOR_DATE: '@0 +0000',
      GIT_COMMITTER_NAME: 'security-baseline', GIT_COMMITTER_EMAIL: 'security-baseline@invalid', GIT_COMMITTER_DATE: '@0 +0000',
    };
    const passOf = (dir, merge) => {
      const ref = fs.mkdtempSync(path.join(tmp, 'pass-reference-'));
      spawnSync('git', ['clone', '-q', '--no-checkout', `file://${dir}`, path.join(ref, 'c')], { env: base });
      const g = (...a) => (spawnSync('git', a, { cwd: path.join(ref, 'c'), env: { ...base, ...passId }, encoding: 'utf8' }).stdout || '').trim();
      const [, ...ps] = g('rev-list', '--parents', '-n1', merge).split(' ');
      let at = ps[0], tree = '';
      for (let i = 1; i < ps.length; i++) {
        tree = g('merge-tree', '--write-tree', '--no-messages', '--allow-unrelated-histories', at, ps[i]).split('\n')[0];
        if (i < ps.length - 1) at = g('commit-tree', '--no-gpg-sign', tree, '-p', at, '-p', ps[i], '-m', `security-baseline: octopus step of ${merge}`);
      }
      const since = g('commit-tree', '--no-gpg-sign', tree, '-m', `security-baseline: git's own merge of ${merge}'s parents`);
      const tip = g('commit-tree', '--no-gpg-sign', `${merge}^{tree}`, '-p', since, '-m', `security-baseline: what ${merge} adds`);
      fs.rmSync(ref, { recursive: true, force: true });
      return `${tip} ^${since}`;
    };
    const glLine = (file, line, k, where) => `- ❌ ${file}:${line} — generic-api-key ${redact(k)} ${where} _(CWE-798)_`;
    const thLine = (file, where) => `- ❌ ${file}:1 — 🔴 VERIFIED-LIVE Github ${where} — ROTATE NOW _(CWE-798)_`;
    const byMerge = (sha) => `in merge ${sha.slice(0, 7)}'s own changes`;

    // (U-a) A push of a merge onto main. The merge resolves a conflict keeping main's key, which
    // predates the range, adds a key of its own to the resolution, and adds a file neither side had;
    // topic's commit adds a key too (the control both scanners always read).
    const ma = repoAt('merge-adds-push');
    const kCtl = keyFor('mCtl'), kPre = keyFor('mPre'), kRes = keyFor('mRes'), kEvil = keyFor('mEvil');
    commitFiles(ma, '2026-09-06T10:00:00Z', { 'conf.txt': 'a\nshared=base\nz\n' }, 'fork');
    gitAt(ma)('checkout', '-q', '-b', 'topic');
    const maCtl = commitFiles(ma, '2026-09-06T11:00:00Z', { 'control.live': `control=${kCtl}\n`, 'conf.txt': 'a\nshared=topic\nz\n' }, 'topic: a key, and its side of conf.txt');
    gitAt(ma)('checkout', '-q', 'main');
    const maBefore = commitFiles(ma, '2026-09-06T12:00:00Z', { 'conf.txt': `a\nshared=${kPre}\nz\n` }, 'main: a key that predates the range');
    gitAt(ma, '2026-09-06T13:00:00Z')('merge', '-q', '--no-ff', '--no-commit', 'topic');
    const maMerge = commitFiles(ma, '2026-09-06T13:00:00Z', { 'conf.txt': `a\nshared=${kPre}\nresolved=${kRes}\nz\n`, 'evil.live': `evil=${kEvil}\n` }, 'merge topic: keep main, add a key, and a file neither side had');
    const maRemerge = gitAt(ma)('show', '--remerge-diff', '--format=', '-U0', maMerge).stdout || '';
    check("(U-a) the fixture: a merge whose own changes add two keys, a conflict resolution's and a new file's, and keep main's, which predates the range",
      shaIn(ma, `${maMerge}^1`) === maBefore && shaIn(ma, `${maMerge}^2`) === maCtl
      && maRemerge.includes(`+resolved=${kRes}`) && maRemerge.includes(`+evil=${kEvil}`) && !maRemerge.includes(`+shared=${kPre}`), maRemerge);
    const maV1197 = glOnce(ma, `${maBefore}..HEAD`);
    check("(U-a) control: v1.19.7's gitleaks range, <base>..HEAD, reads topic's key and neither of the merge's",
      maV1197.length === 1 && maV1197[0].Commit === maCtl && maV1197[0].File === 'control.live', JSON.stringify(maV1197.map((f) => [f.File, f.StartLine, f.Commit])));
    const uma = mergeScan(ma, pushEnv(maBefore));
    const [maTip, maSince] = (uma.logOpts[1] || '').split(' ').map((s) => s.replace(/^\^/, ''));
    check("(U-a) gitleaks reads the range as before, then, in a run of its own, the pass commit with its parent excluded: the merge's tree over git's own merge of its parents",
      uma.logOpts.length === 2 && uma.logOpts[0] === `${maBefore}..HEAD` && uma.logOpts[1] === passOf(ma, maMerge)
      && ![maMerge, maBefore, maCtl].includes(maTip), JSON.stringify({ logOpts: uma.logOpts, want: passOf(ma, maMerge) }));
    check("(U-a) BLOCKED on the merge's two keys and topic's, each named where it was added; main's, which predates the range, never reaches the report",
      uma.status === 1 && uma.stdout.includes('\nBLOCKED — 5 critical finding(s). ') && uma.stdout.includes('### ❌ `secret-pattern` · T0 · 3 finding(s)')
      && uma.stdout.includes(glLine('conf.txt', 3, kRes, byMerge(maMerge))) && uma.stdout.includes(glLine('evil.live', 1, kEvil, byMerge(maMerge)))
      && uma.stdout.includes(glLine('control.live', 1, kCtl, `in commit ${maCtl.slice(0, 7)}`)) && !uma.stdout.includes(redact(kPre))
      && !uma.stdout.includes('could not look'), verdict(uma));
    check("(U-a) trufflehog walks that same commit from that same parent, and what it finds there is the merge's: secret-verified, never demoted to history",
      uma.argvs.length === 3 && new RegExp(` --branch ${maTip} --since-commit ${maSince}$`).test(uma.argvs[2])
      && uma.stdout.includes('### ❌ `secret-verified` · T0 · 2 finding(s)') && uma.stdout.includes(thLine('evil.live', byMerge(maMerge)))
      && !uma.stdout.includes('`secrets-history`'), JSON.stringify({ argvs: uma.argvs, verdict: verdict(uma) }));
    check('(U-a) the report says the merge adds lines of its own, and how they were read',
      uma.stdout.includes("\n- merges: the range holds 1 merge; it adds lines of its own, a conflict resolution or an edit made while merging, read as one commit from git's own merge of the parents to the merge\n"), verdict(uma));
    check("(U-a) the pass writes nothing to the checkout: its commit is in no object store of it", gitAt(ma)('cat-file', '-e', `${maTip}^{commit}`).status !== 0, maTip);
    check('(U-a) NO planted value reaches the job log or stderr', uma.stdout.length > 0 && !leaked(uma.stdout) && !leaked(uma.stderr));
    const umaOff = mergeScan(ma, pushEnv(maBefore), { VERIFIED_SECRETS: 'off' });
    check('(U-a) verified-secrets: off: gitleaks reads what the merge adds all the same, from the same commit (fixed author, committer and dates)',
      umaOff.status === 1 && umaOff.argvs.length === 0 && umaOff.logOpts[1] === uma.logOpts[1]
      && umaOff.stdout.includes(glLine('conf.txt', 3, kRes, byMerge(maMerge))) && umaOff.stdout.includes(glLine('evil.live', 1, kEvil, byMerge(maMerge))), verdict(umaOff));

    // (U-b) The fleet's only ignore form pins a line to the commit that added it: for a merge's own
    // line, the merge. gitleaks reads that line in the pass's commit, so the entry is handed over again.
    fs.writeFileSync(path.join(ma, '.gitleaksignore'), `# the resolution's line, pinned to the merge\n  ${maMerge}:conf.txt:generic-api-key:3  \n`);
    const umb = mergeScan(ma, pushEnv(maBefore), { VERIFIED_SECRETS: 'off' });
    fs.writeFileSync(path.join(ma, '.gitleaksignore'), `${maBefore}:conf.txt:generic-api-key:3\n`);
    const umbCtl = mergeScan(ma, pushEnv(maBefore), { VERIFIED_SECRETS: 'off' });
    fs.rmSync(path.join(ma, '.gitleaksignore'));
    check('(U-b) a .gitleaksignore entry pinned to the merge silences exactly that line of what the merge adds',
      umb.status === 1 && !umb.stdout.includes(redact(kRes)) && umb.stdout.includes(glLine('evil.live', 1, kEvil, byMerge(maMerge)))
      && umb.stdout.includes(glLine('control.live', 1, kCtl, `in commit ${maCtl.slice(0, 7)}`)), verdict(umb));
    check('(U-b) control: the same entry pinned to another commit silences nothing', umbCtl.stdout.includes(glLine('conf.txt', 3, kRes, byMerge(maMerge))), verdict(umbCtl));

    // (U-c) A merge that adds nothing git's own merge lacks: v1.19.7's runs, and a note.
    const mc = repoAt('merge-adds-nothing');
    commitFiles(mc, '2026-09-07T10:00:00Z', { 'a.txt': 'a\n' }, 'fork');
    gitAt(mc)('checkout', '-q', '-b', 'topic');
    commitFiles(mc, '2026-09-07T11:00:00Z', { 'topic.txt': 'topic\n' }, 'topic');
    gitAt(mc)('checkout', '-q', 'main');
    const mcBefore = commitFiles(mc, '2026-09-07T12:00:00Z', { 'b.txt': 'b\n' }, 'main');
    gitAt(mc, '2026-09-07T13:00:00Z')('merge', '-q', '--no-ff', '--no-edit', 'topic');
    const umc = mergeScan(mc, pushEnv(mcBefore));
    check("(U-c) a merge that adds nothing: no pass commit, gitleaks' one run and trufflehog's walks as before — PASS",
      umc.status === 0 && JSON.stringify(umc.logOpts) === JSON.stringify([`${mcBefore}..HEAD`]) && umc.argvs.length === 2 && !umc.stdout.includes('could not look')
      && umc.stdout.includes("\n- merges: the range holds 1 merge, and it adds nothing to git's own merge of its parents\n"), JSON.stringify({ logOpts: umc.logOpts, argvs: umc.argvs, verdict: verdict(umc) }));

    // (U-d) An octopus merge that adds a file no head had: merged again one head at a time.
    const mo = repoAt('merge-adds-octopus');
    const kOct = keyFor('mOct'), kO2 = keyFor('mO2');
    commitFiles(mo, '2026-09-08T10:00:00Z', { 'a.txt': 'a\n' }, 'fork');
    const moHeads = {};
    for (const b of ['o1', 'o2']) { gitAt(mo)('checkout', '-q', '-b', b, 'main'); moHeads[b] = commitFiles(mo, '2026-09-08T11:00:00Z', { [`${b}.txt`]: b === 'o2' ? `o2=${kO2}\n` : `${b}\n` }, b); }
    gitAt(mo)('checkout', '-q', 'main');
    const moBefore = commitFiles(mo, '2026-09-08T12:00:00Z', { 'b.txt': 'b\n' }, 'main');
    gitAt(mo, '2026-09-08T13:00:00Z')('merge', '-q', '--no-commit', 'o1', 'o2');
    const moMerge = commitFiles(mo, '2026-09-08T13:00:00Z', { 'octo.live': `octo=${kOct}\n` }, 'octopus, and a file no head had');
    const tmo = mergeScan(mo, pushEnv(moBefore));
    check('(U-d) an octopus merge: what it adds is read by both legs, and named as its own',
      (gitAt(mo)('rev-list', '--parents', '-n1', moMerge).stdout || '').trim().split(' ').length === 4
      && tmo.stdout.includes(glLine('octo.live', 1, kOct, byMerge(moMerge))) && tmo.stdout.includes(thLine('octo.live', byMerge(moMerge)))
      && !tmo.stdout.includes('could not look'), verdict(tmo));
    check("(U-d) its last head's key is read once, in that head's commit, never again as the octopus's own",
      tmo.logOpts[1] === passOf(mo, moMerge) && tmo.stdout.split('\n').filter((l) => l.includes(redact(kO2))).length === 1
      && tmo.stdout.includes(glLine('o2.txt', 1, kO2, `in commit ${moHeads.o2.slice(0, 7)}`)), JSON.stringify({ logOpts: tmo.logOpts, verdict: verdict(tmo) }));

    // (U-e) A PR that merged its base in, resolving a conflict with a key of its own. GitHub's test
    // merge here is not git's own merge (it carries a file neither side had), as one GitHub computed
    // differently would be: it is never merged again, since its lines would be read as the merge's.
    const mu = repoAt('merge-adds-pr-up');
    const kPrRes = keyFor('mPrRes'), kGh = keyFor('mGh');
    commitFiles(mu, '2026-09-09T10:00:00Z', { 'conf.txt': 'a\nshared=base\nz\n' }, 'fork');
    gitAt(mu)('checkout', '-q', '-b', 'feature');
    commitFiles(mu, '2026-09-09T11:00:00Z', { 'conf.txt': 'a\nshared=feature\nz\n' }, 'feature: its side');
    gitAt(mu)('checkout', '-q', 'main');
    commitFiles(mu, '2026-09-09T12:00:00Z', { 'conf.txt': 'a\nshared=main\nz\n' }, 'main: its side');
    gitAt(mu)('checkout', '-q', 'feature');
    gitAt(mu, '2026-09-09T13:00:00Z')('merge', '-q', '--no-commit', 'main');
    const prMerge = commitFiles(mu, '2026-09-09T13:00:00Z', { 'conf.txt': `a\nshared=main\nresolved=${kPrRes}\nz\n` }, 'merge main into feature: resolve, and add a key');
    const pe = path.join(tmp, 'merge-adds-pr');
    fs.mkdirSync(pe);
    gitAt(pe)('init', '-q');
    gitAt(pe)('fetch', '-q', '--no-tags', mu, '+refs/heads/*:refs/remotes/origin/*');
    gitAt(pe)('checkout', '-q', '--detach', 'refs/remotes/origin/main');
    gitAt(pe, '2026-09-09T14:00:00Z')('merge', '-q', '--no-ff', '--no-commit', 'refs/remotes/origin/feature');
    const ghMerge = commitFiles(pe, '2026-09-09T14:00:00Z', { 'github.live': `github=${kGh}\n` }, 'Merge feature into main');
    gitAt(pe)('update-ref', 'refs/remotes/pull/1/merge', 'HEAD');
    gitAt(pe)('checkout', '-q', '--detach', 'refs/remotes/pull/1/merge');
    const prMergeEnv = { BASE_REF: '', GITHUB_BASE_REF: 'main', GITHUB_EVENT_BEFORE: '' };
    const ume = mergeScan(pe, { ...prMergeEnv, PR_HEAD_SHA: prMerge });
    check("(U-e) a PR that merged its base in: what the PR's merge adds is read, and named as it; the range ends at the PR head, so GitHub's test merge is never read",
      shaIn(pe, 'HEAD') === ghMerge && ume.stdout.includes(glLine('conf.txt', 3, kPrRes, byMerge(prMerge))) && !ume.stdout.includes('could not look')
      && !ume.stdout.includes(redact(kGh)) && !ume.stdout.includes('github.live'), verdict(ume));
    const umeGh = mergeScan(pe, { ...prMergeEnv, PR_HEAD_SHA: shaOf('a PR head this checkout never fetched') });
    check("(U-e) walked from GitHub's test merge, the PR's merge is read still, and GitHub's own file never is",
      umeGh.stdout.includes(glLine('conf.txt', 3, kPrRes, byMerge(prMerge))) && !umeGh.stdout.includes(redact(kGh)) && !umeGh.stdout.includes('github.live')
      && !umeGh.stdout.includes('could not look'), verdict(umeGh));

    // (U-f) What could not look. Each is a FAULT on the leg it blinds, never a PASS.
    const umf = mergeScan(ma, pushEnv(maBefore), gitRefusing('merge-tree'));
    check('(U-f) a merge git cannot merge again: FAULT on both secret legs, naming the merge and the git call',
      umf.status === 1
      && umf.stdout.includes(`- ❌ gitleaks secret scan — what the range's merge adds could not be read: git merge-tree for merge ${maMerge.slice(0, 7)} failed, exit 128: fatal: merge-tree refused by the selftest\n`)
      && umf.stdout.includes(`- ❌ trufflehog verified-live secrets — what the range's merge adds could not be read: git merge-tree for merge ${maMerge.slice(0, 7)} failed, exit 128: fatal: merge-tree refused by the selftest\n`), verdict(umf));
    const umf2 = mergeScan(ma, pushEnv(maBefore), gitRefusing('commit-tree'));
    check("(U-f) a pass commit git cannot write: FAULT, naming the git call",
      umf2.status === 1 && umf2.stdout.includes("- ❌ gitleaks secret scan — what the range's merge adds could not be read: git commit-tree failed, exit 128: fatal: commit-tree refused by the selftest\n"), verdict(umf2));
    // trufflehog exits 0 having read nothing when its `git log` dies (3.95.6): the clone's log runs first.
    const umf3 = mergeScan(ma, pushEnv(maBefore), gitRefusing('log'));
    check("(U-f) a pass commit whose log git cannot print in the clone: FAULT on trufflehog's leg too, never a walk that read nothing",
      umf3.status === 1 && umf3.stdout.includes("- ❌ trufflehog verified-live secrets — what the range's merge adds could not be read: git log of the pass's commits failed, exit 128: fatal: log refused by the selftest\n"), verdict(umf3));
    // …and gitleaks exits 0 with `[]` when its `git log` dies (8.30.1): a checkout whose git cannot
    // see the clone's objects must fault, not pass.
    const noAlt = path.join(tmp, 'git-without-alternates');
    fs.mkdirSync(noAlt);
    fs.writeFileSync(path.join(noAlt, 'git'), `#!/bin/sh\nunset GIT_ALTERNATE_OBJECT_DIRECTORIES\nexec '${realGit}' "$@"\n`);
    fs.chmodSync(path.join(noAlt, 'git'), 0o755);
    const umf4 = mergeScan(ma, pushEnv(maBefore), { PATH: `${noAlt}:${process.env.PATH}`, VERIFIED_SECRETS: 'off' });
    check("(U-f) a pass commit the checkout's git cannot read: FAULT, never the empty PASS gitleaks itself would give",
      umf4.status === 1 && umf4.stdout.includes("- ❌ gitleaks secret scan — what the range's merges add could not be read by gitleaks: git log of the pass's commits failed, exit 128: fatal: bad object ")
      && umf4.glArgvs.length === 1, verdict(umf4));
    const glFailsOnPass = stub('gitleaks-fails-on-the-pass', `case "$*" in *" ^"*) echo 'fatal: pass run refused by the selftest' >&2; exit 1 ;; esac\nexec '${glAsMeasured}' "$@"`);
    const umf6 = mergeScan(ma, pushEnv(maBefore), { GITLEAKS_BIN: glFailsOnPass, VERIFIED_SECRETS: 'off' });
    check("(U-f) gitleaks failing on the pass's run alone: FAULT, naming that run, and the range's own run still reported",
      umf6.status === 1 && umf6.stdout.includes("- ❌ gitleaks secret scan — gitleaks, on what the range's merges add, exit 1: fatal: pass run refused by the selftest\n")
      && umf6.stdout.includes(glLine('control.live', 1, kCtl, `in commit ${maCtl.slice(0, 7)}`)), verdict(umf6));
    const thFailsOnPass = stub('trufflehog-fails-on-the-pass', `case " $* " in *" --branch ${maTip} "*) exit 1 ;; esac\nexec '${thAsMeasured}' "$@"`);
    const umf5 = mergeScan(ma, pushEnv(maBefore), {}, thFailsOnPass);
    check("(U-f) the pass's walk that cannot look: FAULT, naming the merge whose changes it walks",
      umf5.status === 1 && umf5.stdout.includes(`- ❌ trufflehog verified-live secrets — trufflehog walk 3 of 3, of what merge ${maMerge.slice(0, 7)} adds, exit 1 — its log is not quoted here, rerun trufflehog to read it\n`), verdict(umf5));

    // (U-g) A scan that inherits an alternate object directory, one that already holds git's own merge
    // of the parents (as any checkout that merged them itself would). trufflehog walks only what the
    // clone holds, like 3.95.6, which reads no alternate: were git pointed at that directory for the
    // clone or the pass, it would leave there what the clone lacks, and the walk would read nothing.
    const alt = path.join(ma, '.git', 'objects');
    gitAt(ma)('merge-tree', '--write-tree', '--no-messages', '--allow-unrelated-histories', maBefore, maCtl);
    const thOwnObjects = stub('trufflehog-own-objects-only', `unset GIT_ALTERNATE_OBJECT_DIRECTORIES\nexec '${thAsMeasured}' "$@"`);
    const umg = mergeScan(ma, pushEnv(maBefore), { GIT_ALTERNATE_OBJECT_DIRECTORIES: alt }, thOwnObjects);
    check('(U-g) an inherited alternate object directory: the pass still walks what the merge adds, from the clone alone',
      umg.status === 1 && umg.stdout.includes(thLine('evil.live', byMerge(maMerge))) && umg.stdout.includes(glLine('evil.live', 1, kEvil, byMerge(maMerge)))
      && !umg.stdout.includes('could not look'), verdict(umg));

    // (U-h) A merge the base already holds, which `git rev-list <base>..<head>` lists past a clock skew:
    // the fork point is a merge that added a key of its own, and seven base commits after it are dated
    // before it (measured on git 2.54: five are not enough). What it added is pre-existing, never read.
    const mh = repoAt('merge-held-by-the-base');
    const kFork = keyFor('mFork');
    commitFiles(mh, '2026-09-10T10:00:00Z', { 'a.txt': 'a\n' }, 'root');
    gitAt(mh)('checkout', '-q', '-b', 'side');
    commitFiles(mh, '2026-09-10T10:30:00Z', { 's.txt': 's\n' }, 'side');
    gitAt(mh)('checkout', '-q', 'main');
    commitFiles(mh, '2026-09-10T10:40:00Z', { 'm.txt': 'm\n' }, 'main');
    gitAt(mh, '2026-09-10T11:00:00Z')('merge', '-q', '--no-ff', '--no-commit', 'side');
    const mhFork = commitFiles(mh, '2026-09-10T11:00:00Z', { 'own.txt': `forkkey=${kFork}\n` }, 'the fork: a merge that adds a key of its own');
    gitAt(mh)('checkout', '-q', '-b', 'feature');
    const mhHead = commitFiles(mh, '2026-09-10T12:00:00Z', { 'f.txt': 'f\n' }, 'feature');
    gitAt(mh)('checkout', '-q', 'main');
    for (let i = 1; i <= 7; i++) commitFiles(mh, `2026-09-10T09:0${i}:00Z`, { [`b${i}.txt`]: `${i}\n` }, `base ${i}, dated before the fork`);
    const mhBase = shaIn(mh, 'HEAD');
    gitAt(mh)('checkout', '-q', 'feature');
    check('(U-h) control: past the skew, `git rev-list <base>..<head>` lists the fork, a merge the base holds',
      (gitAt(mh)('rev-list', `${mhBase}..${mhHead}`).stdout || '').split('\n').includes(mhFork) && gitAt(mh)('merge-base', '--is-ancestor', mhFork, mhBase).status === 0);
    const umh = mergeScan(mh, { BASE_REF: mhBase, GITHUB_BASE_REF: '', GITHUB_EVENT_BEFORE: '', PR_HEAD_SHA: '' });
    check('(U-h) a merge the base holds is not merged again: what it added is pre-existing and never read — PASS, one gitleaks run',
      umh.status === 0 && umh.stdout.includes('\nPASS — no critical findings.\n') && umh.logOpts.length === 1 && !umh.stdout.includes(redact(kFork))
      && !umh.stdout.includes('own.txt') && !umh.stdout.includes('- merges:'), JSON.stringify({ logOpts: umh.logOpts, verdict: verdict(umh) }));

    // ---- (W) a range whose own `git log` dies (v1.20.1) ----
    // Both scanners read the range through a `git log -p` of their own and exit 0 having read nothing
    // when it dies on an object the repository lacks: gitleaks 8.30.1 with `[]`, trufflehog 3.95.6 with
    // no result, under --fail-on-scan-errors too. The gitleaks stub above behaves so, and so does the
    // trufflehog stub below. Here the range's middle commit adds a blob that later leaves the object
    // store: the changed-file list reads the range's two ends and never it, and the head's own patch,
    // which also adds a key, needs it first.
    const wr = repoAt('log-dies');
    const kW = keyFor('wKey');
    const wBase = commitFiles(wr, '2026-09-11T10:00:00Z', { 'a.txt': 'base\n' }, 'base');
    const wMid = commitFiles(wr, '2026-09-11T11:00:00Z', { 'b.txt': 'b1\n' }, 'the range: b.txt');
    const wHead = commitFiles(wr, '2026-09-11T12:00:00Z', { 'b.txt': 'b2\n', 'v.live': `key=${kW}\n` }, 'the range: b.txt again, and a key');
    const wBlob = shaIn(wr, `${wMid}:b.txt`);
    const looseOf = (dir, sha) => path.join(dir, '.git', 'objects', sha.slice(0, 2), sha.slice(2));
    // A git that, once it has cloned, takes one object out of the clone: what goes wrong in the clone
    // itself, after cloning read every object of the checkout. A clone's objects arrive packed, so they
    // are unpacked loose first.
    const gitDamagingClones = (sha) => gitShim(['clone'], [
      `'${realGit}' "$@" || exit $?`,
      'for d in "$@"; do :; done',
      `for p in "$d"/.git/objects/pack/*.pack; do mv "$p" "$p.x" && rm -f "\${p%.pack}.idx" && '${realGit}' -C "$d" unpack-objects -q < "$p.x" && rm -f "$p.x"; done`,
      `rm -f "$d/.git/objects/${sha.slice(0, 2)}/${sha.slice(2)}"`,
    ].join('\n'));
    // trufflehog 3.95.6 on a log that dies in the range: it runs `git log` as it does (TRUFFLEHOG_LOG in
    // scan.mjs) in the repository it is given, with GIT_DIR its only variable, and when git dies it
    // exits 0 having walked nothing (measured: `chunks: 0`). On a log git finishes it is the stub above.
    const thLogDies = stub('trufflehog-log-dies', [
      'uri=""; branch=""; since=""; prev=""',
      'for a in "$@"; do case "$prev" in --branch) branch="$a" ;; --since-commit) since="$a" ;; esac; case "$a" in file://*) uri="${a#file://}" ;; esac; prev="$a"; done',
      'filter=""; [ -n "$since" ] || filter="--diff-filter=AM"',
      `env -i GIT_DIR="$uri/.git" '${realGit}' -C "$uri" log --patch --full-history --date=iso-strict --pretty=fuller --notes $filter "$branch" > /dev/null 2>&1 || { printf '%s\\n' "$*" >> '${realArgv}'; exit 0; }`,
      `exec '${thAsMeasured}' "$@"`,
    ].join('\n'));
    const wDamaged = path.join(tmp, 'log-dies-clone');
    gitAt(tmp)('clone', '-q', '--no-checkout', `file://${wr}`, wDamaged);
    for (const p of fs.readdirSync(path.join(wDamaged, '.git', 'objects', 'pack')).filter((f) => f.endsWith('.pack'))) {
      const pack = path.join(wDamaged, '.git', 'objects', 'pack', p);
      fs.renameSync(pack, `${pack}.x`);
      fs.rmSync(pack.replace(/\.pack$/, '.idx'), { force: true });
      spawnSync(realGit, ['-C', wDamaged, 'unpack-objects', '-q'], { input: fs.readFileSync(`${pack}.x`), env: base });
      fs.rmSync(`${pack}.x`);
    }
    fs.rmSync(looseOf(wDamaged, wBlob));
    fs.rmSync(walkLog, { force: true });
    const wCtl = spawnSync(thLogDies, ['git', `file://${wDamaged}`, '--trust-local-git-config', '--only-verified', '--json', '--fail-on-scan-errors', '--branch', wHead, '--since-commit', wBase],
      { env: { ...base, TH_EMIT: '1' }, encoding: 'utf8' });
    check('(W) control: trufflehog, as measured, on a repository that lacks a range object: exit 0, nothing walked, no result',
      wCtl.status === 0 && wCtl.stdout === '' && (walked() || []).length === 0, JSON.stringify({ status: wCtl.status, stdout: wCtl.stdout, walked: walked() }));

    // What goes wrong in the clone: the walk's log runs first, in the clone, as trufflehog runs it.
    const wc = mergeScan(wr, pushEnv(wBase), gitDamagingClones(wBlob), thLogDies);
    const wWalkFails = (tail) => `- ❌ trufflehog verified-live secrets — trufflehog could not read its walk: git log --patch ${wHead.slice(0, 7)} ^${wBase.slice(0, 7)}, the log trufflehog reads, failed in the clone, ${tail}\n`;
    check("(W) a clone that lacks a range object: FAULT on trufflehog's leg, naming the walk's log, never the walk that read nothing; gitleaks, on the checkout, still blocks",
      wc.status === 1 && wc.stdout.includes(wWalkFails(`exit 128: fatal: unable to read ${redact(wBlob)}`))
      && wc.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && wc.stdout.includes('…and 1 scanner leg(s) that could have blocked could not look (trufflehog verified-live secrets)')
      && wc.argvs.length === 1 && !leaked(wc.stdout), verdict(wc));
    // trufflehog's git gets GIT_DIR and nothing else, so an inherited alternate that holds the object
    // is no help to it, and must be none to the log run for it.
    const wf = mergeScan(wr, pushEnv(wBase), { ...gitDamagingClones(wBlob), GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(wr, '.git', 'objects') }, thLogDies);
    check("(W) …with an inherited alternate that holds the object: FAULT all the same, since trufflehog's git is given GIT_DIR alone",
      wf.status === 1 && wf.stdout.includes(wWalkFails(`exit 128: fatal: unable to read ${redact(wBlob)}`)), verdict(wf));
    // An object only the history below the range reads, lost from the clone: trufflehog stops at the
    // base before it matters, and the log run for a walk is the walk's commits, never all of history.
    const wx = mergeScan(wr, pushEnv(wBase), gitDamagingClones(shaIn(wr, `${wBase}:a.txt`)));
    check('(W) an object only the history below the range reads, lost from the clone: no fault, the walk as before',
      wx.status === 1 && wx.stdout.includes('\nBLOCKED — 2 critical finding(s). ') && !wx.stdout.includes('could not look') && wx.argvs.length === 1, verdict(wx));
    // A log that prints more than run()'s 64 MB output buffer is read to its end: its output is discarded.
    const wy = repoAt('log-over-the-buffer');
    const wyBase = commitFiles(wy, '2026-09-12T10:00:00Z', { 'a.txt': 'a\n' }, 'base');
    commitFiles(wy, '2026-09-12T11:00:00Z', { 'big.txt': `${'x'.repeat(99)}\n`.repeat(700000) }, 'a 70 MB file');
    fs.rmSync(path.join(wy, 'big.txt'));   // its object is what the logs read; the working copy is not needed
    const wyr = walkScan(wy, pushEnv(wyBase));   // the clean gitleaks stub: only the two logs read the range
    check("(W) a range whose log prints more than run()'s 64 MB buffer: read by both logs, no fault — their output is discarded, whatever its size",
      wyr.argvs.length === 1 && !wyr.stdout.includes('could not look'), verdict(wyr));

    // What goes wrong in the checkout: gitleaks' log runs first, in the checkout, as gitleaks runs it.
    const wAlt = path.join(tmp, 'log-dies-alternate');   // an object directory that holds the blob
    const wAltBlob = path.join(wAlt, wBlob.slice(0, 2), wBlob.slice(2));
    fs.mkdirSync(path.dirname(wAltBlob), { recursive: true });
    fs.copyFileSync(looseOf(wr, wBlob), wAltBlob);
    fs.rmSync(looseOf(wr, wBlob));
    const wLog = gitAt(wr)('log', '-p', '-U0', `${wBase}..HEAD`);
    const wDiff = gitAt(wr)('diff', '--name-only', '--diff-filter=d', `${wBase}...HEAD`);
    check("(W) the fixture: git log -p of the range dies on the lost blob, while the changed-file list, which reads the range's ends, does not",
      wLog.status === 128 && wLog.stderr.includes(`unable to read ${wBlob}`) && wDiff.status === 0 && wDiff.stdout.includes('v.live'), JSON.stringify([wLog.status, wLog.stderr, wDiff.status]));
    const wRep = path.join(tmp, 'gitleaks-log-dies.json');
    const wGl = spawnSync(glAsMeasured, ['detect', '--report-path', wRep, '--log-opts', `${wBase}..HEAD`], { cwd: wr, env: base, encoding: 'utf8' });
    check('(W) control: gitleaks, as measured, reads nothing there, the key included, and exits 0 with []',
      wGl.status === 0 && fs.readFileSync(wRep, 'utf8') === '[]');
    const wa = mergeScan(wr, pushEnv(wBase), { VERIFIED_SECRETS: 'off' });
    const wRangeFails = `- ❌ gitleaks secret scan — the range could not be read: git log -p -U0 ${wBase}..HEAD, the log gitleaks reads, failed, exit 128: fatal: unable to read ${redact(wBlob)}\n`;
    check('(W) a checkout that lacks a range object: FAULT on the gitleaks leg, naming the log, never the PASS gitleaks gives; its run still goes ahead',
      wa.status === 1 && wa.stdout.includes(wRangeFails) && wa.stdout.includes('\nFAULT — 1 scanner leg(s) that could have blocked could not look (gitleaks secret scan).')
      && JSON.stringify(wa.logOpts) === JSON.stringify([`${wBase}..HEAD`]), verdict(wa));
    const wb = mergeScan(wr, pushEnv(wBase));
    check('(W) …with the verified probe on: both legs could not look, trufflehog on the clone, which cloning an incomplete checkout cannot make',
      wb.status === 1 && wb.stdout.includes(wRangeFails) && wb.argvs.length === 0
      && wb.stdout.includes('- ❌ trufflehog verified-live secrets — git clone of the checkout for trufflehog failed, exit 128: '), verdict(wb));
    // gitleaks' git inherits the scan's env, so an alternate that holds the object is read by both.
    const wg = mergeScan(wr, pushEnv(wBase), { VERIFIED_SECRETS: 'off', GIT_ALTERNATE_OBJECT_DIRECTORIES: wAlt });
    check("(W) …with an inherited alternate that holds the object: gitleaks' git reads it, so does the log run for it — no fault, and the key BLOCKS",
      wg.status === 1 && wg.stdout.includes('\nBLOCKED — 1 critical finding(s). ') && wg.stdout.includes(glLine('v.live', 1, kW, `in commit ${wHead.slice(0, 7)}`))
      && !wg.stdout.includes('could not look'), verdict(wg));

    // One walk of several whose log git cannot finish, and a walk to the root, which trufflehog reads
    // with --diff-filter=AM: each named.
    const wd = walkScan(pa, { ...prEnv, PR_HEAD_SHA: aHead }, gitRefusing('--pretty=fuller', aMid));
    check("(W) one walk of several whose log git cannot finish: FAULT, naming the walk, its tip and its stop",
      wd.status === 1 && wd.stdout.includes(`- ❌ trufflehog verified-live secrets — trufflehog walk 2 of 2, from ${aMid.slice(0, 7)}, could not read its walk: git log --patch ${aMid.slice(0, 7)} ^${aFork.slice(0, 7)}, the log trufflehog reads, failed in the clone, exit 128: fatal: --pretty=fuller refused by the selftest\n`), verdict(wd));
    const we = walkScan(pd, { ...prEnv, PR_HEAD_SHA: dHead }, gitRefusing('--diff-filter=AM', dImp));
    check('(W) a walk to the root is read as trufflehog reads one, with --diff-filter=AM: FAULT, naming it',
      we.status === 1 && we.stdout.includes(`- ❌ trufflehog verified-live secrets — trufflehog walk 3 of 3, from ${dImp.slice(0, 7)}, could not read its walk: git log --patch ${dImp.slice(0, 7)}, the log trufflehog reads, failed in the clone, exit 128: fatal: --diff-filter=AM refused by the selftest\n`), verdict(we));

    // Each gitleaks run reports into a directory made for it, removed after — none may be left behind.
    check('every gitleaks report directory is removed afterwards', fs.readdirSync(tmp).filter((d) => d.startsWith('sb-gitleaks-')).length === 0,
      fs.readdirSync(tmp).join(','));
    check('every trufflehog clone directory is removed afterwards, the failed clone\'s too', fs.readdirSync(tmp).filter((d) => d.startsWith('sb-trufflehog-')).length === 0,
      fs.readdirSync(tmp).join(','));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(failed === 0 ? '\n✅ all engine self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
