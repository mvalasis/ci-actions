// Offline self-test for the security-baseline tier engine. No network, no scanners — feeds
// canned findings to the pure engine and asserts the tiering / promotion / block decision and
// the redaction disclosure guard. Run: node scripts/selftest.mjs (also runs in CI). Exits
// non-zero on any regression — the gate's own regression guard, mirroring seo-aeo/selftest.mjs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  SEV, CHECKS, T0_CHECKS, T1_CHECKS, T2_CHECKS, RESERVED_CHECKS, evaluate, parsePromote,
  isPromotable, baseSev, safe, redact,
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

console.log(failed === 0 ? '\n✅ all engine self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
