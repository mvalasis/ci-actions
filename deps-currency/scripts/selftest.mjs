// Offline self-test for the deps-currency engine. No network, no osv-scanner, no gh — feeds a
// SAVED osv-scanner JSON output fixture (one CRITICAL vuln, one LOW vuln) + workflow-text fixtures
// to the pure engine and asserts: severity-floor filtering, issue open/close decision, clean→close,
// block decision (fail-on-vuln), unpinned-action detection, the first-party OWNER-SET derivation
// (caller ∪ action ∪ declared extras — the 2026-08 ownership split), and the
// report-spoofing/disclosure guard; then runs the real scan.mjs against a stub osv-scanner and a
// stub gh to assert what reaches the job log (the report, its lockfiles named relative to the
// workspace since v1.29.5, one annotation per at/above-floor advisory, and what happened to the
// tracking issue) and what reaches the issue (its body, cut under GitHub's limit since v1.29.4).
// Run: node scripts/selftest.mjs (also runs in CI). Exits non-zero on any regression — the
// action's own regression guard, mirroring security-baseline/selftest.mjs.
//
// FIXTURE RULE learned from that split (see the "ownership split" block below): when a fixture
// models a RELATIONSHIP between two values, the two must be DIFFERENT literals. The original
// owner-exclusion fixture used 'mvalasis' as both the action owner in the workflow text and the
// owner passed in, so it passed no matter which one the engine actually consulted — and it stayed
// green through the entire defect.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  SEV, normalizeFloor, bucketFor, atOrAboveFloor, parseOsv, filterByFloor,
  scanUnpinnedActions, normalizeOwners, resolveFirstPartyOwners, issueDecision, blockDecision,
  renderReport, safe, escapeData, escapeProperty, repoRelative, annotation, annotations,
  osvOutcome, scrub, errorLine, faultAnnotation, capIssueBody, capSummary,
} from './engine.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

let failed = 0;
function check(name, cond, detail = '') { if (cond) console.log(`  ✅ ${name}`); else { console.log(`  ❌ ${name} ${detail}`); failed++; } }

// ---- SAVED osv-scanner v2 JSON fixture: one CRITICAL (CVSS 9.8), one LOW (CVSS 3.1) on npm,
//      plus a composer MODERATE (CVSS 6.5) — exactly the shape osv-scanner emits. ----
const OSV_FIXTURE = {
  results: [
    {
      source: { path: 'package-lock.json', type: 'lockfile' },
      packages: [
        {
          package: { name: 'lodash', version: '4.17.4', ecosystem: 'npm' },
          groups: [{ ids: ['GHSA-jf85-cpcp-j695', 'CVE-2019-10744'], aliases: ['CVE-2019-10744'], max_severity: '9.8' }],
        },
        {
          package: { name: 'tough-cookie', version: '2.3.2', ecosystem: 'npm' },
          groups: [{ ids: ['GHSA-72xf-g2v4-qvf3', 'CVE-2023-26136'], max_severity: '3.1' }],
        },
      ],
    },
    {
      source: { path: 'composer.lock', type: 'lockfile' },
      packages: [
        {
          package: { name: 'guzzlehttp/guzzle', version: '6.5.0', ecosystem: 'Packagist' },
          groups: [{ ids: ['GHSA-w248-ffj2-4v5q', 'CVE-2022-31090'], max_severity: '6.5' }],
        },
      ],
    },
  ],
};

console.log('\n# CVSS → bucket');
{
  check('9.8 → CRITICAL', bucketFor(9.8) === SEV.CRITICAL);
  check('7.0 → HIGH', bucketFor(7.0) === SEV.HIGH);
  check('6.5 → MODERATE', bucketFor(6.5) === SEV.MODERATE);
  check('3.1 → LOW', bucketFor(3.1) === SEV.LOW);
  check('no CVSS (0) → HIGH (conservative, never silently dropped)', bucketFor(0) === SEV.HIGH);
  check('absent score → HIGH', bucketFor(undefined) === SEV.HIGH);
}

console.log('\n# floor normalization + comparison');
{
  check("normalizeFloor('high') = HIGH", normalizeFloor('high') === SEV.HIGH);
  check("normalizeFloor('CRIT') alias = CRITICAL", normalizeFloor('CRIT') === SEV.CRITICAL);
  check("normalizeFloor('medium') = MODERATE", normalizeFloor('medium') === SEV.MODERATE);
  check('garbage floor defaults to HIGH', normalizeFloor('zzz') === SEV.HIGH);
  check('CRITICAL is at/above a HIGH floor', atOrAboveFloor(SEV.CRITICAL, 'HIGH'));
  check('LOW is NOT at/above a HIGH floor', !atOrAboveFloor(SEV.LOW, 'HIGH'));
  check('MODERATE is at/above a MODERATE floor', atOrAboveFloor(SEV.MODERATE, 'MODERATE'));
}

console.log('\n# parse the saved osv fixture');
const parsed = parseOsv(OSV_FIXTURE);
{
  check('parsed 3 findings (one per group)', parsed.length === 3, `got ${parsed.length}`);
  const lodash = parsed.find((f) => f.name === 'lodash');
  check('lodash → CRITICAL, CVSS 9.8', lodash && lodash.severity === SEV.CRITICAL && lodash.score === 9.8, JSON.stringify(lodash));
  check('lodash carries both advisory ids', lodash && lodash.ids.includes('GHSA-jf85-cpcp-j695') && lodash.ids.includes('CVE-2019-10744'));
  const tough = parsed.find((f) => f.name === 'tough-cookie');
  check('tough-cookie → LOW, CVSS 3.1', tough && tough.severity === SEV.LOW && tough.score === 3.1);
  const guzzle = parsed.find((f) => f.name === 'guzzlehttp/guzzle');
  check('guzzle → MODERATE from composer.lock', guzzle && guzzle.severity === SEV.MODERATE && guzzle.source === 'composer.lock');
  check('parseOsv tolerates garbage input → []', parseOsv(null).length === 0 && parseOsv({}).length === 0 && parseOsv({ results: 'x' }).length === 0);
}

console.log('\n# severity-floor filtering');
{
  const hi = filterByFloor(parsed, 'HIGH');
  check('HIGH floor keeps only the CRITICAL (lodash), drops LOW + MODERATE', hi.length === 1 && hi[0].name === 'lodash', JSON.stringify(hi.map((f) => f.name)));
  const mod = filterByFloor(parsed, 'MODERATE');
  check('MODERATE floor keeps CRITICAL + MODERATE (2), drops LOW', mod.length === 2 && mod.every((f) => f.name !== 'tough-cookie'));
  const low = filterByFloor(parsed, 'LOW');
  check('LOW floor keeps all 3', low.length === 3);
  const crit = filterByFloor(parsed, 'CRITICAL');
  check('CRITICAL floor keeps only the 9.8', crit.length === 1 && crit[0].name === 'lodash');
  check('filter sorts most-severe first', low[0].severity === SEV.CRITICAL && low[low.length - 1].severity === SEV.LOW);
}

console.log('\n# issue open/close decision (linkcheck lifecycle)');
{
  const dirty = issueDecision(filterByFloor(parsed, 'HIGH'), []);
  check('findings present → OPEN the issue', dirty.action === 'open' && dirty.clean === false && dirty.vulnCount === 1);
  const cleanByFloor = issueDecision(filterByFloor(parsed, 'CRITICAL').filter(() => false), []);
  check('no findings (clean) → CLOSE the issue', cleanByFloor.action === 'close' && cleanByFloor.clean === true);
  // clean osv but an unpinned-action advisory still OPENs (the issue tracks both)
  const onlyUnpinned = issueDecision([], [{ path: '.github/workflows/x.yml', line: 3, uses: 'foo/bar@v1', pin: 'v1' }]);
  check('no vulns but an unpinned-action advisory → still OPEN', onlyUnpinned.action === 'open' && onlyUnpinned.unpinnedCount === 1);
  const fullyClean = issueDecision([], []);
  check('zero vulns AND zero unpinned → CLOSE', fullyClean.action === 'close' && fullyClean.clean === true);
  // osv-scanner could not look: no verdict either way — not "clean", and not "found something" on
  // the strength of the half that did look (the unpinned-action scan, or a partial report).
  const blind = issueDecision([], [], { looked: false });
  check('osv could not look, nothing else found → HOLD, not CLOSE (a scan that did not happen is not clean)', blind.action === 'hold' && blind.clean === false && blind.looked === false, JSON.stringify(blind));
  check('osv could not look, with unpinned + partial findings → still HOLD, never OPEN',
    issueDecision(filterByFloor(parsed, 'HIGH'), [{ path: 'x.yml', line: 1, uses: 'foo/bar@v1', pin: 'v1' }], { looked: false }).action === 'hold');
  check('looked: true is the default and changes nothing', issueDecision([], [], { looked: true }).action === 'close' && issueDecision(filterByFloor(parsed, 'HIGH'), [], {}).action === 'open');
}

console.log('\n# osvOutcome — an osv-scanner that could not look never reads as one that found nothing');
{
  // Canned processes in scan.mjs run()'s shape. Exit codes are osv-scanner v2.4.0's (engine.mjs).
  const R = (o) => ({ missing: false, status: 0, signal: '', error: '', ms: 0, stdout: '', stderr: '', ...o });
  const osv = (status, stdout, stderr = '') => osvOutcome(R({ status, stdout, stderr }));
  const report = JSON.stringify(OSV_FIXTURE);
  check('exit 0 {"results":[]}: looked, found nothing', osv(0, '{"results":[]}').looked === true && osv(0, '{"results":[]}').results.length === 0);
  check('exit 1 with results: looked, every result kept (vulnerabilities found is not a failure)', osv(1, report).looked === true && osv(1, report).results.length === 2);
  check('exit 128, empty stdout (no package source): looked, nothing to audit', osv(128, '', 'No package sources found, --help for usage information.').looked === true && osv(128, '').results.length === 0);
  // Exit 128 is three trees on v2.4.0 (measured): no lockfile, lockfiles holding no package, and
  // lockfiles it could not read. scan.mjs passes its own lockfile walk and the root osv scanned.
  const root = '/home/runner/work/x/x';
  const at = (stderr, lockfiles) => osvOutcome(R({ status: 128, stderr }), { lockfiles, root });
  const EXTRACT = 'Error during extraction: (extracting as javascript/packagelockjson) home/runner/work/x/x/sub/package-lock.json: could not extract: unexpected end of JSON input';
  const NONE = 'No package sources found, --help for usage information.';
  const junk = at(`Scanning dir .\n${EXTRACT}\n${NONE}`, ['sub/package-lock.json']);
  check('exit 128, extraction error: could not look; the reason is osv\'s error, root cut off',
    junk.looked === false && junk.reason === 'exit 128: Error during extraction: extracting as javascript/packagelockjson sub/package-lock.json: could not extract: unexpected end of JSON input', JSON.stringify(junk));
  check('…even with no lockfile listed', at(EXTRACT, []).looked === false);
  check('…even beside a lockfile it read empty',
    at(`Scanned /home/runner/work/x/x/package-lock.json file and found 0 packages\n${EXTRACT}\n${NONE}`, ['package-lock.json', 'sub/package-lock.json']).looked === false);
  const unread = at(`Scanning dir .\n${NONE}`, ['bun.lockb']);
  check('exit 128, no lockfile read (a bun.lockb): could not look, lockfile named',
    unread.looked === false && unread.reason === "exit 128: it read none of the tree's lockfiles: bun.lockb", JSON.stringify(unread));
  check('…a long list is cut to three', at(NONE, ['a', 'b', 'c', 'd', 'e']).reason === "exit 128: it read none of the tree's lockfiles: a, b, c and 2 more");
  check('exit 128, every lockfile read and empty: looked',
    at(`Scanning dir .\nScanned /home/runner/work/x/x/package-lock.json file and found 0 packages\n${NONE}`, ['package-lock.json']).looked === true);
  check('…`found 1 package` too', at('Scanned /w/composer.lock file and found 1 package', ['composer.lock']).looked === true);
  check('exit 128, no lockfile: looked', at(NONE, []).looked === true && at('', []).looked === true);
  check('no root: the path stays whole', String(osvOutcome(R({ status: 128, stderr: EXTRACT }), {}).reason || '').includes('home/runner/work/x/x/sub/package-lock.json'));
  const down = osv(129, '', 'Scanning dir .\nfailed to query the OSV API: 503 Service Unavailable');
  check('exit 129, empty stdout (the API failed): could not look; the reason names the exit and osv\'s error line',
    down.looked === false && down.reason === 'exit 129: failed to query the OSV API: 503 Service Unavailable', JSON.stringify(down));
  check('exit 127, empty stdout (an unreachable osv.dev, as measured): could not look', osv(127, '', 'dial tcp: lookup api.osv.dev: no such host').reason === 'exit 127: dial tcp: lookup api.osv.dev: no such host');
  check('exit 130 (an invalid config): could not look', osv(130, '').looked === false && osv(130, '').reason === 'exit 130');
  check('exit 0 with an EMPTY stdout: could not look — the old code parsed this as {} and called it clean', osv(0, '').looked === false && osv(0, '').reason === 'exit 0: no JSON report', JSON.stringify(osv(0, '')));
  check('exit 0 with unparseable stdout: could not look — the old code noted "treated as clean"', osv(0, '{"results":[').looked === false);
  check('exit 0 with JSON but no results array: could not look', osv(0, '{}').looked === false && osv(0, '{"results":null}').looked === false);
  check('exit 1 with no results: could not look (a findings exit with no findings)', osv(1, '{"results":[]}').looked === false && osv(1, '{"results":[]}').reason === 'exit 1, vulnerabilities found, with no results in its report');
  check('exit 2 with a valid-looking report: could not look — the status decides — and what it reported is kept', osv(2, report).looked === false && osv(2, report).results.length === 2);
  check('not installed: could not look', osvOutcome(R({ missing: true, status: 127 })).reason === 'not installed');
  check('a timeout: could not look, even behind a complete-looking report', osvOutcome(R({ status: 1, stdout: report, error: 'ETIMEDOUT', signal: 'SIGTERM', ms: 420003 })).reason === 'timed out after 420 s');
  check('the 64 MB output cap: could not look', osvOutcome(R({ status: 1, stdout: report, error: 'ENOBUFS' })).reason === 'output over the 64 MB buffer');
  check('killed by a signal: could not look', osvOutcome(R({ status: 1, stdout: report, signal: 'SIGKILL' })).reason === 'killed by SIGKILL');
  check('a spawn that failed: could not look', osvOutcome(R({ status: 1, stdout: report, error: 'EACCES' })).reason === 'could not run: EACCES');
  check('a run that took 10 s or more says how long', osvOutcome(R({ status: 129, ms: 97400, stderr: 'boom' })).reason === 'exit 129 after 97 s: boom');
  check('errorLine: the first error:/fatal: line, else the last line', errorLine('Scanning dir .\nError: bad flag\nusage: …') === 'Error: bad flag' && errorLine('a\nb\n\n') === 'b' && errorLine('') === '');
  // What osv prints about its own failure reaches the log, the summary and a (possibly public) issue.
  const tok = `tok${'a1'.repeat(15)}`;   // built at run time: this file is itself scanned for secrets
  check('scrub: a URL\'s userinfo is dropped', !scrub('Post "https://user:hunter2@api.osv.dev/v1/querybatch"').includes('hunter2'));
  check('scrub: a letters+digits run of 20+ is cut to first4…last4', !scrub(`token ${tok} rejected`).includes(tok) && scrub(`token ${tok} rejected`).includes('toka…a1a1'));
  check('scrub: one line, markdown-structural characters stripped (safe() underneath)', !/[\n`|<>()]/.test(scrub('a\n`b`|<c>(d)')));
}

console.log('\n# report + annotation when osv-scanner could not look');
{
  const blindReport = renderReport([], [], { floor: 'HIGH', lockfiles: ['bun.lock'], totalFindings: 0, looked: false });
  check('no ✅ and no "0 total" — the tree was not audited', !blindReport.includes('✅') && !blindReport.includes('**0** total') && blindReport.includes('- advisories in tree: **unknown** — osv-scanner could not look'), blindReport);
  check('the report says there is no verdict', blindReport.includes('- ⚠️ no verdict — osv-scanner could not look, so nothing here says the dependencies are clean.'));
  const partial = renderReport(filterByFloor(parsed, 'HIGH'), [], { floor: 'HIGH', totalFindings: 3, looked: false });
  check('what a failed run did report is listed, marked possibly incomplete', partial.includes('lodash') && partial.includes('_osv-scanner could not finish, so this list may be incomplete._'));
  check('a report that looked is unchanged (looked: true, or absent)', renderReport([], [], { floor: 'HIGH', totalFindings: 0, looked: true }) === renderReport([], [], { floor: 'HIGH', totalFindings: 0 }));
  check('faultAnnotation: the level is the caller\'s, the title names the fault',
    faultAnnotation('exit 129', 'warning') === '::warning title=deps-currency could not look::osv-scanner could not look — exit 129' && faultAnnotation('exit 129').startsWith('::error '));
  const hostile = faultAnnotation('exit 127: x%0A\n::stop-commands::tok');
  check('faultAnnotation: a hostile reason stays one line, its % escaped', !/[\r\n]/.test(hostile) && hostile.includes('x%250A'), JSON.stringify(hostile));
}

console.log('\n# block decision (fail-on-vuln — report-mode-first default)');
{
  const hi = filterByFloor(parsed, 'HIGH');
  check('default (fail-on-vuln unset) NEVER blocks, even with a CRITICAL present', blockDecision(hi) === false);
  check('fail-on-vuln:false NEVER blocks', blockDecision(hi, { failOnVuln: false }) === false);
  check('fail-on-vuln:true + >=floor finding → BLOCK', blockDecision(hi, { failOnVuln: true }) === true);
  check('fail-on-vuln:true + NO >=floor finding → no block', blockDecision([], { failOnVuln: true }) === false);
  // a LOW under a HIGH floor: even fail-on-vuln:true does NOT block (it was filtered out before block)
  check('fail-on-vuln:true but only sub-floor advisories → no block', blockDecision(filterByFloor(parsed, 'CRITICAL').filter((f) => f.severity === SEV.LOW), { failOnVuln: true }) === false);
}

console.log('\n# unpinned third-party actions consuming secrets');
{
  // BAD: consumes a secret AND uses a third-party action pinned to a mutable tag
  const bad = `
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v4
      - uses: webfactory/ssh-agent@v0.9.0
        with:
          ssh-private-key: \${{ secrets.DEPLOY_KEY }}
`;
  // GOOD-1: third-party action but SHA-pinned (immutable) — safe
  const shaPinned = `
jobs:
  build:
    steps:
      - uses: pnpm/action-setup@a3252b78c470c02df07e9d59298aecedc3ccdd6d
        with:
          token: \${{ secrets.NPM_TOKEN }}
`;
  // GOOD-2: unpinned third-party action but NO secret in the file — out of scope
  const noSecret = `
jobs:
  lint:
    steps:
      - uses: some/linter@main
`;
  const r = scanUnpinnedActions([
    { path: '.github/workflows/deploy.yml', text: bad },
    { path: '.github/workflows/build.yml', text: shaPinned },
    { path: '.github/workflows/lint.yml', text: noSecret },
  ]);
  check('flags exactly the unpinned third-party action consuming a secret', r.length === 1 && r[0].uses === 'webfactory/ssh-agent@v0.9.0', JSON.stringify(r));
  check('does NOT flag the SHA-pinned third-party action', !r.some((u) => u.uses.includes('pnpm/action-setup')));
  check('does NOT flag first-party actions/checkout', !r.some((u) => u.uses.includes('actions/checkout')));
  check('does NOT flag an unpinned action in a workflow with no secret', !r.some((u) => u.uses.includes('some/linter')));
  check('does NOT flag a local ./action', scanUnpinnedActions([{ path: 'x.yml', text: 'uses: ./local\nsecrets.FOO' }]).length === 0);
  check('empty input → []', scanUnpinnedActions([]).length === 0 && scanUnpinnedActions(null).length === 0);

  // first-party-owner exclusion: an owner in the first-party set is ours (e.g. mvalasis/ci-actions@v1,
  // deliberately floating-tag-pinned by the fleet policy) — must NOT be flagged. The single-STRING
  // form is the pre-2026-08 call signature and is asserted here so it keeps working for any caller
  // that still passes one owner.
  const selfOrg = [{ path: '.github/workflows/x.yml',
    text: 'jobs:\n  a:\n    steps:\n      - uses: mvalasis/ci-actions/linkcheck@v1\n      - uses: oven-sh/setup-bun@v2\n    env:\n      T: ${{ secrets.CF_TOKEN }}' }];
  const sOff = scanUnpinnedActions(selfOrg);            // no owners → flags BOTH
  const sOn = scanUnpinnedActions(selfOrg, 'mvalasis'); // owner set (string form) → only the real third-party
  check('without a first-party owner, own-org action IS flagged', sOff.some((u) => u.uses.includes('mvalasis/ci-actions')));
  check('first-party owner (string form) excludes own-org action', !sOn.some((u) => u.uses.includes('mvalasis/ci-actions')));
  check('first-party owner still flags the genuine third-party (oven-sh)', sOn.length === 1 && sOn[0].uses === 'oven-sh/setup-bun@v2', JSON.stringify(sOn));
  check('owner match is case-insensitive', scanUnpinnedActions([{ path: 'x.yml', text: 'uses: MVALASIS/ci-actions@v1\nsecrets.X' }], 'mvalasis').length === 0);
}

console.log('\n# first-party owner SET — the 2026-08 caller/action ownership split');
{
  // WHY THIS BLOCK EXISTS. The fixture above uses `mvalasis` as BOTH the action owner in the
  // workflow text AND the owner passed in — the same literal twice, so it passes whether
  // "first-party" is derived from the caller, the action, or a coin flip. That is precisely why it
  // could not catch the split defect: when 11 repos moved to `creme-ypsilon` and ci-actions stayed
  // on `mvalasis`, the caller-derived owner stopped matching the action's owner and every
  // `mvalasis/ci-actions/*@v1` ref became an "unpinned third-party action" on every org caller.
  // These fixtures keep the two owners DELIBERATELY DIFFERENT so the union is doing real work.
  const CALLER = 'creme-ypsilon';   // github.repository owner, post-move (e.g. creme-ypsilon/lampakia-astro)
  const ACTION = 'mvalasis';        // github.action_repository owner — ci-actions did NOT move
  // A caller workflow shaped like the live ones: one of OUR shared actions, one genuine
  // third-party action, and a secret in the file (the consuming-secrets qualifier).
  const split = [{ path: '.github/workflows/linkcheck-weekly.yml',
    text: 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: mvalasis/ci-actions/linkcheck@v1\n      - uses: oven-sh/setup-bun@v2.2.0\n        env:\n          T: ${{ secrets.CF_API_TOKEN }}' }];

  // (1) caller owner ONLY = the pre-fix behaviour = the live defect, asserted rather than assumed.
  // This is also what proves the exemption is NOT vacuous: drop the action owner and the ref really
  // does get flagged, so assertion (2) below is testing a mechanism and not a tautology.
  const callerOnly = scanUnpinnedActions(split, [CALLER]);
  check('caller-owner-only (pre-fix) DOES flag our own ci-actions ref — the defect', callerOnly.some((u) => u.uses.includes('mvalasis/ci-actions')), JSON.stringify(callerOnly));

  // (2) the union — caller ∪ action — is the fix.
  const union = scanUnpinnedActions(split, [CALLER, ACTION]);
  check('caller ∪ action owner does NOT flag mvalasis/ci-actions on a creme-ypsilon caller', !union.some((u) => u.uses.includes('mvalasis/ci-actions')), JSON.stringify(union));
  check('…and STILL flags the genuine third-party in the same file', union.length === 1 && union[0].uses === 'oven-sh/setup-bun@v2.2.0', JSON.stringify(union));
  check('…and still ignores actions/checkout', !union.some((u) => u.uses.includes('actions/checkout')));

  // (3) local `./` invocation: github.action_repository is EMPTY, so ownerOf('') === '' is really
  // in the list. The set must degrade to caller-only — and the '' must NOT become an owner that
  // matches everything (an exemption matching by accident is the whole defect class).
  const localRef = scanUnpinnedActions(split, [CALLER, '']);
  check("empty action_repository → caller-only set (own ci-actions ref flagged again, not exempted)", localRef.length === 2 && localRef.some((u) => u.uses.includes('mvalasis/ci-actions')), JSON.stringify(localRef));
  check('empty-string owner does NOT exempt the third-party either', localRef.some((u) => u.uses.includes('oven-sh')));
  // the direct probe: an owner-less `uses:` must stay flagged even with '' handed in
  check("'' in the owner list never matches an owner-less uses:", scanUnpinnedActions([{ path: 'x.yml', text: 'uses: @v1\nsecrets.X' }], ['', '  ']).length === 1);

  // (4) case-insensitivity survives the widening, on BOTH owners of the union.
  check('union owner match is case-insensitive', scanUnpinnedActions(split, ['CREME-Ypsilon', 'MVALASIS']).length === 1);
  check('mixed-case owner in the workflow text is matched too', scanUnpinnedActions([{ path: 'x.yml', text: 'uses: MVALASIS/ci-actions/linkcheck@v1\nsecrets.X' }], ['creme-ypsilon', 'mvalasis']).length === 0);

  // (5) the third leg of the contract: caller-declared extra owners.
  check('a declared extra owner exempts a third account', scanUnpinnedActions([{ path: 'x.yml', text: 'uses: some-other-org/tool@v3\nsecrets.X' }], [CALLER, ACTION, 'some-other-org']).length === 0);
}

console.log('\n# owner-set derivation (resolveFirstPartyOwners / normalizeOwners)');
{
  const r = resolveFirstPartyOwners({ callerRepo: 'creme-ypsilon/lampakia-astro', actionRepo: 'mvalasis/ci-actions' });
  check('derives caller ∪ action owner from the two repo slugs', r.join(',') === 'creme-ypsilon,mvalasis', JSON.stringify(r));
  const withExtra = resolveFirstPartyOwners({ callerRepo: 'creme-ypsilon/lux-pm', actionRepo: 'mvalasis/ci-actions', extraOwners: 'acme, Other-Org' });
  check('first-party-owners input adds extras (split on space/comma, lowercased)', withExtra.join(',') === 'creme-ypsilon,mvalasis,acme,other-org', JSON.stringify(withExtra));
  // local `./` ref — the case the selftest workflows actually exercise
  const localRef = resolveFirstPartyOwners({ callerRepo: 'mvalasis/ci-actions', actionRepo: '' });
  check("empty action_repository contributes NOTHING (no '' owner)", localRef.length === 1 && localRef[0] === 'mvalasis', JSON.stringify(localRef));
  check('same caller+action owner de-duplicates to one entry', resolveFirstPartyOwners({ callerRepo: 'mvalasis/epn-astro', actionRepo: 'mvalasis/ci-actions' }).join(',') === 'mvalasis');
  check('no env at all (both empty) → EMPTY set, not a set containing ""', resolveFirstPartyOwners({}).length === 0);
  check('normalizeOwners drops empty/whitespace tokens', normalizeOwners(['', '   ', null, undefined, ',']).size === 0);
  check('normalizeOwners parses a single string, an array, and a separated string identically', normalizeOwners('mvalasis').has('mvalasis') && normalizeOwners(['mvalasis']).has('mvalasis') && normalizeOwners('mvalasis creme-ypsilon').size === 2 && normalizeOwners('mvalasis,creme-ypsilon').size === 2);
  check('normalizeOwners lowercases', [...normalizeOwners('MVALASIS')][0] === 'mvalasis');
}

console.log('\n# END-TO-END wiring: action.yml env → scan.mjs → report (still offline)');
{
  // The unit tests above prove the ENGINE's policy. They cannot prove the CLI reads the owners
  // from the env keys action.yml actually sets — and a name drift between the two files
  // (ACTION_REPOSITORY here, `github.action_repository` there) would silently restore the
  // exact 2026-08 defect with every assertion above still green. So: run the real entrypoint with
  // a synthetic env, no network. osv-scanner/gh are pointed at a nonexistent binary and
  // MANAGE_ISSUE is off, so nothing dials out; the lockfile-less workdir just yields "(none found)".
  const actionYml = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');
  check('action.yml declares the first-party-owners input', /^\s*first-party-owners:/m.test(actionYml));
  check('action.yml passes github.action_repository as ACTION_REPOSITORY', /^\s*ACTION_REPOSITORY:\s*\$\{\{\s*github\.action_repository\s*\}\}/m.test(actionYml));
  // …and must NOT write the `GITHUB_` spelling, which would shadow the runner's ambient copy of the
  // same value and leave the derivation with a single, undocumented point of failure. This is the
  // assertion that keeps the redundancy from being "tidied away" by a later editor who reads the
  // two names as a duplicate.
  check('action.yml does NOT shadow the ambient GITHUB_ACTION_REPOSITORY', !/^\s*GITHUB_ACTION_REPOSITORY:/m.test(actionYml));
  check('action.yml passes the input as FIRST_PARTY_OWNERS', /FIRST_PARTY_OWNERS:\s*\$\{\{\s*inputs\.first-party-owners\s*\}\}/.test(actionYml));

  // A caller tree shaped like lampakia-astro post-move: our own shared action + a real third party.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deps-currency-selftest-'));
  fs.mkdirSync(path.join(tmp, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(tmp, '.github', 'workflows', 'linkcheck-weekly.yml'),
    'jobs:\n  a:\n    steps:\n      - uses: mvalasis/ci-actions/linkcheck@v1\n      - uses: oven-sh/setup-bun@v2.2.0\n        env:\n          T: ${{ secrets.CF_API_TOKEN }}\n');

  const runCli = (env) => {
    const summaryPath = path.join(tmp, `summary-${Math.random().toString(36).slice(2)}.md`);
    fs.writeFileSync(summaryPath, '');
    const r = spawnSync(process.execPath, [path.join(HERE, 'scan.mjs')], {
      encoding: 'utf8',
      env: {
        ...process.env,
        WORKING_DIRECTORY: tmp,
        GITHUB_STEP_SUMMARY: summaryPath,
        MANAGE_ISSUE: 'false',          // no gh, no GitHub API
        OSV_BIN: path.join(tmp, 'no-such-osv-scanner'),
        GH_BIN: path.join(tmp, 'no-such-gh'),
        FIRST_PARTY_OWNERS: '',
        // BOTH action-repo sources are blanked by default so a case must opt into the one it is
        // exercising — otherwise an ambient value leaking in from the real CI runner (which sets
        // GITHUB_ACTION_REPOSITORY) would silently satisfy the local-`./` cases below.
        ACTION_REPOSITORY: '',
        GITHUB_ACTION_REPOSITORY: '',
        ...env,
      },
    });
    return { exit: r.status, summary: fs.readFileSync(summaryPath, 'utf8'), stderr: r.stderr || '' };
  };

  // (1) the live post-split shape: org caller, personal-account action.
  const split = runCli({ GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro', ACTION_REPOSITORY: 'mvalasis/ci-actions' });
  check('CLI runs clean with no osv-scanner present (report mode)', split.exit === 0, `exit=${split.exit} ${split.stderr.slice(0, 200)}`);
  check('CLI exempts our own ci-actions ref on an org caller', !split.summary.includes('mvalasis/ci-actions'), split.summary.slice(0, 400));
  check('CLI still reports the genuine third-party', split.summary.includes('oven-sh/setup-bun@v2.2.0'));
  check('CLI reports exactly 1 unpinned advisory', /unpinned-action advisories: 1\b/.test(split.summary), split.summary.slice(-200));
  check('CLI names both derived owners in the report', split.summary.includes('creme-ypsilon') && split.summary.includes('`mvalasis`'));

  // (1b) THE AMBIENT FALLBACK. GitHub documents `github.action_repository` and the runner's
  // GITHUB_ACTION_REPOSITORY identically — and documents NEITHER for a composite action's own
  // steps, which is the only shape this action ever runs in. So the CLI reads both, and this case
  // proves the second one actually works: context source blank, ambient populated, exemption still
  // correct. Without it the redundancy would be decorative — present in the wiring, never executed,
  // and therefore free to rot.
  const ambientOnly = runCli({ GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro', ACTION_REPOSITORY: '', GITHUB_ACTION_REPOSITORY: 'mvalasis/ci-actions' });
  check('ambient GITHUB_ACTION_REPOSITORY alone still exempts our own ref', /unpinned-action advisories: 1\b/.test(ambientOnly.summary), ambientOnly.summary.slice(-200));
  check('…and the ambient owner is named in the report', ambientOnly.summary.includes('`mvalasis`'));

  // (1c) precedence when the two disagree: the context value wins, the ambient is only a fallback.
  // Asserted so the `||` is a deliberate rule rather than an accident of ordering.
  const bothSet = runCli({ GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro', ACTION_REPOSITORY: 'mvalasis/ci-actions', GITHUB_ACTION_REPOSITORY: 'oven-sh/setup-bun' });
  check('context ACTION_REPOSITORY wins over the ambient when both are set', /unpinned-action advisories: 1\b/.test(bothSet.summary) && bothSet.summary.includes('oven-sh/setup-bun@v2.2.0'), bothSet.summary.slice(-200));

  // (2) local `./` invocation — BOTH sources are empty. Caller-only set: our own ref is
  // (correctly) flagged, and crucially the empty value has NOT exempted everything.
  const localRef = runCli({ GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro' });
  check('both action-repo sources empty → caller-only, own ref flagged, third-party still flagged', /unpinned-action advisories: 2\b/.test(localRef.summary), localRef.summary.slice(-200));

  // (3) this repo running its OWN selftest workflow: caller IS ci-actions, action ref is local.
  const selfHosted = runCli({ GITHUB_REPOSITORY: 'mvalasis/ci-actions' });
  check('ci-actions scanning itself via a local ./ ref still exempts its own owner', /unpinned-action advisories: 1\b/.test(selfHosted.summary), selfHosted.summary.slice(-200));

  // (4) the escape hatch reaches the engine through the input.
  const extra = runCli({ GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro', FIRST_PARTY_OWNERS: 'mvalasis oven-sh' });
  check('first-party-owners input reaches the scan (both refs exempted)', /unpinned-action advisories: 0\b/.test(extra.summary), extra.summary.slice(-200));

  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log('\n# report rendering is deterministic + spoof-safe');
{
  const report = renderReport(filterByFloor(parsed, 'HIGH'), [], { floor: 'HIGH', ecosystems: ['npm', 'composer'], lockfiles: ['package-lock.json', 'composer.lock'], totalFindings: 3 });
  check('report names the floor', report.includes('floor: **HIGH**'));
  check('report lists the CRITICAL package', report.includes('lodash'));
  check('clean report says ✅ no advisories', renderReport([], [], { floor: 'HIGH' }).includes('✅ no dependency advisories'));
  // the exemption set is DIAGNOSABLE from the report — a mis-derived owner set was invisible before
  check('report names the first-party owners it exempted', renderReport([], [], { floor: 'HIGH', firstPartyOwners: ['creme-ypsilon', 'mvalasis'] }).includes('first-party owners (exempt'));
  check('report omits the owners line entirely when the CLI supplies none', !renderReport([], [], { floor: 'HIGH' }).includes('first-party owners'));
  check('empty owner set renders explicitly, not as a blank', renderReport([], [], { floor: 'HIGH', firstPartyOwners: [] }).includes('(none — every non-'));
  // disclosure/spoof guard: a hostile package name with markdown + a fake verdict line is neutralized
  const evil = [{ ecosystem: 'npm', source: 's', name: '`|\nBLOCKED](http://evil.tld)', version: '1', ids: ['x'], score: 9.9, severity: SEV.CRITICAL, abandoned: false }];
  const er = renderReport(evil, [], { floor: 'HIGH' });
  check('safe() strips newlines (no forged verdict line in a dep name)', !er.includes('\nBLOCKED'));
  check('safe() strips markdown-structural chars', safe('`|<x>[a](b)') === 'xab');
  check('safe() defangs URLs', safe('see http://evil.tld') === 'see http[:]//evil.tld');
  check('safe() caps length', safe('x'.repeat(500), 50).length === 50);
  // The Lockfile column: the workspace-relative `file` scan.mjs locates, else osv's own path cut at 60.
  // Until v1.29.5 it was always osv's path, absolute on a runner, so the lockfile's name was cut off.
  const ABS = '/home/runner/work/lampakia-astro/lampakia-astro/apps/web/package-lock.json';
  const lodash = parsed.find((f) => f.name === 'lodash');
  const column = (f) => (renderReport([f], [], { floor: 'HIGH' }).match(/^\| 🔴 CRITICAL \|.* \| ([^|]*) \|$/m) || [])[1];
  const rel = column({ ...lodash, source: ABS, file: 'apps/web/package-lock.json' });
  check('Lockfile column: the workspace-relative file, not the absolute path osv printed', rel === 'apps/web/package-lock.json', JSON.stringify(rel));
  const out = column({ ...lodash, source: ABS, file: '' });
  check("Lockfile column: no file (outside the workspace) → osv's path, cut at 60 as before", out === '/home/runner/work/lampakia-astro/lampakia-astro/apps/web/pac', JSON.stringify(out));
  const hostile = column({ ...lodash, source: ABS, file: `apps/\`we|b\`/[x](y)/${'n'.repeat(50)}/package-lock.json` });
  check('Lockfile column: the file goes through safe() too — stripped, and cut at 60', hostile === `apps/web/xy/${'n'.repeat(48)}`, JSON.stringify(hostile));
}

// ---------------------------------------------------------------------------
// The crash guard is BEHAVIOURAL, so assert it by crashing the real scanner —
// not by grepping scan.mjs for the handler's position. From the action's first
// commit until 2026-08-05 the handler sat BELOW the `main()` IIFE, which runs at
// module load and exits, so it was unreachable: a scanner fault exited 1
// unconditionally and wrote NOTHING to the step summary. A textual assertion
// would have to encode "above the IIFE" and would go vacuous the moment the file
// is restructured; running it cannot.
//
// Still offline — the injected throw is main's FIRST statement, so no osv-scanner,
// no gh, no network.
console.log('\n# crash guard (real scan.mjs, injected fault)');
{
  const source = fs.readFileSync(path.join(HERE, 'scan.mjs'), 'utf8');
  const ANCHOR = '(function main() {';

  // Fail CLOSED: if the anchor is gone the mutation is silently a no-op and the
  // assertions below would pass against a scanner that never crashed at all.
  check('fault-injection anchor still present in scan.mjs', source.includes(ANCHOR),
    `(expected to find ${JSON.stringify(ANCHOR)} — if main was renamed, update this test)`);

  if (source.includes(ANCHOR)) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deps-currency-crash-'));
    try {
      fs.copyFileSync(path.join(HERE, "engine.mjs"), path.join(tmp, "engine.mjs"));
      fs.writeFileSync(path.join(tmp, 'scan.mjs'),
        source.replace(ANCHOR, `${ANCHOR}\n  throw new Error('injected scanner fault');`));

      const crash = (failOnVuln) => {
        const summary = path.join(tmp, `summary-${failOnVuln}.md`);
        fs.writeFileSync(summary, '');
        const r = spawnSync(process.execPath, [path.join(tmp, 'scan.mjs')], {
          encoding: 'utf8',
          env: { ...process.env, GITHUB_STEP_SUMMARY: summary, FAIL_ON_VULN: String(failOnVuln), MANAGE_ISSUE: 'false' },
        });
        return { status: r.status, summary: fs.readFileSync(summary, 'utf8'), stdout: r.stdout || '' };
      };

      const report = crash(false);
      const enforce = crash(true);

      // The guard ran at all — this is the assertion the shipped code failed.
      check('a scanner fault is reported into the step summary',
        report.summary.includes('deps-currency crashed') && report.summary.includes('injected scanner fault'),
        `(got ${JSON.stringify(report.summary.slice(0, 120))})`);
      // …and both exit codes, which is the half that is a product decision.
      check('report mode: a crash exits 0 (a scanner fault must not block a green repo)',
        report.status === 0, `(exit ${report.status})`);
      check('fail-on-vuln: a crash exits 1 (conservative for an enforcing caller)',
        enforce.status === 1, `(exit ${enforce.status})`);
      check('fail-on-vuln crash is reported too',
        enforce.summary.includes('deps-currency crashed'));
      check('…and in the job log, not only the step summary',
        report.stdout.includes('deps-currency crashed') && report.stdout.includes('injected scanner fault'),
        `(got ${JSON.stringify(report.stdout.slice(0, 120))})`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
}

console.log('\n# annotation encoding + lockfile location (pure)');
{
  check('escapeData encodes % CR LF', escapeData('a%b\r\nc') === 'a%25b%0D%0Ac');
  check('escapeProperty also encodes : and ,', escapeProperty('a:b,c%') === 'a%3Ab%2Cc%25');
  const ws = '/home/runner/work/r/r';
  check('repoRelative: an absolute osv path under the workspace → repo-relative', repoRelative(`${ws}/bun.lock`, { workdir: ws, workspace: ws }) === 'bun.lock');
  check('repoRelative: a path relative to a sub-directory workdir → repo-relative', repoRelative('pnpm-lock.yaml', { workdir: `${ws}/apps/web`, workspace: ws }) === 'apps/web/pnpm-lock.yaml');
  check('repoRelative: outside the workspace, the workspace itself, or none → "" (no file=)',
    repoRelative('/opt/elsewhere/composer.lock', { workdir: ws, workspace: ws }) === '' && repoRelative(ws, { workdir: ws, workspace: ws }) === '' && repoRelative('', { workdir: ws, workspace: ws }) === '');
  const crit = parsed.find((f) => f.name === 'lodash');
  const want = '::error file=package-lock.json,title=deps-currency CRITICAL::CRITICAL lodash@4.17.4 GHSA-jf85-cpcp-j695, CVE-2019-10744 at package-lock.json';
  check('annotation = file + title + `<SEVERITY> <pkg>@<version> <ids> at <lockfile>`', annotation({ ...crit, file: 'package-lock.json' }) === want, annotation({ ...crit, file: 'package-lock.json' }));
  check("annotation level is the caller's", annotation({ ...crit, file: 'package-lock.json' }, 'warning').startsWith('::warning file='));
  check('no workspace-relative file → no file=, the raw source names the location',
    annotation({ ...crit, source: '/opt/elsewhere/package-lock.json', file: '' }) === '::error title=deps-currency CRITICAL::CRITICAL lodash@4.17.4 GHSA-jf85-cpcp-j695, CVE-2019-10744 at /opt/elsewhere/package-lock.json');
  // A HOSTILE lockfile path must stay one command with exactly the two properties we set, and a
  // hostile package name must stay in the data. Unescaped, the `,` would add `line=1` and the
  // newline would start a second command that stops command processing.
  const evil = annotation({ ...crit, name: 'x%0A\n::stop-commands::tok', file: 'x.lock,line=1::forged\n::stop-commands::tok' });
  const props = (evil.match(/^::error (.*?)::/) || [])[1] || '';
  check('a hostile path or package name stays ONE line', !/[\r\n]/.test(evil), JSON.stringify(evil));
  check("a % in the data is escaped (the runner would decode a raw %0A into a line break)", evil.includes('x%250A') && !evil.includes('x%0A'), JSON.stringify(evil));
  check('a hostile path cannot add or rewrite a property', props.split(',').map((kv) => kv.split('=')[0]).join(',') === 'file,title', JSON.stringify(props));
  check('a hostile path is carried escaped, not dropped', props.startsWith('file=x.lock%2Cline=1%3A%3Aforged%0A%3A%3Astop-commands%3A%3Atok,title='), JSON.stringify(props));
  const many = Array.from({ length: 12 }, (_, i) => ({ ...crit, name: `pkg-${i}`, file: 'package-lock.json' }));
  const out = annotations(many);
  check("annotations: 10 (GitHub's per-step cap) + one overflow line", out.length === 11 && out.slice(0, 10).every((l) => l.startsWith('::error ')) && /^deps-currency: 2 more advisory/.test(out[10]), `got ${out.length}`);
  check('annotations: none for an empty floor set', annotations([]).length === 0);
}

console.log('\n# scan.mjs end to end — the job log carries the report; at/above-floor advisories annotate');
{
  // A workspace with a lockfile and a workflow; a stub osv-scanner answering as osv-scanner v2 does,
  // with ABSOLUTE runner paths, which the report's table and the annotations name relative to the
  // workspace. One advisory is planted with a workflow command in its package name, one lives outside
  // the workspace, one sits below the floor. Offline: no gh (manage-issue off).
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'deps-currency-e2e-'));
  try {
    fs.writeFileSync(path.join(tmp, 'package-lock.json'), '{}\n');
    fs.mkdirSync(path.join(tmp, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(tmp, '.github', 'workflows', 'deploy.yml'), 'jobs:\n  a:\n    steps:\n      - uses: oven-sh/setup-bun@v2.2.0\n        env:\n          T: ${{ secrets.CF_API_TOKEN }}\n');
    const osv = { results: [
      { source: { path: path.join(tmp, 'package-lock.json'), type: 'lockfile' }, packages: [
        { package: { name: 'lodash', version: '4.17.4', ecosystem: 'npm' }, groups: [{ ids: ['GHSA-jf85-cpcp-j695', 'CVE-2019-10744'], max_severity: '9.8' }] },
        { package: { name: 'evil\n::error title=forged::pwned-name', version: '1.0.0', ecosystem: 'npm' }, groups: [{ ids: ['GHSA-xxxx-yyyy-zzzz'], max_severity: '7.5' }] },
        { package: { name: 'tough-cookie', version: '2.3.2', ecosystem: 'npm' }, groups: [{ ids: ['GHSA-72xf-g2v4-qvf3'], max_severity: '3.1' }] },
      ] },
      { source: { path: '/opt/outside-the-workspace/composer.lock', type: 'lockfile' }, packages: [
        { package: { name: 'guzzlehttp/guzzle', version: '6.5.0', ecosystem: 'Packagist' }, groups: [{ ids: ['GHSA-w248-ffj2-4v5q'], max_severity: '8.1' }] },
      ] },
    ] };
    const stub = path.join(tmp, 'osv-scanner-stub');
    // It answers as osv-scanner v2 does: the advisories, exit 1. OSV_STUB_CLEAN answers with none and
    // exit 0 — a clean sweep, for the issue-close cases below. OSV_STUB_EXIT answers with that exit
    // status, OSV_STUB_OUT on stdout and OSV_STUB_ERR on stderr — the could-not-look cases (G).
    // OSV_STUB_KILL prints the whole report and is then killed, as a timeout would kill it.
    // OSV_STUB_FILE answers with that file's report, exit 1 (one too big for an environment variable).
    fs.writeFileSync(stub, `#!/bin/sh\n[ "$1" = "--version" ] && { echo 0.0.0-stub; exit 0; }\n[ -n "$OSV_STUB_FILE" ] && { cat "$OSV_STUB_FILE"; exit 1; }\n[ -n "$OSV_STUB_EXIT" ] && { printf '%s' "$OSV_STUB_OUT"; [ -n "$OSV_STUB_ERR" ] && printf '%s\\n' "$OSV_STUB_ERR" >&2; exit "$OSV_STUB_EXIT"; }\n[ -n "$OSV_STUB_CLEAN" ] && { echo '{"results":[]}'; exit 0; }\ncat <<'JSON'\n${JSON.stringify(osv)}\nJSON\n[ -n "$OSV_STUB_KILL" ] && kill -9 $$\nexit 1\n`);
    fs.chmodSync(stub, 0o755);
    const summaryPath = path.join(tmp, 'summary.md');
    // The env is built from scratch so a CI runner's own GITHUB_ACTIONS / GITHUB_STEP_SUMMARY never
    // leak into a case.
    // `script`: a copy with a fault injected (I). The log of a summary-sized report is past spawnSync's 1 MiB default.
    const scan = (extra, script = path.join(HERE, 'scan.mjs')) => {
      try { fs.rmSync(summaryPath, { force: true }); } catch { /* fresh file per run */ }
      const r = spawnSync(process.execPath, [script], {
        encoding: 'utf8', timeout: 60000, maxBuffer: 64 * 1024 * 1024,
        env: {
          PATH: process.env.PATH, HOME: tmp, TMPDIR: tmp, WORKING_DIRECTORY: tmp, GITHUB_WORKSPACE: tmp,
          OSV_BIN: stub, GH_BIN: path.join(tmp, 'no-such-gh'), MANAGE_ISSUE: 'false',
          GITHUB_REPOSITORY: 'creme-ypsilon/lampakia-astro', ACTION_REPOSITORY: 'mvalasis/ci-actions', ...extra,
        },
      });
      const summary = fs.existsSync(summaryPath) && fs.statSync(summaryPath).isFile() ? fs.readFileSync(summaryPath, 'utf8') : '';
      return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', summary };
    };
    // A line the runner would read as a command: `::` after leading whitespace, or `##[` anywhere.
    const commands = (text) => text.split('\n').filter((l) => /^\s*::/.test(l) || l.includes('##['));
    // The Lockfile column of a report's advisory rows: each row's last cell.
    const lockfileColumn = (text) => text.split('\n').filter((l) => /^\| \S+ [A-Z]+ \| /.test(l)).map((l) => (l.match(/ \| ([^|]*) \|$/) || [])[1]);
    const why = (r) => `exit ${r.status}, ${r.stdout.length} B stdout, stderr ${JSON.stringify(r.stderr.split('\n').find((l) => l.trim()) || '')}`;
    const HEADER = '## 📦 deps-currency';
    const once = (r) => r.stdout.split(HEADER).length === 2 && !r.stdout.includes('crashed');
    const expected = (level) => [
      `::${level} file=package-lock.json,title=deps-currency CRITICAL::CRITICAL lodash@4.17.4 GHSA-jf85-cpcp-j695, CVE-2019-10744 at package-lock.json`,
      `::${level} file=package-lock.json,title=deps-currency HIGH::HIGH evil ::error title=forged::pwned-name@1.0.0 GHSA-xxxx-yyyy-zzzz at package-lock.json`,
      `::${level} title=deps-currency HIGH::HIGH guzzlehttp/guzzle@6.5.0 GHSA-w248-ffj2-4v5q at /opt/outside-the-workspace/composer.lock`,
    ];

    // (A) On Actions, fail-on-vuln: summary + job log + one ::error per at/above-floor advisory.
    const a = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', FAIL_ON_VULN: 'true' });
    check('Actions run: three at/above-floor advisories BLOCK (exit 1)', a.status === 1, why(a));
    check('the step summary is the report, verdict included', a.summary.startsWith(HEADER) && a.summary.includes('\nBLOCKED — 3 dependency advisory(ies) at/above floor **HIGH**'), JSON.stringify(a.summary.slice(-200)));
    check('the job log carries the WHOLE report, byte for byte', a.summary.length > 0 && a.stdout.includes(a.summary));
    check('the report reaches the log once, not twice', once(a), why(a));
    check('the fixtures reached the report (the planted name flattened; the unpinned action; the LOW counted)',
      a.stdout.includes('evil ::error title=forged::pwned-name') && a.stdout.includes('oven-sh/setup-bun@v2.2.0') && a.stdout.includes('advisories in tree: **4** total'), why(a));
    check('one ::error per at/above-floor advisory — none for the LOW or the unpinned action, nothing else command-shaped',
      JSON.stringify(commands(a.stdout)) === JSON.stringify(expected('error')), JSON.stringify(commands(a.stdout)));
    check('annotations stay out of the step summary', commands(a.summary).length === 0);
    // The table names each lockfile as its annotation does: relative to the workspace, and the one outside it
    // by osv's own path. Until v1.29.5 every row named osv's absolute path, cut at 60.
    check('the report names each lockfile workspace-relative, the one outside the workspace by its own path',
      JSON.stringify(lockfileColumn(a.summary)) === JSON.stringify(['package-lock.json', 'package-lock.json', '/opt/outside-the-workspace/composer.lock']), JSON.stringify(lockfileColumn(a.summary)));

    // (A2) A working-directory below the repository root, the shape the defect was measured on: osv names
    // <workspace>/apps/web/package-lock.json, and the table and `file=` both read apps/web/package-lock.json,
    // relative to the repository root, not to the working directory.
    const web = path.join(tmp, 'apps', 'web');
    fs.mkdirSync(web, { recursive: true });
    fs.writeFileSync(path.join(web, 'package-lock.json'), '{}\n');
    const webReport = path.join(tmp, 'osv-apps-web.json');
    fs.writeFileSync(webReport, JSON.stringify({ results: [{ source: { path: path.join(web, 'package-lock.json'), type: 'lockfile' }, packages: osv.results[0].packages.slice(0, 1) }] }));
    const w = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', WORKING_DIRECTORY: web, OSV_STUB_FILE: webReport });
    fs.rmSync(path.join(tmp, 'apps'), { recursive: true, force: true });   // the cases below walk tmp for lockfiles
    check('working-directory apps/web: the table names apps/web/package-lock.json, relative to the repository root',
      JSON.stringify(lockfileColumn(w.summary)) === '["apps/web/package-lock.json"]', `${why(w)} ${JSON.stringify(lockfileColumn(w.summary))}`);
    check('…and so does the annotation', JSON.stringify(commands(w.stdout)) === JSON.stringify(
      ['::warning file=apps/web/package-lock.json,title=deps-currency CRITICAL::CRITICAL lodash@4.17.4 GHSA-jf85-cpcp-j695, CVE-2019-10744 at apps/web/package-lock.json']), JSON.stringify(commands(w.stdout)));

    // (B) Off Actions: stdout is the only output — the report prints once, with no commands.
    // spawnSync hands the child a SOCKET as stdout: the case that crashes an
    // `appendFileSync('/dev/stdout')` fallback on Linux (ENXIO) with nothing printed.
    for (const [label, extra] of [['local run', {}], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', { GITHUB_STEP_SUMMARY: '/dev/stdout' }]]) {
      const b = scan({ FAIL_ON_VULN: 'true', ...extra });
      check(`${label}: the report prints exactly once, verdict included, no crash`, b.status === 1 && once(b) && b.stdout.includes('\nBLOCKED — 3 dependency advisory(ies)'), why(b));
      check(`${label}: no workflow commands`, b.stdout.length > 0 && commands(b.stdout).length === 0, why(b));
    }

    // (C) report-mode (the default): the same advisories annotate as ::warning, and nothing blocks.
    const c = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true' });
    check('report-mode: exit 0', c.status === 0, why(c));
    check('report-mode: the advisories annotate as ::warning, never ::error', JSON.stringify(commands(c.stdout)) === JSON.stringify(expected('warning')), JSON.stringify(commands(c.stdout)));
    check('report-mode: the log still carries the whole report', c.summary.length > 0 && c.stdout.includes(c.summary) && c.summary.includes('report-only — 3 advisory(ies) at/above floor would BLOCK'));

    // (D) The summary sink itself fails: the report is already in the log (it is echoed first), the
    // fault is named there, and the exit is the caller's setting — our fault never blocks report-mode.
    const sinkDir = path.join(tmp, 'summary-is-a-dir');
    fs.mkdirSync(sinkDir);
    const d = scan({ GITHUB_STEP_SUMMARY: sinkDir, GITHUB_ACTIONS: 'true' });
    check('unwritable summary: the report still reaches the job log', d.stdout.includes(HEADER) && d.stdout.includes('report-only — 3 advisory(ies) at/above floor would BLOCK'), why(d));
    check('unwritable summary: the fault is named in the log', /deps-currency crashed: .*EISDIR/.test(d.stdout), why(d));
    check('unwritable summary: the crash note is ONE line (no stack frame starts a log line)', !/^\s+at /m.test(d.stdout), why(d));
    check('unwritable summary: the report reaches the log once', d.stdout.split(HEADER).length === 2);
    check('unwritable summary under report-mode: exit 0, not an unhandled throw', d.status === 0, why(d));

    // (E) What happened to the tracking issue reaches the log and the summary, once each, after the
    // report and before the annotations. manageIssue pushes it into `infra` only once the report,
    // scanner notes included, is out, so until v1.18.1 none of it printed: a workflow without
    // `issues: write` got a green run, no issue, and no word why. The stub gh lists GH_STUB_OPEN's
    // issue (or none), prints GH_STUB_LIST instead when it is set, refuses the verbs in GH_STUB_DENY
    // with a 403 whose second line is a planted workflow command, and appends every verb it runs to
    // GH_STUB_CALLS — so each row also pins what the run DID: a failed lookup must stop at `list`,
    // never go on to `create`, which duplicates an issue that is open. ECOSYSTEMS adds a scanner
    // note, which must stay in the report and only there.
    const gh = path.join(tmp, 'gh-stub');
    // GH_STUB_BODIES gets every --body it is handed, so a comment's text is asserted too. GH_STUB_BODY
    // gets the last one byte for byte, and a body over 65,536 bytes is refused, as GitHub refuses one
    // over 65,536 characters (bytes are never fewer).
    fs.writeFileSync(gh, String.raw`#!/bin/sh
[ "$1" = "--version" ] && { echo 'gh version 0.0.0-stub'; exit 0; }
[ -n "$GH_STUB_CALLS" ] && echo "$2" >> "$GH_STUB_CALLS"
[ -n "$GH_STUB_BODIES" ] && { prev=; for a in "$@"; do [ "$prev" = --body ] && printf '%s\n' "$a" >> "$GH_STUB_BODIES"; prev=$a; done; }
[ -n "$GH_STUB_BODY" ] && { prev=; for a in "$@"; do [ "$prev" = --body ] && printf '%s' "$a" > "$GH_STUB_BODY"; prev=$a; done; }
[ -n "$GH_STUB_BODY" ] && [ -f "$GH_STUB_BODY" ] && [ "$(wc -c < "$GH_STUB_BODY" | tr -d ' ')" -gt 65536 ] && { echo 'Body is too long (maximum is 65536 characters)' >&2; exit 1; }
case " $GH_STUB_DENY " in *" $2 "*) printf 'HTTP 403: Resource not accessible by integration\n::error title=forged::planted-by-gh\n' >&2; exit 1 ;; esac
[ "$2" = list ] && [ -n "$GH_STUB_LIST" ] && { echo "$GH_STUB_LIST"; exit 0; }
[ "$2" = list ] && { [ -n "$GH_STUB_OPEN" ] && printf '[{"number":%s,"title":"deps-currency: dependency advisories"}]\n' "$GH_STUB_OPEN" || echo '[]'; }
[ "$2" = create ] && [ -n "$GH_STUB_BREAK_SUMMARY" ] && { rm -f "$GITHUB_STEP_SUMMARY"; mkdir "$GITHUB_STEP_SUMMARY"; }
exit 0
`);
    fs.chmodSync(gh, 0o755);
    const count = (text, s) => text.split(s).length - 1;
    const DENIED = 'HTTP 403: Resource not accessible by integration ::error title=forged::planted-by-gh';
    const CLEAN = { OSV_STUB_CLEAN: '1', FIRST_PARTY_OWNERS: 'oven-sh' };   // no advisory, no unpinned action → close
    const LOOKUP = 'failed to look up the tracking issue:';
    // osv-scanner's API failure: exit 129, nothing on stdout, its error last on stderr.
    const API_DOWN = { OSV_STUB_EXIT: '129', OSV_STUB_OUT: '', OSV_STUB_ERR: 'Scanning dir .\nfailed to query the OSV API: 503 Service Unavailable' };
    const HELD = 'osv-scanner could not look, so this sweep has no verdict';
    const lifecycle = [   // [case, env, the one note it prints (null: none), the gh verbs it runs]
      ['no issue open, create succeeds', {}, 'opened tracking issue', 'list create'],
      ['no issue open, create refused (403)', { GH_STUB_DENY: 'create' }, `failed to open tracking issue: ${DENIED}`, 'list create'],
      ['#7 open, comment succeeds', { GH_STUB_OPEN: '7' }, 'updated tracking issue #7', 'list comment'],
      ['#7 open, comment refused (403)', { GH_STUB_OPEN: '7', GH_STUB_DENY: 'comment' }, `failed to update tracking issue #7: ${DENIED}`, 'list comment'],
      ['clean, #7 open, close succeeds', { ...CLEAN, GH_STUB_OPEN: '7' }, 'closed tracking issue #7 — the sweep is clean', 'list comment close'],
      ['clean, #7 open, close refused (403)', { ...CLEAN, GH_STUB_OPEN: '7', GH_STUB_DENY: 'comment close' }, `failed to close issue #7: ${DENIED}`, 'list comment close'],
      ['clean, no issue open', CLEAN, null, 'list'],
      // The lookup itself fails. #7 IS open in each, so a run that read the failure as "none open"
      // would create a duplicate (dirty) or leave #7 open and say nothing (clean).
      ['dirty, #7 open, lookup refused (403)', { GH_STUB_OPEN: '7', GH_STUB_DENY: 'list' }, `${LOOKUP} ${DENIED} — nothing opened or updated`, 'list'],
      ['clean, #7 open, lookup refused (403)', { ...CLEAN, GH_STUB_OPEN: '7', GH_STUB_DENY: 'list' }, `${LOOKUP} ${DENIED} — nothing closed`, 'list'],
      ['dirty, #7 open, lookup prints no JSON', { GH_STUB_OPEN: '7', GH_STUB_LIST: 'Resource not accessible by integration' }, `${LOOKUP} gh printed no JSON list — nothing opened or updated`, 'list'],
      ['clean, #7 open, lookup prints JSON but no list', { ...CLEAN, GH_STUB_OPEN: '7', GH_STUB_LIST: '{"number":7}' }, `${LOOKUP} gh printed no JSON list — nothing closed`, 'list'],
      // osv-scanner could not look: no verdict, so the issue is neither opened nor closed, and an open
      // one gets a comment saying why it did not move. The first row is the defect v1.19.4 fixes:
      // nothing else found, so the old code read the sweep as clean and CLOSED #7 as resolved.
      ['osv could not look, nothing else found, #7 open', { ...API_DOWN, FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7' }, `tracking issue #7 left open, with a comment — ${HELD}`, 'list comment'],
      ['osv could not look, an unpinned action found, #7 open', { ...API_DOWN, GH_STUB_OPEN: '7' }, `tracking issue #7 left open, with a comment — ${HELD}`, 'list comment'],
      ['osv could not look, #7 open, comment refused (403)', { ...API_DOWN, GH_STUB_OPEN: '7', GH_STUB_DENY: 'comment' }, `tracking issue #7 left open — osv-scanner could not look; the comment failed: ${DENIED}`, 'list comment'],
      ['osv could not look, an unpinned action found, no issue open', API_DOWN, `no tracking issue opened — ${HELD}`, 'list'],
      ['osv could not look, #7 open, lookup refused (403)', { ...API_DOWN, GH_STUB_OPEN: '7', GH_STUB_DENY: 'list' }, `${LOOKUP} ${DENIED} — nothing commented`, 'list'],
      // null: with no gh binary nothing runs to record a verb, so a verbs check there cannot fail. The
      // note check covers the have() guard: without it this row notes a failed lookup instead.
      ['no gh', { GH_BIN: path.join(tmp, 'no-such-gh') }, 'gh CLI not available — issue management skipped', null],
      ['no GITHUB_REPOSITORY', { GITHUB_REPOSITORY: '' }, 'GITHUB_REPOSITORY unset — issue management skipped', ''],
    ];
    const calls = path.join(tmp, 'gh-calls');
    const ran = () => (fs.existsSync(calls) ? fs.readFileSync(calls, 'utf8').trim().split('\n').join(' ') : '');
    // One run with the stub recording: what it printed, the gh verbs it ran, the bodies it sent.
    const bodies = path.join(tmp, 'gh-bodies');
    const scanGh = (extra) => {
      for (const f of [calls, bodies]) fs.rmSync(f, { force: true });
      const r = scan({ GH_STUB_CALLS: calls, GH_STUB_BODIES: bodies, ...extra });
      return { ...r, verbs: ran(), body: fs.existsSync(bodies) ? fs.readFileSync(bodies, 'utf8') : '' };
    };
    for (const [label, extra, note, verbs] of lifecycle) {
      const env = { GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, GH_STUB_CALLS: calls, ECOSYSTEMS: 'npm cobol', ...extra };
      fs.rmSync(calls, { force: true });
      const off = scan({ ...env, MANAGE_ISSUE: 'false' });
      const ranOff = ran();
      fs.rmSync(calls, { force: true });
      const on = scan({ ...env, MANAGE_ISSUE: 'true' });
      const block = note ? `\n### ℹ️ issue lifecycle\n- ${note}\n` : '';
      if (note) check(`issue lifecycle, ${label}: note in the log once, the summary once`, count(on.stdout, `\n- ${note}\n`) === 1 && count(on.summary, `\n- ${note}\n`) === 1, why(on));
      check(`issue lifecycle, ${label}: report byte-identical, ${note ? 'block before the annotations' : 'no block'}, same exit, no new command`,
        off.summary.includes('unknown ecosystem') && on.summary === off.summary + block && on.stdout === on.summary + off.stdout.slice(off.summary.length)
          && on.status === off.status && JSON.stringify(commands(on.stdout)) === JSON.stringify(commands(off.stdout)), JSON.stringify(on.stdout.slice(off.summary.length - 60)));
      if (verbs !== null) check(`issue lifecycle, ${label}: gh verbs run — ${verbs || 'none'}`, ranOff === '' && ran() === verbs, JSON.stringify({ off: ranOff, on: ran() }));
    }

    // (F) The summary turns unwritable while the issue opens: the block is in the log anyway, because
    // emit() writes the log first; the fault is named, and report-mode still exits 0.
    const f = scan({ GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true', GH_STUB_BREAK_SUMMARY: '1' });
    check('issue lifecycle, summary gone unwritable: the block still reaches the log, once', count(f.stdout, '\n### ℹ️ issue lifecycle\n- opened tracking issue\n') === 1, why(f));
    check('…the fault is named in the log, and report-mode exits 0', /deps-currency crashed: .*EISDIR/.test(f.stdout) && f.status === 0, why(f));

    // (G) osv-scanner could not look. Its API failure exits 129 with nothing on stdout, which until
    // v1.19.2 parsed as `{}`: "PASS — no dependency advisories", and the "clean" sweep CLOSED the open
    // advisories issue as resolved. Now it is no verdict: a scanner note naming osv's exit and error
    // line, never PASS, the issue neither opened nor closed, and the exit a tool fault's —
    // fail-on-vuln ? 1 : 0. Exit 128 is the one non-zero exit that can have looked: when the tree has no
    // lockfile, or osv read every one and found no package in it (v1.19.5).
    fs.rmSync(summaryPath, { recursive: true, force: true });   // (F) left a directory there; scan() only removes a file
    const REAL = fs.realpathSync(tmp);   // osv-scanner prints real paths (macOS: /var → /private/var)
    const EMPTY_TREE = path.join(tmp, 'empty-tree');
    fs.mkdirSync(EMPTY_TREE, { recursive: true });
    const NOTE ='osv-scanner could not look — exit 129: failed to query the OSV API: 503 Service Unavailable';
    const blindly = (fov) => (fov === 'true'
      ? '\nFAULT — osv-scanner could not look, so the dependency tree was not audited. No verdict: a tool fault in deps-currency, not a finding about this repository.\n'
      : '\nreport-only — osv-scanner could not look, so the dependency tree was not audited: no verdict. Under `fail-on-vuln: true` this run would FAULT.\n');
    const verdictless = (r) => !r.stdout.includes('PASS —') && !r.stdout.includes('✅') && !r.stdout.includes('BLOCKED —')
      && r.stdout.includes('\n- advisories in tree: **unknown** — osv-scanner could not look\n') && r.stdout.includes('\n**at/above floor: unknown — osv-scanner could not look · ');
    for (const fov of ['false', 'true']) {
      const g = scanGh({ ...API_DOWN, FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7', FAIL_ON_VULN: fov, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true' });
      const level = fov === 'true' ? 'error' : 'warning';
      check(`osv exit 129, fail-on-vuln ${fov}: exit ${fov === 'true' ? 1 : 0} — a tool fault, ${fov === 'true' ? 'never a pass for an enforcing caller' : 'never a block for a report-mode caller'}`, g.status === (fov === 'true' ? 1 : 0), why(g));
      check(`osv exit 129, fail-on-vuln ${fov}: the scanner note names the exit and osv's error line — log once, summary once`, count(g.stdout, `\n- ${NOTE}\n`) === 1 && count(g.summary, `\n- ${NOTE}\n`) === 1, why(g));
      check(`osv exit 129, fail-on-vuln ${fov}: no verdict — never PASS, never ✅, no count`, verdictless(g) && g.stdout.includes(blindly(fov)), why(g));
      check(`osv exit 129, fail-on-vuln ${fov}: #7 neither closed nor re-opened — looked up, commented on`, g.verbs === 'list comment', g.verbs);
      check(`osv exit 129, fail-on-vuln ${fov}: the comment names the fault and says #7 stays open`,
        /^No verdict as of \d{4}-\d{2}-\d{2}: /.test(g.body) && g.body.includes(`: ${NOTE}. This sweep neither updates nor closes this issue; it stays open until a sweep that looked comes back clean.`) && !g.body.includes('Resolved'), JSON.stringify(g.body));
      check(`osv exit 129, fail-on-vuln ${fov}: one ::${level} names the fault for the check-run API, nothing else is command-shaped`,
        JSON.stringify(commands(g.stdout)) === JSON.stringify([`::${level} title=deps-currency could not look::${NOTE}`]), JSON.stringify(commands(g.stdout)));

      // 128 having read the tree's lockfile and found no package in it, as v2.4.0 says of a valid lockfile
      // with no dependency: it looked, and there was nothing to audit. Clean.
      const n = scanGh({ OSV_STUB_EXIT: '128', OSV_STUB_OUT: '', OSV_STUB_ERR: `Scanning dir .\nScanned ${REAL}/package-lock.json file and found 0 packages\nNo package sources found, --help for usage information.`, FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7', FAIL_ON_VULN: fov, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true' });
      check(`osv exit 128, lockfile read empty, fail-on-vuln ${fov}: PASS, exit 0`,
        n.status === 0 && n.stdout.includes('\n- advisories in tree: **0** total · **0** at/above floor\n') && n.stdout.includes('\nPASS — no dependency advisories at or above the severity floor.') && !n.stdout.includes('could not look'), why(n));
      check(`osv exit 128, fail-on-vuln ${fov}: the sweep is clean, so #7 closes — and nothing annotates`,
        n.verbs === 'list comment close' && count(n.stdout, '\n- closed tracking issue #7 — the sweep is clean\n') === 1 && commands(n.stdout).length === 0, n.verbs);
      // 128 in a tree with no lockfile at all: nothing to audit either.
      const e = scanGh({ OSV_STUB_EXIT: '128', OSV_STUB_OUT: '', OSV_STUB_ERR: 'Scanning dir .\nNo package sources found, --help for usage information.', WORKING_DIRECTORY: EMPTY_TREE, FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7', FAIL_ON_VULN: fov, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true' });
      check(`osv exit 128, no lockfile, fail-on-vuln ${fov}: PASS, exit 0, #7 closes`,
        e.status === 0 && e.stdout.includes('\n- lockfiles scanned: (none found)\n') && e.stdout.includes('\nPASS — no dependency advisories at or above the severity floor.') && !e.stdout.includes('could not look') && e.verbs === 'list comment close', `${why(e)} gh=${e.verbs}`);
    }
    // Every other way osv-scanner can fail to look, end to end: the same no verdict, #7 held.
    const shapes = [   // [case, env, the note's reason]
      ['exit 127, nothing on stdout — an unreachable osv.dev, as measured on v2.4.0', { OSV_STUB_EXIT: '127', OSV_STUB_ERR: 'dial tcp: lookup api.osv.dev: no such host' }, 'exit 127: dial tcp: lookup api.osv.dev: no such host'],
      ['exit 130, an invalid config', { OSV_STUB_EXIT: '130', OSV_STUB_ERR: 'invalid config' }, 'exit 130: invalid config'],
      ['exit 128, a lockfile it could not parse',
        { OSV_STUB_EXIT: '128', OSV_STUB_ERR: `Scanning dir .\nError during extraction: (extracting as javascript/packagelockjson) ${REAL.slice(1)}/package-lock.json: could not extract: unexpected end of JSON input\nNo package sources found, --help for usage information.` },
        'exit 128: Error during extraction: extracting as javascript/packagelockjson package-lock.json: could not extract: unexpected end of JSON input'],
      ['exit 128, no lockfile read (as with a bun.lockb)', { OSV_STUB_EXIT: '128', OSV_STUB_ERR: 'Scanning dir .\nNo package sources found, --help for usage information.' },
        "exit 128: it read none of the tree's lockfiles: package-lock.json"],
      ['exit 0 with an EMPTY stdout — what the old code parsed as {}', { OSV_STUB_EXIT: '0' }, 'exit 0: no JSON report'],
      ['exit 0, a report cut short — the old "treated as clean"', { OSV_STUB_EXIT: '0', OSV_STUB_OUT: '{"results":[{"source":' }, 'exit 0: no JSON report'],
      ['exit 1 with no results in its report', { OSV_STUB_EXIT: '1', OSV_STUB_OUT: '{"results":[]}' }, 'exit 1, vulnerabilities found, with no results in its report'],
      ['osv-scanner not installed — the old code closed the issue then too', { OSV_BIN: path.join(tmp, 'no-such-osv-scanner') }, 'not installed'],
      ['a working-directory that is not there', { WORKING_DIRECTORY: path.join(tmp, 'no-such-dir') }, 'working-directory '],
      ['killed after printing its whole report, as a timeout kills it', { OSV_STUB_KILL: '1' }, 'killed by SIGKILL'],
    ];
    for (const [label, extra, reason] of shapes) {
      for (const fov of ['false', 'true']) {
        const s = scanGh({ FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7', FAIL_ON_VULN: fov, GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true', ...extra });
        check(`could not look, ${label}, fail-on-vuln ${fov}: noted, no verdict, #7 held, exit ${fov === 'true' ? 1 : 0}`,
          s.stdout.includes(`\n- osv-scanner could not look — ${reason}`) && verdictless(s) && s.stdout.includes(blindly(fov))
            && s.verbs === 'list comment' && s.status === (fov === 'true' ? 1 : 0), `${why(s)} gh=${s.verbs}`);
      }
    }
    // A failed run that still reported something: its advisories are listed (they are real) and marked
    // incomplete, the run is still no verdict, and the fault's annotation counts toward GitHub's 10.
    const many = { results: [{ source: { path: path.join(tmp, 'package-lock.json') }, packages: Array.from({ length: 12 }, (_, i) => (
      { package: { name: `pkg-${String(i).padStart(2, '0')}`, version: '1.0.0', ecosystem: 'npm' }, groups: [{ ids: [`GHSA-${i}`], max_severity: '9.8' }] })) }] };
    const p = scanGh({ OSV_STUB_EXIT: '2', OSV_STUB_OUT: JSON.stringify(many), FIRST_PARTY_OWNERS: 'oven-sh', GH_STUB_OPEN: '7', GITHUB_STEP_SUMMARY: summaryPath, GITHUB_ACTIONS: 'true', GH_BIN: gh, MANAGE_ISSUE: 'true' });
    check('exit 2 with a report: its 12 advisories listed, marked incomplete — still no verdict, #7 held',
      p.stdout.includes('### Vulnerable / advisory-flagged dependencies (12)') && p.stdout.includes('_osv-scanner could not finish, so this list may be incomplete._')
        && p.stdout.includes('\n- osv-scanner could not look — exit 2') && verdictless(p) && p.verbs === 'list comment' && p.status === 0, why(p));
    const pc = commands(p.stdout);
    check('…annotations: the fault first, then 9 advisories — GitHub keeps 10 — and one line counting the other 3',
      pc.length === 10 && pc[0].startsWith('::warning title=deps-currency could not look::') && pc.slice(1).every((l) => l.startsWith('::warning file=package-lock.json,'))
        && p.stdout.includes('\ndeps-currency: 3 more advisory(ies) not annotated (GitHub keeps 10 per step)'), JSON.stringify(pc.map((l) => l.slice(0, 60))));

    // (H) The issue body stays under GitHub's limit (v1.29.4). GitHub refuses an issue or comment body
    // over 65,536 characters, and past 128 KiB Linux will not start gh with it; either was one lifecycle
    // note in a green run, so the issue went missing when the tree carried the most advisories. The real
    // manageIssue, the stub gh keeping the exact --body: 900 advisories under `severity-floor: LOW`,
    // handed over LOW first so the order is the engine's, every other one in a Greek-named directory
    // (two bytes a letter). Their body must come back at most 60,000 bytes: the report's head, whole
    // rows from the top, the rest of the report, and a note counting the rows left out.
    const runUrl = (id) => `https://github.com/creme-ypsilon/lampakia-astro/actions/runs/${id}`;
    const RULE = '|---|---|---|---|---|---|';
    const rankOf = (row) => ({ CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3 })[(row.match(/^\| \S+ ([A-Z]+) \|/) || [])[1]] ?? 9;
    const LOCK = '/home/runner/work/lampakia-astro/lampakia-astro/package-lock.json';
    const GREEK = '/home/runner/work/ηλεκτρολογικά/ηλεκτρολογικά/εφαρμογή/package-lock.json';
    const osvFile = path.join(tmp, 'osv-report.json');
    const bodyFile = path.join(tmp, 'gh-body');
    // `plan`: [[severity, how many], …] in the order osv lists them, one package each. `pad(i)` lengthens
    // the i-th package's name: safe() keeps 60 characters, 46 past `@acme/pkg-0000`.
    const advisories = (plan, where = () => LOCK, pad = () => '') => {
      const by = new Map();
      let i = 0;
      for (const [sev, n] of plan) for (let j = 0; j < n; j++, i++) {
        const id = String(i).padStart(4, '0');
        if (!by.has(where(i))) by.set(where(i), []);
        by.get(where(i)).push({ package: { name: `@acme/pkg-${id}${pad(i)}`, version: '4.17.21', ecosystem: 'npm' },
          groups: [{ ids: [`GHSA-${id}-q2w3-e4r5`, `CVE-2021-2${id}`], max_severity: { CRITICAL: '9.8', HIGH: '7.5', MODERATE: '5.3', LOW: '3.1' }[sev] }] });
      }
      fs.writeFileSync(osvFile, JSON.stringify({ results: [...by].map(([p, packages]) => ({ source: { path: p, type: 'lockfile' }, packages })) }));
    };
    // One run that opens the issue (or, GH_STUB_OPEN, comments on it): the report as the log carries it,
    // the exact body gh was handed (null: none), and v1.29.3's body for that report — its lead, then all of it.
    const post = (extra = {}) => {
      fs.rmSync(bodyFile, { force: true });
      const id = extra.GITHUB_RUN_ID || '33911783576';
      const r = scanGh({ OSV_STUB_FILE: osvFile, SEVERITY_FLOOR: 'LOW', GITHUB_RUN_ID: id, GITHUB_STEP_SUMMARY: summaryPath, GH_BIN: gh, MANAGE_ISSUE: 'true', GH_STUB_BODY: bodyFile, ...extra });
      const at = r.summary.indexOf('\n\n**at/above floor: ');
      const report = at < 0 ? '' : r.summary.slice(0, at);
      const sent = fs.existsSync(bodyFile) ? fs.readFileSync(bodyFile) : null;
      const stamp = (String(sent || '').match(/^Scheduled [^\n]* \((\d{4}-\d{2}-\d{2})\)\.\n/) || [])[1];
      const lead = `Scheduled dependency-currency sweep found advisories on **creme-ypsilon/lampakia-astro** (${stamp}).\n\nRun: ${runUrl(id)}\n\nThis issue auto-closes when the next scheduled run is clean.\n\n`;
      return { ...r, id, report, sent, lead, before: Buffer.from(lead + report) };
    };
    // What a cut body owes, each property on its own; `kept` and `rows` are the body's and the report's.
    const grade = (r) => {
      const text = String(r.sent || '');
      const m = text.startsWith(r.lead) ? text.slice(r.lead.length).match(/^([\s\S]*)\n\n\(truncated — (\d+) more rows; the full report is in the run log: (\S+)\)$/) : null;
      const lines = m ? `${m[1]}\n`.split('\n') : [];   // the report's own trailing newline put back
      const rep = r.report.split('\n');
      const first = rep.indexOf(RULE) + 1;
      let end = first;
      while (first && end < rep.length && rep[end].startsWith('| ')) end++;
      let k = first;
      while (k < lines.length && lines[k].startsWith('| ')) k++;
      const rows = rep.slice(first, end);
      const kept = lines.slice(first, k);
      const have = new Set(rep);
      return { rows, kept,
        size: !!r.sent && r.sent.length <= 60000 && text.length <= 65536,
        shape: !!m && m[3] === runUrl(r.id),
        head: first > 0 && lines.slice(0, first).join('\n') === rep.slice(0, first).join('\n'),
        whole: lines.length > 0 && lines.every((l) => have.has(l)) && new Set(kept).size === kept.length,
        top: kept.length > 0 && kept.join('\n') === rows.slice(0, kept.length).join('\n'),
        tail: k < lines.length && lines.slice(k).join('\n') === rep.slice(end).join('\n'),
        count: !!m && Number(m[2]) === rows.length - kept.length,
        fill: !!r.sent && kept.length < rows.length && 60000 - r.sent.length < Buffer.byteLength(rows[kept.length]) + 11 };
    };

    advisories([['LOW', 400], ['MODERATE', 300], ['HIGH', 150], ['CRITICAL', 50]], (i) => (i % 2 ? GREEK : LOCK));
    const big = post();
    const g = grade(big);
    check('issue body, 900 advisories handed over LOW first: listed CRITICAL first, v1.29.3\'s body past 128 KiB',
      g.rows.length === 900 && rankOf(g.rows[0]) === 0 && g.rows.every((row, i) => !i || rankOf(g.rows[i - 1]) <= rankOf(row)) && big.before.length > 131072, `${big.before.length} B`);
    check('…the issue opens', big.verbs === 'list create' && count(big.stdout, '\n- opened tracking issue\n') === 1, why(big));
    check('…its body is at most 60,000 bytes', g.size, `${big.sent && big.sent.length} B`);
    check('…the lead, then the report cut, then the note with the run URL', g.shape);
    check('…the report\'s head kept, the table\'s header rows included', g.head);
    check('…whole rows only, each one of the report\'s', g.whole);
    check('…the rows kept are the report\'s first ones', g.top);
    const by = [0, 1, 2, 3].map((n) => g.kept.filter((row) => rankOf(row) === n).length);
    check(`…every CRITICAL and HIGH row, the cut inside MODERATE, no LOW (kept ${by.join('/')})`, by[0] === 50 && by[1] === 150 && by[2] > 0 && by[2] < 300 && by[3] === 0);
    check('…the rest of the report follows whole, the unpinned action too', g.tail && big.sent && String(big.sent).includes('oven-sh/setup-bun@v2.2.0'));
    check(`…the note counts the ${900 - g.kept.length} rows left out`, g.count);
    check('…and fills the room: the first row left out would not fit', g.fill, `${big.sent && big.sent.length} B`);
    check('…the job log still carries all 900 rows', big.stdout.includes(big.report) && g.rows.length === 900);
    const again = post({ GH_STUB_OPEN: '7' });
    check('…#7 open: the comment carries the same cut body',
      again.verbs === 'list comment' && count(again.stdout, '\n- updated tracking issue #7\n') === 1 && !!big.sent && String(again.sent) === again.lead + String(big.sent).slice(big.lead.length), why(again));
    // LOCK and GREEK sit outside this workspace, so every row in these legs names osv's path cut at 60, as
    // every row did until v1.29.5: their rows and counts are v1.29.3's, which keeps "v1.29.3's body" literal.
    // In the workspace, as a real run's lockfiles are, a row names its lockfile workspace-relative: 43 bytes
    // shorter than LOCK's, 60 than GREEK's, so more rows fit under the same cap.
    advisories([['LOW', 400], ['MODERATE', 300], ['HIGH', 150], ['CRITICAL', 50]], (i) => path.join(tmp, i % 2 ? 'εφαρμογή' : '', 'package-lock.json'));
    const near = grade(post());
    const named = [...new Set(lockfileColumn(near.kept.join('\n')))].sort().join(' ');
    check(`…the same 900 in the workspace: rows name their lockfiles workspace-relative, so ${near.kept.length} fit where ${g.kept.length} did — cut to at most 60,000, whole rows from the top, the rest counted`,
      named === 'package-lock.json εφαρμογή/package-lock.json' && near.kept.length > g.kept.length
        && near.size && near.shape && near.head && near.whole && near.top && near.tail && near.count && near.fill, named);

    // A report under the cap goes as v1.29.3 posted it, byte for byte, on both paths.
    advisories([['MODERATE', 1], ['CRITICAL', 1], ['LOW', 1]], (i) => (i === 1 ? GREEK : LOCK));
    const small = post();
    check('issue body, 3 advisories: v1.29.3\'s body, byte for byte', small.verbs === 'list create' && !!small.sent && small.sent.equals(small.before), why(small));
    const smallAgain = post({ GH_STUB_OPEN: '7' });
    check('…and the comment on #7 too', smallAgain.verbs === 'list comment' && !!smallAgain.sent && smallAgain.sent.equals(smallAgain.before), why(smallAgain));

    // The boundary, both sides: HIGH rows of one width, the run ID padded until v1.29.3's body is exactly
    // 60,000 bytes, then one byte more.
    advisories([['HIGH', 300]]);
    const base = post();
    const width = Buffer.byteLength(grade(base).rows[0] || '') + 1;
    const n = 300 + Math.floor((60000 - base.before.length) / width);
    advisories([['HIGH', n]]);
    const pad = 60000 - (base.before.length + (n - 300) * width);
    const exact = post({ GITHUB_RUN_ID: `33911783576${'0'.repeat(pad)}` });
    check(`issue body, ${n} rows built to a v1.29.3 body of exactly 60,000 bytes: posted whole`, exact.before.length === 60000 && !!exact.sent && exact.sent.equals(exact.before), `${exact.before.length} B`);
    const over = post({ GITHUB_RUN_ID: `33911783576${'0'.repeat(pad + 1)}` });
    const o = grade(over);
    check('…one byte more: cut to at most 60,000, whole rows from the top, the rest counted',
      over.before.length === 60001 && o.size && o.shape && o.head && o.whole && o.top && o.tail && o.count && o.fill, `${over.sent && over.sent.length} B`);
    check('…no table to cut: an over-cap body goes whole, with no note', capIssueBody('', `${'x'.repeat(60001)}\n`, runUrl(1)) === `${'x'.repeat(60001)}\n`);

    // (I) The step summary stays under GitHub's limit (v1.29.6). GitHub drops a step summary over 1 MiB (the
    // upload fails with an error annotation, so the run shows none), so the report's block is cut for the
    // summary alone, as the issue body is: the head, whole rows from the top, the rest of the block — scanner
    // notes and verdict included — and a note counting the rows left out, at most 900,000 bytes. The log
    // keeps every row. No gh and no annotations here, so a run's log is its block whole.
    const CAP = 900000;
    const RUN_ID = '33911783576';
    const sweep = (extra = {}, script = undefined) => scan({ OSV_STUB_FILE: osvFile, SEVERITY_FLOOR: 'LOW', GITHUB_RUN_ID: RUN_ID, GITHUB_STEP_SUMMARY: summaryPath, ...extra }, script);
    // What a cut summary owes against its block (`log`), each property on its own.
    const fitted = (summary, log, cap = CAP) => {
      const m = summary.match(/^([\s\S]*)\n\n\(truncated — (\d+) more rows; the full report is in the run log: (\S+)\)\n$/);
      const lines = m ? `${m[1]}\n`.split('\n') : [];
      const rep = log.split('\n');
      const first = rep.indexOf(RULE) + 1;
      let end = first;
      while (first && end < rep.length && rep[end].startsWith('| ')) end++;
      let k = first;
      while (k < lines.length && lines[k].startsWith('| ')) k++;
      const rows = rep.slice(first, end);
      const kept = lines.slice(first, k);
      const left = rows.length - kept.length;
      const size = Buffer.byteLength(summary);
      const have = new Set(rep);
      return { rows, kept, size,
        under: size <= cap,
        shape: !!m && m[3] === runUrl(RUN_ID),
        head: first > 0 && lines.slice(0, first).join('\n') === rep.slice(0, first).join('\n'),
        whole: lines.length > 0 && lines.every((l) => have.has(l)) && new Set(kept).size === kept.length,
        top: kept.join('\n') === rows.slice(0, kept.length).join('\n'),
        tail: k < lines.length && lines.slice(k).join('\n') === rep.slice(end).join('\n'),
        count: !!m && Number(m[2]) === left,
        // The first row left out would not fit, its note budgeted at the longest (every row left out).
        fill: left > 0 && cap - size - (String(rows.length).length - String(left).length) < Buffer.byteLength(rows[kept.length]) + 1 };
    };
    const owed = (f) => f.under && f.shape && f.head && f.whole && f.top && f.tail && f.count && f.fill;
    const PLAN = [['LOW', 2500], ['MODERATE', 2500], ['HIGH', 1500], ['CRITICAL', 500]];
    advisories(PLAN, (i) => (i % 2 ? GREEK : LOCK));
    const huge = sweep({ ECOSYSTEMS: 'npm cobol' });
    const h = fitted(huge.summary, huge.stdout);
    check('summary, 7,000 advisories handed over LOW first: listed CRITICAL first, the block past 1 MiB',
      h.rows.length === 7000 && rankOf(h.rows[0]) === 0 && h.rows.every((row, i) => !i || rankOf(h.rows[i - 1]) <= rankOf(row)) && Buffer.byteLength(huge.stdout) > 1048576, `${Buffer.byteLength(huge.stdout)} B`);
    check('…exit 0 (report mode), the block in the log once, every row', huge.status === 0 && huge.stdout.split(HEADER).length === 2 && h.rows.length === 7000, why(huge));
    check('…the summary is at most 900,000 bytes', h.under, `${h.size} B`);
    check('…the block cut, then the note with the run URL', h.shape);
    check('…the head kept, the table\'s header rows included', h.head);
    check('…whole rows only, each one of the log\'s', h.whole);
    check('…the rows kept are the log\'s first ones', h.kept.length > 0 && h.top);
    const sev = [0, 1, 2, 3].map((n) => h.kept.filter((row) => rankOf(row) === n).length);
    check(`…every CRITICAL, HIGH and MODERATE row, the cut inside LOW (kept ${sev.join('/')})`, sev[0] === 500 && sev[1] === 1500 && sev[2] === 2500 && sev[3] > 0 && sev[3] < 2500);
    check('…the rest of the block follows whole: the unpinned action, the scanner notes, the verdict',
      h.tail && huge.summary.includes('oven-sh/setup-bun@v2.2.0') && huge.summary.includes("\n- unknown ecosystem 'cobol'") && huge.summary.includes('\nreport-only — 7000 advisory(ies)'));
    check(`…the note counts the ${7000 - h.kept.length} rows left out`, h.count);
    check('…and fills the room: the first row left out would not fit', h.fill, `${h.size} B`);

    // The boundary, both sides: HIGH rows of one width, then the first names lengthened until the block is
    // exactly 900,000 bytes — the summary must be the block, byte for byte — then one byte more.
    advisories([['HIGH', 1000]]);
    const at1k = sweep();
    const rowWidth = Buffer.byteLength(fitted(at1k.summary, at1k.stdout).rows[0] || '') + 1;
    const rowsAtCap = 1000 + Math.floor((CAP - Buffer.byteLength(at1k.stdout)) / rowWidth);
    const padBytes = CAP - Buffer.byteLength(at1k.stdout) - (rowsAtCap - 1000) * rowWidth;
    const spread = (bytes) => (i) => 'x'.repeat(Math.max(0, Math.min(46, bytes - 46 * i)));
    advisories([['HIGH', rowsAtCap]], undefined, spread(padBytes));
    const atCap = sweep();
    check(`summary, ${rowsAtCap} rows built to a block of exactly 900,000 bytes: the summary is the block, byte for byte`,
      Buffer.byteLength(atCap.stdout) === CAP && atCap.summary === atCap.stdout, `${Buffer.byteLength(atCap.stdout)} B`);
    advisories([['HIGH', rowsAtCap]], undefined, spread(padBytes + 1));
    const pastCap = sweep();
    check('…one byte more: cut to at most 900,000, whole rows from the top, the rest counted',
      Buffer.byteLength(pastCap.stdout) === CAP + 1 && owed(fitted(pastCap.summary, pastCap.stdout)), `${Buffer.byteLength(pastCap.summary)} B`);

    // capSummary at every cap from its floor (head, tail and the longest note) to past the block: an
    // off-by-one anywhere in the budget breaks one of these at some cap.
    const sample = [renderReport(filterByFloor(Array.from({ length: 40 }, (_, i) => ({ name: `pkg-${i}`, version: '1.0.0', ids: [`GHSA-${i}`],
      severity: ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'][i % 4], score: 5, source: i % 3 ? LOCK : GREEK })), 'LOW'), [], { floor: 'LOW' }),
    '', '**at/above floor: 40 · unpinned-action advisories: 0**', 'report-only — 40 advisory(ies) at/above floor would BLOCK.'].join('\n');
    const block = `${sample}\n`;
    const lo = Buffer.byteLength(capSummary(sample, runUrl(RUN_ID), 0));
    const bad = [];
    for (let cap = lo; cap <= Buffer.byteLength(block) + 1; cap++) {
      const out = capSummary(sample, runUrl(RUN_ID), cap);
      if (Buffer.byteLength(block) <= cap ? out !== block : !owed(fitted(out, block, cap))) bad.push(cap);
    }
    check(`capSummary at every cap from ${lo} to ${Buffer.byteLength(block) + 1} bytes: whole at or under the cap, else cut as owed`, lo < 2000 && bad.length === 0, `wrong at ${bad.slice(0, 5).join(', ')}`);
    check('…no table to cut: an over-cap block goes whole, with no note', capSummary('x'.repeat(CAP), runUrl(1)) === `${'x'.repeat(CAP)}\n`);

    // A fault in the cut costs the summary that block, never the run: the log keeps the block whole and names
    // the fault in one plain line, and the exit is the run's own. A copy of the scripts whose capSummary throws.
    const faulty = path.join(tmp, 'faulty');
    fs.mkdirSync(faulty);
    const engineSource = fs.readFileSync(path.join(HERE, 'engine.mjs'), 'utf8');
    const CUT = 'export function capSummary(text, runUrl, cap = SUMMARY_CAP) {';
    check('fault-injection anchor still present in engine.mjs', engineSource.includes(CUT));
    fs.writeFileSync(path.join(faulty, 'engine.mjs'), engineSource.replace(CUT, `${CUT} throw new Error('injected cut fault');`));
    fs.copyFileSync(path.join(HERE, 'scan.mjs'), path.join(faulty, 'scan.mjs'));
    advisories(PLAN, (i) => (i % 2 ? GREEK : LOCK));
    const FAULT = "deps-currency: the report is over the step summary's limit and could not be cut, so the summary does not carry it; the job log above holds every row (injected cut fault)";
    const sunk = sweep({ ECOSYSTEMS: 'npm cobol' }, path.join(faulty, 'scan.mjs'));
    check('a fault in the cut: the log is the block whole, then one plain line naming it; no summary; exit 0',
      sunk.stdout === `${huge.stdout}${FAULT}\n` && sunk.summary === '' && sunk.status === 0, `${why(sunk)} ${JSON.stringify(sunk.stdout.slice(-200))}`);
    const sunkEnforcing = sweep({ ECOSYSTEMS: 'npm cobol', FAIL_ON_VULN: 'true' }, path.join(faulty, 'scan.mjs'));
    check('…under fail-on-vuln: the advisories still BLOCK (exit 1), the fault a line, not a crash',
      sunkEnforcing.status === 1 && sunkEnforcing.stdout.endsWith(`\nBLOCKED — 7000 dependency advisory(ies) at/above floor **LOW** with \`fail-on-vuln: true\`. Bump/remove the package(s), or lower the floor / document the exposure.\n${FAULT}\n`)
        && !sunkEnforcing.stdout.includes('crashed') && sunkEnforcing.summary === '', why(sunkEnforcing));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

console.log(failed === 0 ? '\n✅ all deps-currency engine self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
