// Offline self-test for the deps-currency engine. No network, no osv-scanner, no gh — feeds a
// SAVED osv-scanner JSON output fixture (one CRITICAL vuln, one LOW vuln) + workflow-text fixtures
// to the pure engine and asserts: severity-floor filtering, issue open/close decision, clean→close,
// block decision (fail-on-vuln), unpinned-action detection, the first-party OWNER-SET derivation
// (caller ∪ action ∪ declared extras — the 2026-08 ownership split), and the
// report-spoofing/disclosure guard. Run: node scripts/selftest.mjs (also runs in CI). Exits
// non-zero on any regression — the action's own regression guard, mirroring
// security-baseline/selftest.mjs.
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
  renderReport, safe,
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
}

console.log(failed === 0 ? '\n✅ all deps-currency engine self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
