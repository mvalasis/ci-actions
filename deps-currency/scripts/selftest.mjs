// Offline self-test for the deps-currency engine. No network, no osv-scanner, no gh — feeds a
// SAVED osv-scanner JSON output fixture (one CRITICAL vuln, one LOW vuln) + workflow-text fixtures
// to the pure engine and asserts: severity-floor filtering, issue open/close decision, clean→close,
// block decision (fail-on-vuln), unpinned-action detection, and the report-spoofing/disclosure
// guard. Run: node scripts/selftest.mjs (also runs in CI). Exits non-zero on any regression —
// the action's own regression guard, mirroring security-baseline/selftest.mjs.
import {
  SEV, normalizeFloor, bucketFor, atOrAboveFloor, parseOsv, filterByFloor,
  scanUnpinnedActions, issueDecision, blockDecision, renderReport, safe,
} from './engine.mjs';

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
}

console.log('\n# report rendering is deterministic + spoof-safe');
{
  const report = renderReport(filterByFloor(parsed, 'HIGH'), [], { floor: 'HIGH', ecosystems: ['npm', 'composer'], lockfiles: ['package-lock.json', 'composer.lock'], totalFindings: 3 });
  check('report names the floor', report.includes('floor: **HIGH**'));
  check('report lists the CRITICAL package', report.includes('lodash'));
  check('clean report says ✅ no advisories', renderReport([], [], { floor: 'HIGH' }).includes('✅ no dependency advisories'));
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
