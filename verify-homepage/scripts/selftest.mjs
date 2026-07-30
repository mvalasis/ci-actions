// Self-test for the verify-homepage render gate — the LANDMARK-RESOLUTION layer.
//
// Runs render-check.mjs END-TO-END against committed `file://` HTML fixtures, so
// it needs Chromium but NO network and no live site. That combination is the
// point: overflow / collapse / overlap are rendered-layout facts (a fixture-free
// unit test cannot produce them), yet the defect this pins — an ambiguous
// landmark selector resolving to the wrong element — is a *markup* shape that a
// live site is free to stop having. lampakia had it for a month and then fixed
// it (commit e2ff769, drawer chrome <footer> → <div>); after that the live smoke
// run in verify-homepage-selftest.yml can never exercise this path again. The
// fixtures can't be fixed out from under us.
//
// What is asserted:
//   1. a collapsed landmark names the element it RESOLVED to, not just the selector
//   2. it names the display:none ANCESTOR that is the actual cause
//   3. it says how many elements match, and points at the runner-up that renders
//   4. the same identification reaches the OVERLAP path (where ambiguity yields a
//      false FAIL, not merely a mis-attributed one)
//   5. the diagnostics are report-only: identical markup + a scoped selector =
//      clean PASS with no advisory, and FAIL_ON_STRUCTURE still decides the exit code
//
// Run: node scripts/selftest.mjs (also runs in CI, before the live smoke).
// Requires: npm ci && npx playwright install chromium.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, 'selftest');
const RUN = path.join(HERE, 'render-check.mjs');
const fixture = (name) => `file://${path.join(FIX, name)}`;

let failed = 0;
function check(name, cond, detail = '') {
  if (cond) console.log(`  ✅ ${name}`);
  else { console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
}

// Run the real entrypoint with a captured step summary; assert against the
// job-log mirror (stdout), which is the sink a human actually reads.
function run(env) {
  const summaryPath = path.join(os.tmpdir(), `vh-summary-${process.pid}-${Object.keys(env).length}-${env.URLS.length}.md`);
  fs.writeFileSync(summaryPath, '');
  const r = spawnSync(process.execPath, [RUN], {
    encoding: 'utf8',
    cwd: path.dirname(HERE),
    env: {
      ...process.env,
      GITHUB_STEP_SUMMARY: summaryPath,
      FORCE_COLOR: '0',
      // The fleet default. `nav` is in the list so the nav-file's `landmarks`
      // are read the way every caller reads them; the fixtures declare no
      // `nav_selector`, so the nav inventory check itself is skipped.
      CHECKS: 'render,nav',
      WAIT_MS: '0',
      ...env,
    },
  });
  const summary = fs.readFileSync(summaryPath, 'utf8');
  try { fs.unlinkSync(summaryPath); } catch { /* ignore */ }
  return { exit: r.status, summary, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// ---------------------------------------------------------------------------
console.log('\n# default (unscoped) landmarks — the ambiguity must be self-diagnosing');

// Report-only, so this run can never depend on the exit code to prove anything.
const loose = run({
  URLS: `${fixture('collapsed-drawer-footer.html')} ${fixture('citation-footer.html')}`,
  VIEWPORTS: 'desktop:1200x800,mobile:390x844',
  FAIL_ON_STRUCTURE: 'false',
  NAV_FILE: '',
});

check('run completed', loose.exit === 0, `exit=${loose.exit} stderr=${loose.stderr.slice(0, 300)}`);
check('report reached the job log', /verify-homepage · structure/.test(loose.stdout), loose.stdout.slice(0, 200));
check('report reached the step summary too', /verify-homepage · structure/.test(loose.summary));

// (1) the headline: WHICH element, not just which selector.
check('collapsed landmark names the resolved element',
  /collapsed landmark footer \(0-height\) — resolved to ‹footer class="drawer-foot/.test(loose.stdout), loose.stdout);
check('the same upgrade applies to every landmark, not just footer',
  /collapsed landmark header \(0-height\) — resolved to ‹header class="drawer-head/.test(loose.stdout));

// EVERY collapse finding carries the tail — the old bare form is gone for good.
const bareCollapse = (loose.stdout.match(/collapsed landmark [^\n]*?\(0-height\)(?! — resolved to)/g) || []);
check('no collapse finding is left un-identified', bareCollapse.length === 0, JSON.stringify(bareCollapse));

// (2) the single most useful fact: the ancestor that is actually display:none.
check('names the display:none ANCESTOR as the cause',
  /whose ancestor ‹aside id="mobile-menu"› is display:none — that ancestor is the cause/.test(loose.stdout), loose.stdout);
check('and does so for a non-drawer container too (blockquote citation in a hidden li)',
  /whose ancestor ‹li class="hidden"› is display:none/.test(loose.stdout), loose.stdout);

// (3) ambiguity: how many matched, and which one probably was meant.
check('reports the match count and first-match-wins',
  /2 elements match "footer" \(first match in document order wins\)/.test(loose.stdout), loose.stdout);
// Spelled "match 2 of 2", not "#2" — safe() strips `#` from the composed line.
check('points at the runner-up that actually renders',
  /match 2 of 2 ‹footer class="site"› renders 120px tall/.test(loose.stdout), loose.stdout);

// (4) the overlap path — at mobile the drawer is visible and its in-flow chrome
// sits over main, so `main ∩ footer` fires on an element that is not the footer.
const overlapLine = loose.stdout.split('\n').find((l) => l.includes('overlap main ∩ footer')) || '';
check('overlap fires on the mobile drawer shape', overlapLine !== '', loose.stdout);
check('overlap identifies the ambiguous side',
  /overlap main ∩ footer \([0-9]+×[0-9]+px\) — footer resolved to ‹footer class="drawer-foot/.test(overlapLine),
  overlapLine);
check('overlap leaves the unambiguous side terse (no noise for `main`)',
  !/main resolved to/.test(overlapLine), overlapLine);

// The standing advisory — printed even when nothing failed, because a selector
// measuring the wrong element is a latent false verdict in BOTH directions.
check('advisory section is emitted',
  /landmark selectors that did not resolve cleanly/.test(loose.stdout), loose.stdout);
check('advisory points at the fix (scope the selector)',
  /scope the selector in `verify-nav\.json`/.test(loose.stdout));

// Report-only mode still exits 0 even though checks broke.
check('report-only mode exits 0 with failures present',
  loose.exit === 0 && /WARN \(report-only\)/.test(loose.stdout), loose.stdout.slice(-400));

// Page-controlled text can never reach line-start and forge a workflow command.
const forged = loose.stdout.split('\n').filter((l) => /^::/.test(l));
check('no line-start `::` in the report', forged.length === 0, JSON.stringify(forged));
// safe() must still be stripping markdown-hostile characters out of page strings.
check('resolved identifiers carry no angle brackets (safe() would strip them)',
  !/resolved to <|resolved to &lt;/.test(loose.stdout));

// ---------------------------------------------------------------------------
console.log('\n# scoped landmarks — IDENTICAL markup, and the gate says nothing');
//
// This is the tension worth knowing about, pinned as a test rather than left as
// a story: `body > header` / `main#main` / `body > footer` are strictly more
// precise, and on the exact fixture above they produce a clean, silent PASS —
// which is why lampakia's own ENFORCING gate stayed green for the month that the
// unscoped ci-actions selftest was flagging the defect. Precision and
// regression-catching pull in opposite directions here.
const navFile = path.join(os.tmpdir(), `vh-nav-${process.pid}.json`);
fs.writeFileSync(navFile, JSON.stringify({ landmarks: ['body > header', 'main#main', 'body > footer'] }));

const scoped = run({
  URLS: fixture('collapsed-drawer-footer.html'),
  VIEWPORTS: 'desktop:1200x800,mobile:390x844',
  FAIL_ON_STRUCTURE: 'true',
  NAV_FILE: navFile,
});
try { fs.unlinkSync(navFile); } catch { /* ignore */ }

check('scoped selectors PASS on the same markup',
  scoped.exit === 0 && /✅ \*\*PASS\*\*/.test(scoped.stdout), `exit=${scoped.exit} :: ${scoped.stdout.slice(-400)}`);
check('…and emit NO advisory (a precise selector adds no noise)',
  !/did not resolve cleanly/.test(scoped.stdout), scoped.stdout);
check('…and never mention the drawer at all',
  !/mobile-menu/.test(scoped.stdout), scoped.stdout);

// ---------------------------------------------------------------------------
console.log('\n# pass/fail semantics are untouched by the diagnostics');

const enforcing = run({
  URLS: fixture('collapsed-drawer-footer.html'),
  VIEWPORTS: 'desktop:1200x800',
  FAIL_ON_STRUCTURE: 'true',
  NAV_FILE: '',
});
check('unscoped + ENFORCING still exits 1 on the collapse',
  enforcing.exit === 1 && /❌ \*\*FAIL\*\*/.test(enforcing.stdout),
  `exit=${enforcing.exit} :: ${enforcing.stdout.slice(-400)}`);

console.log(failed === 0 ? '\n✅ all verify-homepage self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
