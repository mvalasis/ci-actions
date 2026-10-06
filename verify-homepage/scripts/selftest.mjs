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
//   6. the report reaches the job log exactly once, and the step summary only when
//      there is one — with a summary, with none (a local run), and with
//      GITHUB_STEP_SUMMARY=/dev/stdout; a local crash note prints once too
//   7. the `affordance` check (v1.26.0): a BAD fixture fires every rule (label-missing,
//      label-in-name, label-click, cursor), a GOOD fixture stays silent, report-mode and
//      enforcing exit codes, annotations carry identifiers only, the click leg restores
//      what it toggled, a fault in the check is a fault (never a PASS, never a finding),
//      and it never moves the render/nav verdict
//
// Run: node scripts/selftest.mjs (also runs in CI, before the live smoke).
// Requires: npm ci && npx playwright install chromium.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
const count = (text, s) => text.split(s).length - 1;

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

// Run an entrypoint the way a LOCAL run does. The runner's own GITHUB_STEP_SUMMARY
// is dropped (else this is the CI shape again, writing into this self-test's own
// summary); a case that wants one names it. stdout is either what spawnSync hands
// a child — a socket — or an O_APPEND file; the "where the report goes" block
// below says why both.
function spawnLocal(file, env, stdout, cwd) {
  const inherited = { ...process.env };
  delete inherited.GITHUB_STEP_SUMMARY;
  const opts = { encoding: 'utf8', cwd, env: { ...inherited, ...env } };
  if (stdout === 'socket') {
    const r = spawnSync(process.execPath, [file], opts);
    return { exit: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vh-stdout-'));
  const outPath = path.join(dir, 'stdout.txt');
  const fd = fs.openSync(outPath, 'a');
  try {
    const r = spawnSync(process.execPath, [file], { ...opts, stdio: ['ignore', fd, 'pipe'] });
    return { exit: r.status, stdout: fs.readFileSync(outPath, 'utf8'), stderr: r.stderr || '' };
  } finally {
    fs.closeSync(fd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
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

// ---------------------------------------------------------------------------
console.log('\n# where the report goes — the job log exactly once, the step summary when there is one');
//
// Every run echoes the report to the job log through fd 1. Before v1.19.1 a run with
// no GITHUB_STEP_SUMMARY (a local run), or with GITHUB_STEP_SUMMARY=/dev/stdout, also
// appended it to /dev/stdout — the log a second time. That printed it twice on a
// terminal, a pipe or a file, and under macOS child_process (opening /dev/stdout dups
// fd 1). Linux with a SOCKET stdout, which is what spawnSync hands a child, printed it
// once: the open fails with ENXIO and a catch swallowed it. So each case also runs
// with an O_APPEND FILE as stdout, which the old code double-printed into on Linux
// too — without it, these legs pass on the ubuntu runner against the bug.
const HEADER = '## verify-homepage · structure + cross-viewport render';
check('CI shape: the job log carries the whole report, byte for byte',
  enforcing.summary.length > 0 && enforcing.stdout.includes(enforcing.summary), enforcing.stdout.slice(0, 200));
check('CI shape: the report is in the log once and in the step summary once',
  count(enforcing.stdout, HEADER) === 1 && count(enforcing.summary, HEADER) === 1,
  `log ×${count(enforcing.stdout, HEADER)}, summary ×${count(enforcing.summary, HEADER)}`);

for (const [label, sink] of [['local run (no GITHUB_STEP_SUMMARY)', undefined], ['GITHUB_STEP_SUMMARY=/dev/stdout (the local idiom)', '/dev/stdout']]) {
  for (const stdout of ['socket', 'file']) {
    const r = spawnLocal(RUN, {
      FORCE_COLOR: '0',
      CHECKS: 'render,nav',
      WAIT_MS: '0',
      URLS: fixture('collapsed-drawer-footer.html'),
      VIEWPORTS: 'desktop:1200x800',
      FAIL_ON_STRUCTURE: 'true',
      NAV_FILE: '',
      GITHUB_STEP_SUMMARY: sink,
    }, stdout, path.dirname(HERE));
    check(`${label}, stdout a ${stdout}: the report prints exactly once, verdict included, no crash`,
      r.exit === 1 && count(r.stdout, HEADER) === 1 && count(r.stdout, '❌ **FAIL**') === 1 &&
        !/verify-homepage crashed/.test(r.stdout + r.stderr),
      `exit=${r.exit}, report ×${count(r.stdout, HEADER)}, stderr ${JSON.stringify(r.stderr.slice(0, 200))}`);
    check(`${label}, stdout a ${stdout}: it is the report the step summary gets`,
      enforcing.summary.length > 0 && r.stdout.includes(enforcing.summary), r.stdout.slice(0, 200));
  }
}

// ---------------------------------------------------------------------------
console.log('\n# affordance — the BAD fixture fires every rule');
//
// affordance-bad.html carries the EPN /contact/ + /employers/ shape of 2026-10-06 (consent words
// outside any <label>, an aria-label that says something else, no pointer cursor) plus one fixture
// per remaining way a control can lie. Run report-mode with FAIL_ON_STRUCTURE left at its enforcing
// default, to prove it is `fail-on-affordance` — not `fail-on-structure` — that governs this check.
const AFF = { CHECKS: 'affordance', VIEWPORTS: 'desktop:1000x800,iphone:393x852', NAV_FILE: '' };
const bad = run({ URLS: fixture('affordance-bad.html'), ...AFF, FAIL_ON_STRUCTURE: 'true', FAIL_ON_AFFORDANCE: 'false' });
const badLine = (re) => bad.stdout.split('\n').find((l) => re.test(l)) || '';

check('report-mode run completes, exit 0, with findings present',
  bad.exit === 0 && /affordance WARN \(report-only\)/.test(bad.stdout), `exit=${bad.exit} ${bad.stdout.slice(-300)}`);
check('FAIL_ON_STRUCTURE does not govern it (default-enforcing structure, no render/nav in checks)',
  !/\*\*PASS\*\* — \d+ checks|\*\*FAIL\*\* — \d+\/\d+ checks/.test(bad.stdout), bad.stdout.slice(-300));

// label-missing — the EPN shape: the words are beside the box, not in a label.
check('label-missing: the EPN consent words sit outside any <label>, and are quoted',
  /\*\*label-missing\*\* `[^`]*input` “I consent to EPN storing my details/.test(badLine(/label-missing.*I consent to EPN/)) &&
    /so the words beside it are not its label/.test(badLine(/label-missing.*I consent to EPN/)), bad.stdout);
check('label-missing: two unlabelled radios are ONE cause (grouped, ×2)',
  /\*\*label-missing\*\* `[^`]*size[^`]*` ×2 “Small”/.test(badLine(/label-missing.*Small/)), badLine(/label-missing.*Small/));

// label-in-name — WCAG 2.5.3, both through a real <label> and through nearby text.
check('label-in-name: aria-label "Sign me up" vs label "Subscribe to the newsletter"',
  /\*\*label-in-name\*\* `input#nl` “Subscribe to the newsletter” — aria-label "Sign me up" does not contain the visible label text/.test(bad.stdout), bad.stdout);
check('label-in-name: the EPN aria-label contradicts the words beside the box',
  /\*\*label-in-name\*\*[^\n]*aria-label "I consent to Elite Prodigy Nexus[^\n]*does not contain the visible nearby text/.test(bad.stdout), bad.stdout);

// label-click — a REAL click, hit-tested.
check('label-click: an overlay on the label text is named',
  /\*\*label-click\*\* `[^`]*covered[^`]*` — clicking the label text hit div\.cover, not the label/.test(bad.stdout), bad.stdout);
check('label-click: a label whose click is swallowed does not toggle',
  /\*\*label-click\*\* `label#stuck > input` — clicking the label text did not toggle the control/.test(bad.stdout), bad.stdout);

// cursor — every clickable kind in the brief, each with its own kind name.
for (const kind of ['button', 'a', 'select', 'summary', 'div role=button', 'input type=file', 'input type=checkbox', 'label for checkbox', 'input type=submit']) {
  check(`cursor: ${kind} without a pointer is flagged`,
    new RegExp(`\\*\\*cursor\\*\\*[^\\n]*— ${kind.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} has cursor: (default|auto), expected pointer`).test(bad.stdout), bad.stdout);
}
check('cursor: a DISABLED control showing pointer is tolerated (only enabled controls must show it)',
  !/Disabled with pointer/.test(bad.stdout) && !/while disabled/.test(bad.stdout), bad.stdout);
check('cursor: a correctly-cursored labelled checkbox is NOT flagged (no noise on the covered/stuck rows)',
  !/\*\*cursor\*\*[^\n]*(covered|#stuck)/.test(bad.stdout), bad.stdout);
check('cursor: an unstyled <input type=checkbox> label names the words, not its value "on"',
  !/“on”/.test(bad.stdout), bad.stdout);

// Same selector at two viewports is ONE finding, not two.
check('findings are merged across viewports (listed once, "all viewports")',
  count(bad.stdout, 'label#stuck > input') >= 1 && (bad.stdout.match(/\*\*label-click\*\* `label#stuck > input`/g) || []).length === 1, bad.stdout);

// Annotations: report mode → ::warning; identifiers only; behavioural findings first; capped at 10.
const annots = bad.stdout.split('\n').filter((l) => /^::(warning|error) /.test(l));
check('annotations are ::warning in report mode, behavioural rules first',
  annots.length > 0 && annots.every((l) => l.startsWith('::warning title=verify-homepage affordance ')) &&
    /affordance label-click::/.test(annots[0]), JSON.stringify(annots.slice(0, 2)));
check('annotations carry the rule, the page URL and a selector — never page text',
  annots.length > 0 && annots.every((l) => /::[a-z-]+ at file:\/\/\S+ — \S/.test(l)) &&
    !annots.some((l) => /Remember my choice|Keep me signed in|Subscribe|consent to/i.test(l)), annots.join('\n'));
check('annotations stop at GitHub\'s 10 per step and say how many were left out',
  annots.length === 10 && /\d+ more finding group\(s\) not annotated/.test(bad.stdout), `${annots.length}`);
check('the annotations come AFTER the report (the log reads report → annotations)',
  bad.stdout.indexOf('affordance WARN') < bad.stdout.indexOf('::warning'), '');

// Enforcing.
const badEnforce = run({ URLS: fixture('affordance-bad.html'), ...AFF, FAIL_ON_AFFORDANCE: 'true' });
check('fail-on-affordance: true → exit 1, FAIL verdict, ::error annotations',
  badEnforce.exit === 1 && /affordance FAIL/.test(badEnforce.stdout) && /^::error title=verify-homepage affordance /m.test(badEnforce.stdout) &&
    !/^::warning /m.test(badEnforce.stdout), `exit=${badEnforce.exit} ${badEnforce.stdout.slice(-300)}`);

// Defaults: unset `fail-on-affordance` is report-only, and the real action.yml agrees (the entrypoint's
// default and the action's must match — a flipped default would newly-block every caller that opts in).
const unset = run({ URLS: fixture('affordance-bad.html'), ...AFF });
check('FAIL_ON_AFFORDANCE unset → report-only: findings present, exit 0',
  unset.exit === 0 && /affordance WARN \(report-only\)/.test(unset.stdout), `exit=${unset.exit}`);
const actionYml = fs.readFileSync(path.join(HERE, '..', 'action.yml'), 'utf8');
const inputDefault = (name) => new RegExp(`^  ${name}:\\n(?:    .*\\n)*?    default: '([^']*)'`, 'm').exec(actionYml)?.[1];
check('action.yml: fail-on-affordance defaults to false', inputDefault('fail-on-affordance') === 'false', String(inputDefault('fail-on-affordance')));
check('action.yml: checks still defaults to render,nav (affordance is opt-in)', inputDefault('checks') === 'render,nav', String(inputDefault('checks')));
check('action.yml: FAIL_ON_AFFORDANCE reaches the script from inputs.fail-on-affordance',
  /FAIL_ON_AFFORDANCE: \$\{\{ inputs\.fail-on-affordance \}\}/.test(actionYml));

// Opt-in: the default checks never run it.
const optin = run({ URLS: fixture('affordance-bad.html'), VIEWPORTS: 'desktop:1000x800', FAIL_ON_STRUCTURE: 'false', NAV_FILE: '' });
check('opt-in: the default `render,nav` checks print no affordance section and no annotation',
  !/\*\*affordance|affordance (PASS|WARN|FAIL)|^::(warning|error)/m.test(optin.stdout), optin.stdout);

// ---------------------------------------------------------------------------
console.log('\n# affordance — the GOOD fixture stays silent');
//
// The mirror page, with the shapes a naive check mis-reads: a link inside a label, a custom checkbox
// whose native input is visually hidden, a pre-checked radio, disabled and not-rendered controls, a
// Greek label. Enforcing, so a single false positive is a red build here.
const good = run({ URLS: fixture('affordance-good.html'), ...AFF, FAIL_ON_AFFORDANCE: 'true' });
check('GOOD page: exit 0 and an affordance PASS, enforcing',
  good.exit === 0 && /affordance PASS/.test(good.stdout), `exit=${good.exit} ${good.stdout.slice(-500)}`);
check('GOOD page: no finding, no annotation', !/^::/m.test(good.stdout) && !/\*\*(label-|cursor)/.test(good.stdout), good.stdout);
// The silence must come from LOOKING: a probe that inspected nothing also reports nothing.
const tally = /(\d+) checkbox\/radio, (\d+) label-click\(s\), (\d+) cursor probe\(s\)/.exec(good.stdout) || [];
check('GOOD page: the check really looked (≥8 controls, ≥6 label clicks, ≥20 cursor probes)',
  +tally[1] >= 8 && +tally[2] >= 6 && +tally[3] >= 20, tally[0] || good.stdout.slice(-300));

// ---------------------------------------------------------------------------
console.log('\n# affordance — independent of the render/nav verdict');
//
// Neither fixture declares header/footer, so with `render` on, the STRUCTURE verdict fails on both
// (missing landmark). The two switches must stay independent.
const both = (affordanceFail, structureFail, fixtureName) => run({
  URLS: fixture(fixtureName), CHECKS: 'render,nav,affordance', VIEWPORTS: 'desktop:1000x800', NAV_FILE: '',
  FAIL_ON_STRUCTURE: structureFail, FAIL_ON_AFFORDANCE: affordanceFail,
});
const a1 = both('true', 'false', 'affordance-good.html');
check('structure red + report-mode, affordance clean + enforcing → exit 0 (affordance never inherits structure)',
  a1.exit === 0 && /WARN \(report-only\)/.test(a1.stdout) && /affordance PASS/.test(a1.stdout), `exit=${a1.exit} ${a1.stdout.slice(-300)}`);
const a2 = both('false', 'true', 'affordance-good.html');
check('structure red + enforcing, affordance clean → exit 1 (structure still blocks as it always did)',
  a2.exit === 1 && /❌ \*\*FAIL\*\*/.test(a2.stdout) && /affordance PASS/.test(a2.stdout), `exit=${a2.exit}`);
const a3 = both('false', 'false', 'affordance-bad.html');
check('affordance findings in report mode never move the exit code, even beside a structure WARN',
  a3.exit === 0 && /affordance WARN/.test(a3.stdout), `exit=${a3.exit}`);
const a4 = both('true', 'false', 'affordance-bad.html');
check('affordance findings + fail-on-affordance → exit 1 even when fail-on-structure is off',
  a4.exit === 1, `exit=${a4.exit}`);

// ---------------------------------------------------------------------------
console.log('\n# affordance — the click leg restores what it toggled; a fault is a fault');
{
  const { chromium } = await import('playwright');
  const { runAffordance } = await import(pathToFileURL(path.join(HERE, 'affordance.mjs')).href);
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  try {
    const states = (page) => page.evaluate(() => [...document.querySelectorAll('input[type=checkbox],input[type=radio]')].map((e) => e.checked));
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    for (const name of ['affordance-good.html', 'affordance-bad.html']) {
      await page.goto(fixture(name));
      const before = await states(page);
      const r = await runAffordance(page);
      const after = await states(page);
      check(`${name}: every checkbox/radio is back to its starting state after the click leg`,
        JSON.stringify(before) === JSON.stringify(after) && r.stats.clicked > 0,
        `before ${JSON.stringify(before)} after ${JSON.stringify(after)} clicked=${r.stats.clicked}`);
      check(`${name}: no fault`, r.fault === '', r.fault);
    }
    await page.goto(fixture('affordance-good.html'));
    const g = await runAffordance(page);
    check('GOOD page: the pre-checked radio is left checked and clicked 0 times (no flip to assert)',
      (await page.evaluate(() => document.querySelector('input[name=size][value=m]').checked)) === true && g.findings.length === 0, JSON.stringify(g.findings));
    // A fault comes back as a fault, never as a thrown error and never as a clean result.
    const dead = await browser.newPage();
    await dead.close();
    const f = await runAffordance(dead);
    check('a page that cannot be inspected returns a fault (not a throw, not a clean PASS)',
      f.fault.length > 0 && f.findings.length === 0, JSON.stringify(f));
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------------------
// CRASH GUARD — asserted BEHAVIOURALLY, by crashing the real entrypoint.
//
// Never by grepping render-check.mjs for `process.on(` or for a line position: a
// textual assertion goes vacuous the moment the file is restructured, and it
// cannot distinguish a registered handler from a dead one — which is the exact
// defect that shipped in deps-currency for the action's entire life.
//
// No Chromium and no network here: the fault is injected at (or before) the first
// const, so the browser is never launched. `playwright` is stubbed in the temp
// dir purely so the bare-specifier import resolves — that keeps this block
// runnable on a bare checkout, without `npm ci`, unlike the fixture tests above.
console.log('\n# crash guard (real render-check.mjs, injected fault)');
{
  const source = fs.readFileSync(RUN, 'utf8');
  const ANCHOR = 'const env = process.env;';

  // Fail CLOSED: if the anchor is gone the mutation is a silent no-op and the
  // `early` assertions below would pass against an entrypoint that never crashed.
  check('fault-injection anchor still present in render-check.mjs', source.includes(ANCHOR),
    `(expected to find ${JSON.stringify(ANCHOR)} — if the const block was renamed, update this test)`);

  if (source.includes(ANCHOR)) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vh-crash-'));
    try {
      // Minimal ESM stub so `import { chromium } from 'playwright'` resolves — and
      // so `launch()` throws, which IS the `launch` variant's fault. No injection.
      // render-check imports ./affordance.mjs — it must sit beside the mutated copies.
      fs.copyFileSync(path.join(HERE, 'affordance.mjs'), path.join(tmp, 'affordance.mjs'));
      const stub = path.join(tmp, 'node_modules', 'playwright');
      fs.mkdirSync(stub, { recursive: true });
      fs.writeFileSync(path.join(stub, 'package.json'),
        JSON.stringify({ name: 'playwright', version: '0.0.0-stub', type: 'module', main: 'index.js' }));
      fs.writeFileSync(path.join(stub, 'index.js'),
        'export const chromium = { launch() { throw new Error("injected launch fault"); } };\n');

      // Two faults at deliberately different points in module evaluation, because
      // they exercise genuinely different states — and only the pair pins the design.
      //
      //  LAUNCH — the entrypoint is UNMODIFIED; the stub throws at
      //           `await chromium.launch()` (line ~195), long after every const is
      //           initialised. This is the realistic production crash: Chromium
      //           failing to start on the runner. Needs no anchor, so it cannot be
      //           silently disarmed by restructuring the const block.
      //
      //  EARLY  — the const initialiser itself throws, so `FAIL`, `summaryFile`,
      //           `safe` and friends are all still in the TEMPORAL DEAD ZONE when
      //           the handler runs. This is the case that keeps the handler reading
      //           `process.env`: "tidy" it to read the `FAIL` const and the handler
      //           faults inside ITSELF with a ReferenceError — node exits 7 having
      //           written nothing, losing the diagnostic and the exit code together,
      //           which is precisely the failure the guard exists to prevent.
      //           (Verified by mutation: swapping the env read for `FAIL` turns this
      //           block red. Without this case the env read reads as a redundant
      //           spelling of `FAIL` and is free to be refactored away.)
      const variants = {
        launch: source,
        early: source.replace(ANCHOR, "const env = (() => { throw new Error('injected init fault'); })();"),
      };

      const crash = (variant, failOnStructure) => {
        const file = path.join(tmp, `render-${variant}.mjs`);
        fs.writeFileSync(file, variants[variant]);
        const summaryPath = path.join(tmp, `sum-${variant}-${failOnStructure}.md`);
        fs.writeFileSync(summaryPath, '');
        const r = spawnSync(process.execPath, [file], {
          encoding: 'utf8',
          env: {
            ...process.env,
            GITHUB_STEP_SUMMARY: summaryPath,
            FAIL_ON_STRUCTURE: String(failOnStructure),
            URLS: 'https://example.invalid/',
          },
        });
        return { status: r.status, summary: fs.readFileSync(summaryPath, 'utf8'), stderr: r.stderr || '' };
      };

      for (const variant of ['launch', 'early']) {
        const report = crash(variant, false);
        const enforce = crash(variant, true);
        const expected = variant === 'launch' ? 'injected launch fault' : 'injected init fault';

        // The guard ran at all — the assertion the shipped code would have failed.
        check(`[${variant}] a tool fault is reported into the step summary`,
          report.summary.includes('verify-homepage crashed') && report.summary.includes(expected),
          `(got ${JSON.stringify(report.summary.slice(0, 200))})`);
        // …and the exit codes, which are the half that is a product decision.
        check(`[${variant}] report mode: a crash exits 0 (must not block a report-mode caller)`,
          report.status === 0, `(exit ${report.status}) ${report.stderr.slice(0, 200)}`);
        check(`[${variant}] fail-on-structure: a crash exits 1 (conservative for an enforcing caller)`,
          enforce.status === 1, `(exit ${enforce.status})`);
        check(`[${variant}] the enforcing crash is reported too`,
          enforce.summary.includes('verify-homepage crashed'));
        // The report must say it is a TOOL fault, not a verdict on the page —
        // this is what stops an operator triaging a scanner bug as a layout bug.
        check(`[${variant}] the report disclaims being a verdict on the page`,
          /not a verdict on the page/.test(report.summary), report.summary.slice(0, 200));

        const NOTE = 'verify-homepage crashed';
        check(`[${variant}] the crash note is in the step summary once and the job log (stderr) once`,
          count(report.summary, NOTE) === 1 && count(report.stderr, NOTE) === 1,
          `summary ×${count(report.summary, NOTE)}, stderr ×${count(report.stderr, NOTE)}`);
        // A LOCAL crash — no step summary, or GITHUB_STEP_SUMMARY=/dev/stdout: the fd-2
        // mirror is the only copy, so the note prints once, on stderr. Before v1.19.1 the
        // handler appended it to /dev/stdout as well, printing it twice on a terminal.
        // Both stdout shapes, for the reason the "where the report goes" block gives.
        for (const [label, sink] of [['local run', undefined], ['GITHUB_STEP_SUMMARY=/dev/stdout', '/dev/stdout']]) {
          for (const stdout of ['socket', 'file']) {
            const r = spawnLocal(path.join(tmp, `render-${variant}.mjs`),
              { FAIL_ON_STRUCTURE: 'false', URLS: 'https://example.invalid/', GITHUB_STEP_SUMMARY: sink }, stdout, tmp);
            check(`[${variant}] ${label}, stdout a ${stdout}: the crash note prints once, on stderr, exit 0`,
              count(r.stdout + r.stderr, NOTE) === 1 && count(r.stderr, NOTE) === 1 && r.exit === 0,
              `stdout ×${count(r.stdout, NOTE)}, stderr ×${count(r.stderr, NOTE)}, exit ${r.exit}`);
          }
        }
      }

      // ---- affordance-only runs: the enforcement switch is `fail-on-affordance`, never fail-on-structure ----
      // FAIL_ON_STRUCTURE stays at the enforcing 'true' below: an affordance-only caller never set it, and
      // a tool fault must not newly-block them through a switch that does not govern their check.
      const affCrash = (failOnAffordance) => {
        const summaryPath = path.join(tmp, `sum-aff-${failOnAffordance}.md`);
        fs.writeFileSync(summaryPath, '');
        const r = spawnSync(process.execPath, [path.join(tmp, 'render-launch.mjs')], {
          encoding: 'utf8',
          env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, CHECKS: 'affordance', FAIL_ON_STRUCTURE: 'true',
            FAIL_ON_AFFORDANCE: String(failOnAffordance), URLS: 'https://example.invalid/' },
        });
        return { status: r.status, summary: fs.readFileSync(summaryPath, 'utf8') };
      };
      const affReport = affCrash(false);
      const affEnforce = affCrash(true);
      check('[affordance-only] a tool fault in report mode exits 0 although fail-on-structure is true',
        affReport.status === 0 && /verify-homepage crashed/.test(affReport.summary) && /`fail-on-affordance: false`/.test(affReport.summary),
        `exit ${affReport.status} ${affReport.summary.slice(0, 200)}`);
      check('[affordance-only] a tool fault with fail-on-affordance: true exits 1',
        affEnforce.status === 1 && /`fail-on-affordance: true`/.test(affEnforce.summary), `exit ${affEnforce.status}`);

      // ---- a fault INSIDE the affordance check (the browser launches, the inspection throws) ----
      const tmp2 = path.join(tmp, 'inspect-fault');
      const stub2 = path.join(tmp2, 'node_modules', 'playwright');
      fs.mkdirSync(stub2, { recursive: true });
      fs.copyFileSync(RUN, path.join(tmp2, 'render-check.mjs'));
      fs.copyFileSync(path.join(HERE, 'affordance.mjs'), path.join(tmp2, 'affordance.mjs'));
      fs.writeFileSync(path.join(stub2, 'package.json'),
        JSON.stringify({ name: 'playwright', version: '0.0.0-stub', type: 'module', main: 'index.js' }));
      // Every affordance call (they carry {mode}) is recorded in AFF_CALLS, then throws; the render
      // measurement (no `mode`) gets a clean answer.
      fs.writeFileSync(path.join(stub2, 'index.js'), `
        import fs from 'node:fs';
        const page = { async goto() {}, async waitForLoadState() {}, async waitForTimeout() {}, url: () => 'https://example.invalid/',
          async evaluate(fn, arg) {
            if (arg && arg.mode) { fs.appendFileSync(process.env.AFF_CALLS, 'x'); throw new Error('injected affordance fault'); }
            return { vw: 800, scrollW: 800, overflow: false, offenders: [], landmarks: [] };
          }, mouse: { async click() {} } };
        const ctx = { async newPage() { return page; }, async close() {}, async route() {} };
        export const chromium = { async launch() { return { async newContext() { return ctx; }, async close() {} }; } };
      `);
      const inspect = (failOnAffordance) => {
        const summaryPath = path.join(tmp2, `sum-${failOnAffordance}.md`);
        fs.writeFileSync(summaryPath, '');
        const r = spawnSync(process.execPath, [path.join(tmp2, 'render-check.mjs')], {
          encoding: 'utf8',
          env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, CHECKS: 'affordance', WAIT_MS: '0', VIEWPORTS: 'desktop:800x600',
            FAIL_ON_AFFORDANCE: String(failOnAffordance), URLS: 'https://example.invalid/', AFF_CALLS: path.join(tmp2, 'calls.txt') },
        });
        return { status: r.status, summary: fs.readFileSync(summaryPath, 'utf8'), stdout: r.stdout || '' };
      };
      // Opt-in, observed at the browser: without `affordance` in checks the page is never touched by it.
      fs.writeFileSync(path.join(tmp2, 'calls.txt'), '');
      spawnSync(process.execPath, [path.join(tmp2, 'render-check.mjs')], {
        encoding: 'utf8',
        env: { ...process.env, CHECKS: 'render,nav', FAIL_ON_STRUCTURE: 'false', WAIT_MS: '0', VIEWPORTS: 'desktop:800x600',
          URLS: 'https://example.invalid/', AFF_CALLS: path.join(tmp2, 'calls.txt'), GITHUB_STEP_SUMMARY: path.join(tmp2, 'optin.md') },
      });
      check('opt-in at the browser: default checks make ZERO affordance calls on the page',
        fs.readFileSync(path.join(tmp2, 'calls.txt'), 'utf8') === '', fs.readFileSync(path.join(tmp2, 'calls.txt'), 'utf8'));
      const iReport = inspect(false);
      check('…and with `affordance` in checks it does look (the call counter is not dead)',
        fs.readFileSync(path.join(tmp2, 'calls.txt'), 'utf8').length > 0);
      const iEnforce = inspect(true);
      check('[inspect fault] reported as the GATE\'s fault, not a verdict on the page, and never as a PASS',
        /affordance could not look/.test(iReport.summary + iReport.stdout) && /not a verdict on the page/.test(iReport.summary + iReport.stdout) &&
          !/affordance PASS/.test(iReport.stdout) && !/\*\*(label-|cursor)/.test(iReport.stdout), iReport.stdout.slice(-300));
      check('[inspect fault] report mode exits 0; fail-on-affordance exits 1',
        iReport.status === 0 && iEnforce.status === 1, `report ${iReport.status}, enforce ${iEnforce.status}`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
}

console.log(failed === 0 ? '\n✅ all verify-homepage self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
