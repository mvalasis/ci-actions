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
//      and a first-visit cookie banner over a control is rejected once (never accepted) before the label
//      click, while any other cover stays a finding
//   8. the five UX families (v1.27.0) — `focus`, `forms`, `target`, `motion`, `consent`: each with a BAD
//      fixture (every rule red, each exclusion held) and a GOOD one (silent, enforcing, and it really
//      looked), report-mode and enforcing exit codes, independence from `fail-on-structure`, annotations,
//      opt-in, a fault in the check is a fault (never a PASS), and the shapes that fooled the first draft
//      (a ring that fades in, a mobile emulation that flags every layout shift as input-caused)
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
// render-check's own modules: the crash-guard legs run copies of it from a temp dir, which need them all beside it.
const MODULES = fs.readdirSync(HERE).filter((f) => f.endsWith('.mjs') && f !== 'selftest.mjs' && f !== 'render-check.mjs');

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

// `scroll-behavior: smooth` + a fixed header over the label at scroll 0 (EPN, 2026-10-07): the probe
// scrolls the label to the middle and hit-tests in the same tick, so a smooth scroll made it read the
// header at the OLD position. The label is clear once the page settles, so the check must say nothing.
const smooth = run({ URLS: fixture('affordance-smooth.html'), ...AFF, FAIL_ON_AFFORDANCE: 'true' });
check('SMOOTH-scroll page: no label-click false positive from the fixed header, enforcing',
  smooth.exit === 0 && /affordance PASS/.test(smooth.stdout) && !/\*\*label-click\*\*/.test(smooth.stdout),
  `exit=${smooth.exit} ${smooth.stdout.slice(-400)}`);
check('SMOOTH-scroll page: the label click really ran (≥1 label click)',
  +((/(\d+) label-click\(s\)/.exec(smooth.stdout) || [])[1]) >= 1, smooth.stdout.slice(-300));

// ---------------------------------------------------------------------------
console.log('\n# affordance — a first-visit cookie banner over a control is rejected once, anything else is a finding');
//
// A fresh browser context always shows the banner, so one that covers a labelled checkbox (EPN /apply/,
// 2026-10-07) must not be reported as a defect of the page: the click leg rejects it and looks again. Never
// accept; never touch a cover that is not a cookie/consent banner.
const BAN = { ...AFF, VIEWPORTS: 'iphone:393x852', FAIL_ON_AFFORDANCE: 'true' };
const banRej = run({ URLS: fixture('affordance-banner-reject.html'), ...BAN });
check('banner with a Reject: rejected, the label click lands, no finding, exit 0 (enforcing)',
  banRej.exit === 0 && /affordance PASS/.test(banRej.stdout) && !/\*\*label-click/.test(banRej.stdout), `exit=${banRej.exit} ${banRej.stdout.slice(-400)}`);
check('banner with a Reject: the report says it rejected the banner (an interaction the reader must be able to see)',
  /ℹ️ [^\n]*rejected the cookie banner \(“Reject”\) to reach input#?target/.test(banRej.stdout), banRej.stdout);
const banAcc = run({ URLS: fixture('affordance-banner-accept-only.html'), ...BAN });
check('banner with ONLY Accept: never accepted on the page\'s behalf — still a label-click finding',
  banAcc.exit === 1 && /\*\*label-click\*\* `input#target` — clicking the label text hit div/.test(banAcc.stdout) && !/rejected the cookie banner/.test(banAcc.stdout), `exit=${banAcc.exit} ${banAcc.stdout.slice(-400)}`);
const chat = run({ URLS: fixture('affordance-chat-cover.html'), ...BAN });
check('a fixed chat widget (not a cookie banner) is left alone — still a label-click finding',
  chat.exit === 1 && /\*\*label-click\*\* `input#target` — clicking the label text hit div/.test(chat.stdout) && !/rejected the cookie banner/.test(chat.stdout), `exit=${chat.exit} ${chat.stdout.slice(-400)}`);

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
// The five UX families (v1.27.0): focus, forms, target, motion, consent.
//
// Every family follows the affordance template, so the assertions that are the SAME for all of them are
// written once, below, and the ones that are about THIS family's rules follow each. Per family:
//   R1 BAD, report-mode (FAIL_ON_<X> left UNSET — which is the default under test), fail-on-structure left
//      at its enforcing default: it must exit 0 with findings, and the structure switch must not govern it
//   R2 BAD, enforcing: exit 1, FAIL, ::error annotations, no ::warning
//   R3 GOOD, enforcing: exit 0, PASS, no annotation — and the tally proves the check LOOKED
//   R4 render,nav + the family on the BAD page, structure report-mode, family enforcing: exit 1 (the family
//      blocks on its own), and R5 the same with GOOD, structure enforcing + red (no landmarks), family
//      enforcing + clean: exit 1 from structure alone with the family at PASS — two independent switches
const VP = 'desktop:1000x800,iphone:393x852';
const famEnv = (name, fixtureName, extra = {}) => ({
  URLS: fixture(fixtureName), CHECKS: name, VIEWPORTS: VP, NAV_FILE: '', FAIL_ON_STRUCTURE: 'true', ...extra,
});
const FAILVAR = (name) => `FAIL_ON_${name.toUpperCase()}`;
// A nav-file whose only landmark is absent: the structure verdict is RED on every fixture, whatever it holds.
const redNav = path.join(os.tmpdir(), `vh-red-nav-${process.pid}.json`);
fs.writeFileSync(redNav, JSON.stringify({ landmarks: ['#no-such-landmark'] }));
const lineOf = (r, re) => r.stdout.split('\n').find((l) => re.test(l)) || '';
const annotsOf = (r) => r.stdout.split('\n').filter((l) => /^::(warning|error) /.test(l));

function commonFamilyChecks(name, badName, goodName, { goodTally, pageText }) {
  const bad = run(famEnv(name, badName));
  const enf = run(famEnv(name, badName, { [FAILVAR(name)]: 'true' }));
  const good = run(famEnv(name, goodName, { [FAILVAR(name)]: 'true' }));
  check(`${name}: BAD, report-mode (switch unset): exit 0, "${name} WARN (report-only)", ::warning annotations`,
    bad.exit === 0 && new RegExp(`${name} WARN \\(report-only\\)`).test(bad.stdout) && annotsOf(bad).length > 0 &&
      annotsOf(bad).every((l) => l.startsWith(`::warning title=verify-homepage ${name} `)), `exit=${bad.exit} ${bad.stdout.slice(-300)}`);
  check(`${name}: fail-on-structure does not govern it (structure enforcing by default, no render/nav in checks)`,
    !/\*\*PASS\*\* — \d+ checks|\*\*FAIL\*\* — \d+\/\d+ checks/.test(bad.stdout), bad.stdout.slice(-300));
  check(`${name}: BAD, enforcing: exit 1, FAIL verdict, ::error annotations only`,
    enf.exit === 1 && new RegExp(`${name} FAIL`).test(enf.stdout) && /^::error title=verify-homepage /m.test(enf.stdout) && !/^::warning /m.test(enf.stdout),
    `exit=${enf.exit} ${enf.stdout.slice(-300)}`);
  const an = annotsOf(bad);
  check(`${name}: annotations carry family, rule, page URL and a selector — never page text`,
    an.every((l) => /::[a-z-]+ at file:\/\/\S+ — \S/.test(l)) && !pageText.test(an.join('\n')), an.slice(0, 3).join('\n'));
  check(`${name}: the annotations come AFTER the report`, bad.stdout.indexOf(`${name} WARN`) < bad.stdout.indexOf('::warning'), '');
  check(`${name}: GOOD, enforcing: exit 0, "${name} PASS", no finding, no annotation`,
    good.exit === 0 && new RegExp(`${name} PASS`).test(good.stdout) && !/^::/m.test(good.stdout) && !new RegExp(`\\*\\*${name}\\*\\* ⚠️|\\*\\*${name}\\*\\* ❌`).test(good.stdout),
    `exit=${good.exit} ${good.stdout.slice(-400)}`);
  // The silence must come from LOOKING: a probe that inspected nothing also reports nothing.
  const t = goodTally(lineOf(good, new RegExp(`${name} PASS`)));
  check(`${name}: GOOD page — the check really looked (${t.want})`, t.ok, lineOf(good, new RegExp(`${name} PASS`)));
  const both = (famFail, structFail, fixtureName) => run({
    URLS: fixture(fixtureName), CHECKS: `render,nav,${name}`, VIEWPORTS: 'desktop:1000x800', NAV_FILE: redNav,
    FAIL_ON_STRUCTURE: structFail, [FAILVAR(name)]: famFail,
  });
  const r4 = both('true', 'false', badName);
  check(`${name}: findings + fail-on-${name} → exit 1 although fail-on-structure is off`, r4.exit === 1 && new RegExp(`${name} FAIL`).test(r4.stdout), `exit=${r4.exit}`);
  const r5 = both('true', 'true', goodName);
  check(`${name}: structure red + enforcing, ${name} clean → exit 1 from structure alone, ${name} PASS (switches independent)`,
    r5.exit === 1 && /❌ \*\*FAIL\*\*/.test(r5.stdout) && new RegExp(`${name} PASS`).test(r5.stdout), `exit=${r5.exit}`);
  const r6 = both('false', 'false', badName);
  check(`${name}: findings in report mode never move the exit code, even beside a structure WARN`, r6.exit === 0 && new RegExp(`${name} WARN`).test(r6.stdout), `exit=${r6.exit}`);
  return { bad, enf, good };
}

console.log('\n# UX families — opt-in, and the action.yml wiring');
{
  const all = ['focus', 'forms', 'target', 'motion', 'consent'];
  const optin = run({ URLS: all.map((n) => fixture(`${n}-bad.html`)).join(' '), VIEWPORTS: 'desktop:1000x800', FAIL_ON_STRUCTURE: 'false', NAV_FILE: '' });
  check('opt-in: the default `render,nav` checks print no focus/forms/target/motion/consent section and no annotation',
    !/\*\*(focus|forms|target|motion|consent)|(focus|forms|target|motion|consent) (PASS|WARN|FAIL)|^::(warning|error)/m.test(optin.stdout), optin.stdout);
  check('action.yml: checks still defaults to render,nav (every family is opt-in)', inputDefault('checks') === 'render,nav', String(inputDefault('checks')));
  for (const n of all) {
    check(`action.yml: fail-on-${n} defaults to false and FAIL_ON_${n.toUpperCase()} reaches the script`,
      inputDefault(`fail-on-${n}`) === 'false' && new RegExp(`FAIL_ON_${n.toUpperCase()}: \\$\\{\\{ inputs\\.fail-on-${n} \\}\\}`).test(actionYml), String(inputDefault(`fail-on-${n}`)));
    check(`action.yml: the install + run steps fire for checks: ${n}`,
      (actionYml.match(new RegExp(`contains\\(inputs\\.checks, '${n}'\\)`, 'g')) || []).length >= 2);
  }
  check('action.yml: cls-budget defaults to 0.1 and CLS_BUDGET reaches the script', inputDefault('cls-budget') === '0.1' && /CLS_BUDGET: \$\{\{ inputs\.cls-budget \}\}/.test(actionYml));
  check('action.yml: consent-selector defaults to empty and CONSENT_SELECTOR reaches the script',
    inputDefault('consent-selector') === '' && /CONSENT_SELECTOR: \$\{\{ inputs\.consent-selector \}\}/.test(actionYml));
}

// ---------------------------------------------------------------------------
console.log('\n# focus — Tab-walk: skip link, obscured, indicator');
{
  const { bad } = commonFamilyChecks('focus', 'focus-bad.html', 'focus-good.html', {
    pageText: /Skip to content|Footer link|Under the banner|Link with no ring|Button with no ring/,
    goodTally: (l) => { const m = /(\d+) Tab stop\(s\), skip link present, 0 partly covered, (\d+) third-party/.exec(l) || []; return { ok: +m[1] >= 12 && +m[2] >= 1, want: '≥12 Tab stops, the skip link seen, ≥1 third-party skipped' }; },
  });
  check('skip-link-hidden: the skip link behind the fixed header is named, with what covers it',
    /\*\*skip-link-hidden\*\* `a\.skip[^`]*` “Skip to content” — the skip link is covered by header\.bar when focused/.test(bad.stdout), bad.stdout);
  check('focus-obscured: a fixed link and a footer link under the bottom banner are both named, with the banner',
    /\*\*focus-obscured\*\* `a#hidden`[^\n]*covered by div\.banner when focused \(all 5 sampled points\)/.test(bad.stdout) &&
      /\*\*focus-obscured\*\* `a#foot`[^\n]*covered by div\.banner/.test(bad.stdout), bad.stdout);
  check('focus-obscured: a link only PARTLY under the banner is not a finding — it is counted (1 partly covered)',
    !/a#partial/.test(bad.stdout) && /1 partly covered/.test(bad.stdout), bad.stdout);
  check('focus-no-indicator: outline:none + no shadow is named (a and button)',
    /\*\*focus-no-indicator\*\* `a#noring`/.test(bad.stdout) && /\*\*focus-no-indicator\*\* `button#noring2`/.test(bad.stdout), bad.stdout);
  check('focus-no-indicator: an input whose ring is a box-shadow is NOT flagged',
    !/input#ring/.test(bad.stdout), bad.stdout);
  check('third-party: an iframe, a .cf-turnstile host and a 1px hidden native checkbox raise no finding (2 third-party skipped)',
    !/iframe|turnstile|Hidden native box|widget/i.test(bad.stdout.replace(/third-party skipped/g, '')) && /2 third-party skipped/.test(bad.stdout), bad.stdout);
  check('every rule fires on BAD and nothing else does (5 groups: 1 skip link, 2 obscured, 2 indicator)',
    /5 finding group\(s\)/.test(bad.stdout), bad.stdout.slice(-300));
}
{
  // The transition wait is load-bearing: GOOD's rings and skip link fade/slide IN. Reading them at the first
  // frame (settleMs 0) must produce findings, or the GOOD page is not exercising the wait it claims to.
  const { chromium } = await import('playwright');
  const { runFocus } = await import(pathToFileURL(path.join(HERE, 'focus.mjs')).href);
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    await page.goto(fixture('focus-good.html'));
    const waited = await runFocus(page);
    check('mutant: with the transition wait, GOOD is clean (rings that fade in, a skip link that slides in)', waited.findings.length === 0 && !waited.fault, JSON.stringify(waited.findings));
    await page.goto(fixture('focus-good.html'));
    const nowait = await runFocus(page, { settleMs: 0 });
    check('mutant: WITHOUT the wait (read at the first frame) the same page is flagged — the fixture exercises it',
      nowait.findings.some((f) => f.rule === 'focus-no-indicator' || f.rule === 'skip-link-hidden'), JSON.stringify(nowait.findings.slice(0, 3)));
    await page.goto(fixture('focus-bad.html'));
    const capped = await runFocus(page, { max: 3 });
    check('the walk honours its cap and says so', capped.stats.stops === 3 && capped.notes.some((n) => /3-stop cap/.test(n)), JSON.stringify(capped.notes));
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------------------
console.log('\n# forms — label, autocomplete, font size, required cue');
{
  const { bad } = commonFamilyChecks('forms', 'forms-bad.html', 'forms-good.html', {
    pageText: /Your name|Your e-mail|Your question|Company|Phone/,
    goodTally: (l) => { const m = /(\d+) form\(s\), (\d+) control\(s\)/.exec(l) || []; return { ok: +m[1] >= 3 && +m[2] >= 12, want: '≥3 forms, ≥12 controls' }; },
  });
  check('label-not-visible: placeholder-only, aria-label-only and a visually-hidden label are each named for what they are',
    /\*\*label-not-visible\*\* `input\[name=your-name\]` “Your name” — no visible <label>: only a placeholder/.test(bad.stdout.replace(/[<>]/g, (c) => c)) || /label-not-visible\*\* `input\[name=your-name\]`[^\n]*only a placeholder/.test(bad.stdout), bad.stdout);
  check('label-not-visible: aria-label alone, and an sr-only label, are named too',
    /label-not-visible\*\* `input\[name=your-email\]`[^\n]*only an aria-label/.test(bad.stdout) && /label-not-visible\*\* `input#phone`[^\n]*visually hidden/.test(bad.stdout) &&
      /label-not-visible\*\* `textarea\[name=your-question\]`/.test(bad.stdout), bad.stdout);
  check('label-not-visible: a control with a real <label for> is not flagged (company, country)', !/label-not-visible\*\* `(input#company|select#country)/.test(bad.stdout), bad.stdout);
  check('autocomplete-missing: name, email and tel are named with the token they should carry',
    /autocomplete-missing\*\* `input\[name=your-name\]`[^\n]*"name"[^\n]*expected autocomplete="name"/.test(bad.stdout) &&
      /autocomplete-missing\*\* `input\[name=your-email\]`[^\n]*expected autocomplete="email"/.test(bad.stdout) &&
      /autocomplete-missing\*\* `input#phone`[^\n]*expected autocomplete="tel"/.test(bad.stdout), bad.stdout);
  check('autocomplete-missing: autocomplete="off" on an identity field counts as missing (organization)',
    /autocomplete-missing\*\* `input#company`[^\n]*has autocomplete="off" — expected autocomplete="organization"/.test(bad.stdout), bad.stdout);
  check('autocomplete-missing: a <select> and a <textarea> are never asked for a token (country, your-question)',
    !/autocomplete-missing\*\* `(select|textarea)/.test(bad.stdout), bad.stdout);
  check('input-font-size: 15.2px is flagged at the phone viewport ONLY (not at 1000px)',
    /input-font-size\*\* `input\[name=your-name\]`[^\n]*15\.2px is under 16px[^\n]*_\(iphone\)_/.test(bad.stdout) && !/input-font-size[^\n]*desktop|input-font-size[^\n]*all viewports/.test(bad.stdout), bad.stdout);
  check('input-font-size: the <select> and <textarea> are covered too',
    /input-font-size\*\* `select#country`/.test(bad.stdout) && /input-font-size\*\* `textarea\[name=your-question\]`/.test(bad.stdout), bad.stdout);
  check('required-unmarked: the three required controls with no cue are named',
    (bad.stdout.match(/required-unmarked\*\* `(input\[name=your-name\]|input\[name=your-email\]|textarea\[name=your-question\])`/g) || []).length === 3, bad.stdout);
  check('exclusions: the honeypot (autocomplete=off, off-screen) and both search boxes (role=search form; type=search in a plain form) raise nothing',
    !/website|name=q|name=s2|nonce/.test(bad.stdout) && /1 honeypot\(s\) skipped/.test(bad.stdout), bad.stdout);
  check('the submit button and the hidden input are not controls (6 inspected: name, email, phone, company, question, country)',
    /1 form\(s\), 6 control\(s\) inspected/.test(bad.stdout), bad.stdout.slice(-300));
}

// ---------------------------------------------------------------------------
console.log('\n# target — WCAG 2.5.8 through axe-core wcag22aa');
{
  const { bad } = commonFamilyChecks('target', 'target-bad.html', 'target-good.html', {
    pageText: /Previous|Next|One|Two|Three/,
    goodTally: (l) => { const m = /(\d+) interactive target\(s\), (\d+) under 44px/.exec(l) || []; return { ok: +m[1] >= 6 && +m[2] >= 1, want: '≥6 targets, ≥1 under 44px counted as a stat' }; },
  });
  check('target-size: the two 14px icon buttons 4px apart and the 18px links are named, with axe\'s own measurement',
    /target-size\*\* `[^`]*button[^`]*`[^\n]*“Previous” — Target has insufficient size \(14px by 14px, should be at least 24px by 24px\)/.test(bad.stdout) &&
      /target-size\*\* `[^`]*a[^`]*`[^\n]*“One” — Target has insufficient size \(18px by 18px/.test(bad.stdout), bad.stdout);
  check('target-size: axe\'s exceptions are inherited — an isolated 14px button and an inline text link are NOT findings',
    !/Isolated small button|inline link/.test(bad.stdout), bad.stdout);
  check('the advisory under-44px count is a STAT, never a finding (only target-size rule lines exist)',
    /7 under 44px \(advisory, not a finding\)/.test(bad.stdout) && !/\*\*(target-44|under-44)/.test(bad.stdout), bad.stdout.slice(-300));
}

// ---------------------------------------------------------------------------
console.log('\n# motion — reduced motion, smooth scroll, layout shift (own browser contexts)');
{
  const { bad } = commonFamilyChecks('motion', 'motion-bad.html', 'motion-good.html', {
    pageText: /infinite shine|slow fade|essential spinner|late banner|brief blip/,
    goodTally: (l) => { const m = /(\d+) CSS animation\(s\) running under reduce, layout shift 0\b/.exec(l) || []; return { ok: +m[1] >= 2, want: '≥2 animations seen running under reduce (the essential spinner and the brief one), layout shift 0' }; },
  });
  check('reduced-motion-animation: an infinite animation and an 8s one are named, with the element and the reason',
    /reduced-motion-animation\*\* `div\.shine[^`]*` “shine” — animation "shine" still runs under prefers-reduced-motion: reduce \(infinite\)/.test(bad.stdout) &&
      /reduced-motion-animation\*\* `div\.slow[^`]*` “slow” — animation "slow" still runs[^\n]*\(8s long\)/.test(bad.stdout), bad.stdout);
  check('reduced-motion-animation: the essential-motion spinner, the 0.4s blip and the animation guarded under reduce are NOT findings',
    !/spin|blip|guarded/.test(bad.stdout.replace(/prefers-reduced-motion/g, '')), bad.stdout);
  check('reduced-motion-smooth-scroll: the root\'s `scroll-behavior: smooth` is named',
    /reduced-motion-smooth-scroll\*\* `html` — the root has scroll-behavior: smooth under prefers-reduced-motion: reduce/.test(bad.stdout), bad.stdout);
  check('cls: the late banner shifts the page, over the 0.1 budget, at ALL viewports — the phone one included',
    /\*\*cls\*\* `\(page\)` — cumulative layout shift 0\.\d+ is over the 0\.1 budget \(1 shift[^\n]*_\(all viewports\)_/.test(bad.stdout), bad.stdout);
  const roomy = run(famEnv('motion', 'motion-bad.html', { CLS_BUDGET: '0.5' }));
  check('cls-budget is honoured: at 0.5 the same 0.3–0.35 shift is within budget (the other rules still fire)',
    !/\*\*cls\*\*/.test(roomy.stdout) && /reduced-motion-animation/.test(roomy.stdout), roomy.stdout);
  const junk = run(famEnv('motion', 'motion-bad.html', { CLS_BUDGET: 'lots' }));
  check('an unparseable cls-budget falls back to 0.1 (it does not disable the rule)', /\*\*cls\*\*/.test(junk.stdout), junk.stdout);
}

// ---------------------------------------------------------------------------
console.log('\n# consent — first-visit banner: reject, size, pre-ticked');
{
  const { bad } = commonFamilyChecks('consent', 'consent-bad.html', 'consent-good.html', {
    pageText: /Accept all|Manage preferences|Analytics|Profiling/,
    goodTally: (l) => { const m = /banner found: (\d+) accept, (\d+) reject/.exec(l) || []; return { ok: +m[1] === 1 && +m[2] === 1, want: 'banner found with 1 accept + 1 reject (the fixed "Allow cookie tips" widget was not mistaken for it)' }; },
  });
  check('consent-no-reject: an accept on the first layer and no reject is named (and says refusing sits behind settings)',
    /consent-no-reject\*\* `button#acc` — the first layer has an accept control \(140×40px\) and no reject — refusing sits behind a settings control/.test(bad.stdout), bad.stdout);
  check('consent-prechecked: an optional pre-ticked box is named, and one in a collapsed panel too',
    /consent-prechecked\*\* `input\[name=analytics\]` “Analytics”/.test(bad.stdout) && /consent-prechecked\*\* `input\[name=profiling\]` “Profiling”[^\n]*\(in a collapsed panel\)/.test(bad.stdout), bad.stdout);
  check('consent-prechecked: the always-on disabled "Necessary" box and the unticked "Marketing" box are NOT findings',
    !/Necessary|marketing/i.test(bad.stdout.replace(/consent-prechecked/g, '')), bad.stdout);
  const small = run(famEnv('consent', 'consent-smaller.html'));
  check('consent-reject-smaller: a 100×28 reject against a 180×48 accept is named, and ONLY that rule fires',
    /consent-reject-smaller\*\* `button#rej` — reject is 100×28px against accept 180×48px — under 80% in width/.test(small.stdout) &&
      !/consent-no-reject|consent-prechecked/.test(small.stdout), small.stdout);
  check('visual weight is an INFO note, never a finding (filled accept vs outline reject)',
    /ℹ️ INFO: accept is filled and reject is an outline/.test(small.stdout) && /1 finding group\(s\)/.test(small.stdout) && /weight filled\/outline/.test(small.stdout), small.stdout);
  const none = run(famEnv('consent', 'consent-none.html', { FAIL_ON_CONSENT: 'true' }));
  check('no banner found (a fixed "Allow notifications" widget, a static in-flow bar): a stat and an INFO note, never a finding — enforcing',
    none.exit === 0 && /no banner found/.test(none.stdout) && /no first-visit consent banner found/.test(none.stdout) && !/consent-no-reject/.test(none.stdout), none.stdout.slice(-300));
  const sel = run(famEnv('consent', 'consent-none.html', { CONSENT_SELECTOR: '#alt-bar' }));
  check('consent-selector overrides detection: the static #alt-bar is judged and its missing reject is named',
    /consent-no-reject\*\* `div#alt-bar > button`/.test(sel.stdout), sel.stdout);
  const miss = run(famEnv('consent', 'consent-none.html', { CONSENT_SELECTOR: '#nope', FAIL_ON_CONSENT: 'true' }));
  check('a consent-selector that matches nothing is a note, not a finding and not a fault',
    miss.exit === 0 && /matched no rendered element/.test(miss.stdout) && !/could not look/.test(miss.stdout), miss.stdout.slice(-300));
}

// ---------------------------------------------------------------------------
try { fs.unlinkSync(redNav); } catch { /* ignore */ }
console.log('\n# UX families — a fault in the check is a fault (axe missing, the page not evaluable)');
{
  // `target` needs node_modules/axe-core: run a copy of the scripts WITHOUT it (playwright symlinked in).
  const tmpT = fs.mkdtempSync(path.join(os.tmpdir(), 'vh-noaxe-'));
  try {
    const sdir = path.join(tmpT, 'scripts');
    fs.mkdirSync(sdir);
    for (const f of [...MODULES, 'render-check.mjs']) fs.copyFileSync(path.join(HERE, f), path.join(sdir, f));
    fs.mkdirSync(path.join(tmpT, 'node_modules'));
    fs.symlinkSync(path.join(path.dirname(HERE), 'node_modules', 'playwright'), path.join(tmpT, 'node_modules', 'playwright'));
    fs.symlinkSync(path.join(path.dirname(HERE), 'node_modules', 'playwright-core'), path.join(tmpT, 'node_modules', 'playwright-core'));
    const noAxe = (failOn) => {
      const r = spawnSync(process.execPath, [path.join(sdir, 'render-check.mjs')], {
        encoding: 'utf8', cwd: tmpT,
        env: { ...process.env, GITHUB_STEP_SUMMARY: '', CHECKS: 'target', FAIL_ON_TARGET: failOn, WAIT_MS: '0', VIEWPORTS: 'desktop:800x600', NAV_FILE: '', URLS: fixture('target-bad.html') },
      });
      return { exit: r.status, stdout: r.stdout || '' };
    };
    const a = noAxe('false');
    const b = noAxe('true');
    check('target without axe-core on disk: "target could not look", not a verdict on the page, not a PASS, not a finding',
      /target could not look/.test(a.stdout) && /not a verdict on the page/.test(a.stdout) && !/target PASS/.test(a.stdout) && !/\*\*target-size/.test(a.stdout), a.stdout.slice(-300));
    check('target without axe-core: report mode exits 0, fail-on-target exits 1', a.exit === 0 && b.exit === 1, `report ${a.exit}, enforce ${b.exit}`);
  } finally {
    fs.rmSync(tmpT, { recursive: true, force: true });
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
      for (const m of MODULES) fs.copyFileSync(path.join(HERE, m), path.join(tmp, m));
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
      for (const m of MODULES) fs.copyFileSync(path.join(HERE, m), path.join(tmp2, m));
      fs.writeFileSync(path.join(stub2, 'package.json'),
        JSON.stringify({ name: 'playwright', version: '0.0.0-stub', type: 'module', main: 'index.js' }));
      // Every affordance call (they carry {mode}) is recorded in AFF_CALLS, then throws; the render
      // measurement (no `mode`) gets a clean answer.
      fs.writeFileSync(path.join(stub2, 'index.js'), `
        import fs from 'node:fs';
        const page = { async goto() {}, async waitForLoadState() {}, async waitForTimeout() {}, url: () => 'https://example.invalid/',
          async evaluate(fn, arg) {
            if (typeof fn === 'string' && fn.startsWith('/*vh-ux*/')) { fs.appendFileSync(process.env.AFF_CALLS, 'u'); throw new Error('injected ux fault'); }
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

      // ---- the v1.27.0 families: an entrypoint crash, and a fault INSIDE the check, one family at a time ----
      const famCrash = (checks, env) => {
        const summaryPath = path.join(tmp, `sum-fam-${checks}-${JSON.stringify(env).length}.md`);
        fs.writeFileSync(summaryPath, '');
        const r = spawnSync(process.execPath, [path.join(tmp, 'render-launch.mjs')], {
          encoding: 'utf8',
          env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, CHECKS: checks, URLS: 'https://example.invalid/', ...env },
        });
        return { status: r.status, summary: fs.readFileSync(summaryPath, 'utf8') };
      };
      const inspectFam = (fam, failOn) => {
        const summaryPath = path.join(tmp2, `sum-${fam}-${failOn}.md`);
        fs.writeFileSync(summaryPath, '');
        const r = spawnSync(process.execPath, [path.join(tmp2, 'render-check.mjs')], {
          encoding: 'utf8',
          env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, CHECKS: fam, WAIT_MS: '0', VIEWPORTS: 'desktop:800x600',
            [`FAIL_ON_${fam.toUpperCase()}`]: String(failOn), URLS: 'https://example.invalid/', AFF_CALLS: path.join(tmp2, 'calls.txt') },
        });
        return { status: r.status, out: (r.stdout || '') + fs.readFileSync(summaryPath, 'utf8') };
      };
      for (const fam of ['focus', 'forms', 'target', 'motion', 'consent']) {
        const FV = `FAIL_ON_${fam.toUpperCase()}`;
        const cr = famCrash(fam, { FAIL_ON_STRUCTURE: 'true', [FV]: 'false' });
        const ce = famCrash(fam, { FAIL_ON_STRUCTURE: 'true', [FV]: 'true' });
        check(`[${fam}-only] a tool fault in report mode exits 0 although fail-on-structure is true, and names fail-on-${fam}`,
          cr.status === 0 && new RegExp(`\`fail-on-${fam}: false\``).test(cr.summary), `exit ${cr.status} ${cr.summary.slice(0, 160)}`);
        check(`[${fam}-only] a tool fault with fail-on-${fam}: true exits 1`, ce.status === 1 && new RegExp(`\`fail-on-${fam}: true\``).test(ce.summary), `exit ${ce.status}`);
        fs.writeFileSync(path.join(tmp2, 'calls.txt'), '');
        const fr = inspectFam(fam, false);
        const fe = inspectFam(fam, true);
        check(`[${fam} inspect fault] reported as the GATE's fault, not a verdict on the page, never a PASS, never a finding`,
          new RegExp(`${fam} could not look`).test(fr.out) && /not a verdict on the page/.test(fr.out) && !new RegExp(`${fam} PASS`).test(fr.out) &&
            !new RegExp(`\\*\\*${fam}\\*\\* ❌|\\*\\*${fam}\\*\\* ⚠️ — \\d+ finding`).test(fr.out), fr.out.slice(-300));
        check(`[${fam} inspect fault] report mode exits 0; fail-on-${fam} exits 1`, fr.status === 0 && fe.status === 1, `report ${fr.status}, enforce ${fe.status}`);
        check(`[${fam} inspect fault] the call counter is live: the check did look at the page`, fs.readFileSync(path.join(tmp2, 'calls.txt'), 'utf8').includes('u'));
      }
      const mixed = (checks, env) => famCrash(checks, env);
      const m1 = mixed('render,focus', { FAIL_ON_STRUCTURE: 'false', FAIL_ON_FOCUS: 'true' });
      const m2 = mixed('render,focus', { FAIL_ON_STRUCTURE: 'false', FAIL_ON_FOCUS: 'false' });
      const m3 = mixed('render,nav,consent', { FAIL_ON_STRUCTURE: 'true', FAIL_ON_CONSENT: 'false' });
      check('[render + focus] a crash blocks when ONLY fail-on-focus is true, and says which switch', m1.status === 1 && /`fail-on-focus: true`/.test(m1.summary), `exit ${m1.status} ${m1.summary.slice(0, 160)}`);
      check('[render + focus] a crash with both switches off exits 0 and names both', m2.status === 0 && /`fail-on-structure \/ fail-on-focus: false`/.test(m2.summary), `exit ${m2.status} ${m2.summary.slice(0, 160)}`);
      check('[render,nav + consent] a crash blocks on fail-on-structure alone (the family switch is off)', m3.status === 1 && /`fail-on-structure: true`/.test(m3.summary), `exit ${m3.status} ${m3.summary.slice(0, 160)}`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
}

console.log(failed === 0 ? '\n✅ all verify-homepage self-tests passed\n' : `\n❌ ${failed} self-test(s) failed\n`);
process.exit(failed === 0 ? 0 : 1);
