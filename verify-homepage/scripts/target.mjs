// verify-homepage `target` check — can a finger or a pointer hit it? (opt-in, v1.27.0)
//
// WCAG 2.5.8 Target Size (Minimum, AA, new in 2.2): a pointer target is at least 24×24 CSS px, or has
// enough free space around it. The gap it closes (EPN, 2026-10-06 UI/UX review): `a11y-audit` runs axe via
// pa11y with the tags wcag2a/wcag21a/wcag2aa/wcag21aa/best-practice — NOT `wcag22aa` — so axe's
// `target-size` rule never runs anywhere in the fleet, and DISCIPLINES §7 listed "target ≥24px" as gated.
// The review ran it by hand: 0 violations on EPN today, so this is regression insurance, not a backlog.
//
// How: axe-core (pinned, 4.11.4 — the version a11y-audit's pa11y already uses) is injected from
// `node_modules/axe-core/axe.min.js` through the DevTools protocol (so a page CSP cannot block it) and run
// with `runOnly: { type: 'tag', values: ['wcag22aa'] }`. Only the `target-size` rule's violations are
// kept, one finding per element, per page × viewport. axe decides what is exempt (inline links in running
// text, the spacing exception, user-agent controls), so this check inherits its judgement and its limits;
// a target axe puts under "incomplete" (needs review) is counted in the stats, never a finding.
//
// Also reported, STATS ONLY and never a finding: how many interactive targets render under 44px in either
// dimension (the Apple HIG / Material guideline, advisory — 15 on a typical desktop page of a content
// site, so it would be noise as a gate). The count is there so a number that doubles is visible.
//
// Report-mode first: `fail-on-target` defaults to false. Spec: ~/.claude/DISCIPLINES.md §7.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { inPage } from './ux-page.mjs';

export const TARGET_ORDER = ['target-size'];

const AXE_PATH = fileURLToPath(new URL('../node_modules/axe-core/axe.min.js', import.meta.url));
let axeSource = '';
const axe = () => (axeSource ||= fs.readFileSync(AXE_PATH, 'utf8'));

const RUN = async (H) => {
  const { norm, rendered, selectorOf, textOf } = H;
  const res = await window.axe.run(document, {
    runOnly: { type: 'tag', values: ['wcag22aa'] },
    resultTypes: ['violations', 'incomplete'],
    elementRef: true,
  });
  const findings = [];
  for (const v of res.violations.filter((x) => x.id === 'target-size')) {
    for (const n of v.nodes) {
      const el = n.element;
      if (!el) continue;
      const msg = norm(((n.any && n.any[0]) || (n.all && n.all[0]) || (n.none && n.none[0]) || {}).message || 'target is smaller than 24×24 CSS px');
      const text = norm(el.getAttribute('aria-label') || (el.tagName === 'INPUT' ? el.value || el.type : textOf(el, true))).slice(0, 40);
      findings.push({ rule: 'target-size', sel: selectorOf(el), text, detail: msg.slice(0, 200) });
    }
  }
  const review = res.incomplete.filter((x) => x.id === 'target-size').reduce((n, v) => n + v.nodes.length, 0);

  // stats only: interactive targets rendered under 44px in either dimension
  const INTERACTIVE =
    'a[href],button,input:not([type="hidden"]),select,textarea,summary,[role="button"],[role="link"],[role="checkbox"],[role="radio"],[role="tab"],[role="menuitem"],[role="switch"],[tabindex]:not([tabindex^="-"])';
  let targets = 0;
  let under44 = 0;
  for (const el of document.querySelectorAll(INTERACTIVE)) {
    if (!rendered(el) || el.closest('[inert]') || el.matches(':disabled')) continue;
    const r = el.getBoundingClientRect();
    if (r.width <= 2 || r.height <= 2) continue; // a visually-hidden native control: its label is the target
    targets++;
    if (r.width < 44 || r.height < 44) under44++;
  }
  return { findings, stats: { violations: findings.length, needsReview: review, targets, under44 } };
};

export async function runTarget(page) {
  const out = { findings: [], notes: [], stats: { violations: 0, needsReview: 0, targets: 0, under44: 0 }, fault: '' };
  try {
    if (!(await page.evaluate(() => typeof window.axe === 'object'))) await page.evaluate(axe());
    const r = await inPage(page, RUN);
    out.findings.push(...r.findings);
    Object.assign(out.stats, r.stats);
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

export const TARGET = {
  name: 'target',
  order: TARGET_ORDER,
  own: false,
  run: (c) => runTarget(c.page),
  tally: (s) => `${s.targets} interactive target(s), ${s.under44} under 44px (advisory, not a finding), ${s.needsReview} needs-review`,
};
