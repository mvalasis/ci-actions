// verify-homepage `motion` check — does the page hold still when it should? (opt-in, v1.27.0)
//
// The gap it closes (EPN, 2026-10-06 UI/UX review): under `prefers-reduced-motion: reduce` the homepage
// still ran two infinite CSS animations (epn-hero-shine, epn-map-flow — 39 running became 2) and `html`
// kept `scroll-behavior: smooth` on every page; and nothing in the fleet measured layout shift at all
// (the performance gates are "proposed"). Both need their OWN browser context, which is why this family
// does not share the page load the other families use:
//   1. a context with `reducedMotion: 'reduce'` — read what is still moving;
//   2. a FRESH context with a `layout-shift` PerformanceObserver installed before the page's own scripts
//      (addInitScript), so a shift that happens during load is not missed. Nothing else touched the page.
//
// Rules, per page × viewport (a finding is identified by rule + selector, merged across viewports):
//   reduced-motion-animation    under `reduce`, a CSS animation or transition from document.getAnimations()
//                               is still `running` and is infinite or lasts longer than 5s. WCAG 2.3.3 /
//                               2.2.2: motion the page itself starts and the user cannot stop. The finding
//                               names the animation and the element (and the pseudo-element, if any).
//   reduced-motion-smooth-scroll under `reduce`, the root's computed `scroll-behavior` is not `auto`.
//   cls                         the layout-shift sum after load + settle is over `cls-budget` (default 0.1,
//                               the Core Web Vitals "good" line). Sum over the whole load, not the worst
//                               session window — a stricter reading, and the number is in the stats either
//                               way. `hadRecentInput` is deliberately NOT used to discard entries: the
//                               context dispatches no input, and a mobile emulation flags every entry with
//                               it (measured: a shift 1.2s after load too), which would read 0 on every
//                               phone viewport.
// Opt-out for essential motion: an element with `data-essential-motion` (or inside one) is ignored by
// the animation rule — a loading spinner, a video the user started. Short, finite animations
// (≤5s, one-shot) are never a finding: they are not what 2.2.2 is about.
//
// NOT here, on purpose: JS-driven animation (requestAnimationFrame, a canvas, the Web Animations API called
// from script) — only CSS animations/transitions are asserted; autoplay video; parallax; LCP/INP (Lighthouse
// is the tool). CLS is measured headless on the runner's network, so it is lab data, not field data —
// expect run-to-run variance near the budget.
//
// Report-mode first: `fail-on-motion` defaults to false. Spec: ~/.claude/DISCIPLINES.md §7.
import { inPage } from './ux-page.mjs';

export const MOTION_ORDER = ['reduced-motion-animation', 'reduced-motion-smooth-scroll', 'cls'];

const REDUCED = (H) => {
  const { selectorOf, norm } = H;
  const findings = [];
  let running = 0;
  const essential = (el) => !!(el && el.closest && el.closest('[data-essential-motion]'));
  for (const an of document.getAnimations()) {
    const css = (typeof CSSAnimation !== 'undefined' && an instanceof CSSAnimation) || (typeof CSSTransition !== 'undefined' && an instanceof CSSTransition);
    if (!css || an.playState !== 'running') continue;
    running++;
    const t = an.effect && an.effect.target;
    if (!t || essential(t)) continue;
    const ct = an.effect.getComputedTiming();
    const infinite = ct.iterations === Infinity || ct.endTime === Infinity;
    if (!infinite && !(ct.endTime > 5000)) continue;
    const name = norm(an.animationName || an.transitionProperty || 'animation').replace(/[^\w-]/g, '').slice(0, 40);
    const kind = typeof CSSTransition !== 'undefined' && an instanceof CSSTransition ? 'transition' : 'animation';
    const pseudo = an.effect.pseudoElement ? String(an.effect.pseudoElement).replace(/[^\w:-]/g, '') : '';
    findings.push({
      rule: 'reduced-motion-animation',
      sel: selectorOf(t) + pseudo,
      text: name,
      detail: `${kind} "${name}" still runs under prefers-reduced-motion: reduce (${infinite ? 'infinite' : `${Math.round(ct.endTime / 100) / 10}s long`})`,
    });
  }
  const sb = getComputedStyle(document.documentElement).scrollBehavior;
  if (sb !== 'auto' && !essential(document.documentElement)) {
    findings.push({
      rule: 'reduced-motion-smooth-scroll', sel: 'html', text: '',
      detail: `the root has scroll-behavior: ${sb.replace(/[^\w-]/g, '')} under prefers-reduced-motion: reduce`,
    });
  }
  return { findings, running };
};

export async function runMotion({ newContext, gotoSettle, url, vp, opts = {} }) {
  const budget = Number.isFinite(opts.clsBudget) ? opts.clsBudget : 0.1;
  const out = { findings: [], notes: [], stats: { running: 0, cls: 0, shifts: 0 }, fault: '' };
  try {
    // 1. reduced motion
    let ctx = await newContext(vp, { reducedMotion: 'reduce' });
    try {
      const page = await ctx.newPage();
      await gotoSettle(page, url);
      const r = await inPage(page, REDUCED);
      out.findings.push(...r.findings);
      out.stats.running = r.running;
    } finally {
      await ctx.close();
    }
    // 2. layout shift, in a fresh context
    ctx = await newContext(vp);
    try {
      const page = await ctx.newPage();
      await page.addInitScript(() => {
        const w = (window.__vhCls = { sum: 0, n: 0, max: 0, flagged: 0, ok: true });
        try {
          new PerformanceObserver((list) => {
            for (const e of list.getEntries()) {
              // Not filtered on e.hadRecentInput: this context never dispatches an input, and a mobile
              // (isMobile) emulation flags EVERY entry hadRecentInput = true — measured on Chromium 1.61.1,
              // a shift 1.2s after load included — so honouring it would read 0 on every phone viewport.
              if (e.hadRecentInput) w.flagged++;
              w.sum += e.value;
              w.n++;
              w.max = Math.max(w.max, e.value);
            }
          }).observe({ type: 'layout-shift', buffered: true });
        } catch { w.ok = false; }
      });
      await gotoSettle(page, url);
      await page.waitForTimeout(700); // a late-arriving banner or lazy image is the classic shift
      const c = await page.evaluate(() => window.__vhCls || null);
      if (!c || !c.ok) out.notes.push('layout-shift entries are not observable in this browser — cls not measured');
      else {
        out.stats.cls = Math.round(c.sum * 1000) / 1000;
        out.stats.shifts = c.n;
        if (c.sum > budget) {
          out.findings.push({
            rule: 'cls', sel: '(page)', text: '',
            detail: `cumulative layout shift ${out.stats.cls} is over the ${budget} budget (${c.n} shift${c.n === 1 ? '' : 's'}, the largest ${Math.round(c.max * 1000) / 1000})`,
          });
        }
      }
    } finally {
      await ctx.close();
    }
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

export const MOTION = {
  name: 'motion',
  order: MOTION_ORDER,
  own: true,
  run: (c) => runMotion(c),
  tally: (s) => `${s.running} CSS animation(s) running under reduce, layout shift ${s.cls}`,
};
