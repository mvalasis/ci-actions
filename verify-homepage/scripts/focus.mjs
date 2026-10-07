// verify-homepage `focus` check — can a keyboard user SEE where they are? (opt-in, v1.27.0)
//
// The gap it closes (EPN, 2026-10-06 UI/UX review): the skip link is the first Tab stop on every page and
// its focused box sits at y 0–25 behind a 144px fixed header, so a keyboard user presses Tab and sees
// nothing; on /search/ and the 404 the focused footer links sit wholly under the cookie banner. axe cannot
// decide either (no rule for 2.4.11, and `bypass` only asks that a skip link EXISTS), and no gate in the
// fleet pressed Tab at all. Both are rendered, per-focus facts, so they live in the headless-Chromium tier.
//
// A real Tab-walk with the keyboard (so :focus-visible matches), from the top of the page: at most 60
// stops, ending when focus comes back to the first stop, leaves the document, or stops moving. Three rules,
// per page × viewport (a finding is identified by rule + selector, merged across viewports):
//   skip-link-hidden   the FIRST stop is an in-page #anchor link (a skip link) and, once focused, it has no
//                      real size (≤2px either way), sits outside the viewport, is transparent, or the point
//                      at the centre of its visible box hit-tests to something that is not the link or a
//                      descendant — i.e. it is behind a fixed header.
//   focus-obscured     WCAG 2.4.11: a stop whose centre AND four inset corner points (those inside the
//                      viewport) are ALL covered by a foreign element — neither an ancestor nor a
//                      descendant. Partly covered is NOT a finding (counted in the stats): 2.4.11 only
//                      fails when the element is entirely hidden.
//   focus-no-indicator a stop with `outline-style: none` (or a 0 outline width) AND `box-shadow: none`.
//                      An input that draws its ring as a box-shadow is fine. Transitions on the element are
//                      awaited first, so a ring that fades in is not read at its first frame.
// Third-party widgets are ignored by all three: a stop that is, sits inside, or contains an <iframe>,
// `.cf-turnstile`, `.g-recaptcha` or `.h-captcha`. A box of ≤2px (the visually-hidden native checkbox of a
// custom control, whose <label> carries the ring) is judged by neither obscured nor indicator.
//
// NOT here, on purpose: Tab ORDER against visual order (WCAG 2.4.3 — a heuristic with real false
// positives), a focus trap (the walk simply ends), focus appearance size/contrast (2.4.13 is AAA), and
// anything that needs a click: the check presses Tab and reads, it never activates a control.
//
// Report-mode first: `fail-on-focus` defaults to false. Spec: ~/.claude/DISCIPLINES.md §7.
import { inPage } from './ux-page.mjs';

export const FOCUS_ORDER = ['skip-link-hidden', 'focus-obscured', 'focus-no-indicator'];

// Reset to "nothing focused, top of the page" so the first Tab lands on the first stop.
const RESET = () => {
  if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur();
  scrollTo(0, 0);
  const sel = getSelection();
  if (sel) sel.removeAllRanges();
  return true;
};

// Describe the element that has focus NOW. Async: waits (≤ waitMs) for the element's own finite CSS
// transitions, so a skip link that slides in, or a ring that fades in, is read where it ends up.
const STOP = async (H, a) => {
  const { norm, selectorOf, textOf } = H;
  const el = document.activeElement;
  if (!el || el === document.body || el === document.documentElement) return { gone: true };
  const ids = (window.__vhFocusIds = window.__vhFocusIds || new WeakMap());
  let id = ids.get(el);
  if (!id) { window.__vhFocusN = (window.__vhFocusN || 0) + 1; id = window.__vhFocusN; ids.set(el, id); }

  void getComputedStyle(el).boxShadow; // flush style, so a transition started by the focus exists below
  const running = document.getAnimations().filter((an) => {
    const t = an.effect && an.effect.target;
    return t && (t === el || t.contains(el)) && an.playState === 'running' && an.effect.getComputedTiming().iterations !== Infinity;
  });
  if (running.length) {
    await Promise.race([Promise.all(running.map((an) => an.finished.catch(() => {}))), new Promise((r) => setTimeout(r, a.waitMs))]);
  }

  // Tab scrolls the focused element into view, and under `scroll-behavior: smooth` that takes a few
  // hundred ms: measuring before it ends reads the element mid-flight (or still off-screen). Wait until
  // the scroll position is unchanged for two frames, capped at waitMs.
  {
    const t0 = performance.now();
    let last = [scrollX, scrollY];
    let still = 0;
    while (still < 2 && performance.now() - t0 < a.waitMs) {
      await new Promise((r) => requestAnimationFrame(() => r()));
      const now = [scrollX, scrollY];
      still = now[0] === last[0] && now[1] === last[1] ? still + 1 : 0;
      last = now;
    }
  }

  const r = el.getBoundingClientRect();
  const cs = getComputedStyle(el);
  const iw = document.documentElement.clientWidth;
  const ih = innerHeight;
  const third = !!(el.closest('iframe,.cf-turnstile,.g-recaptcha,.h-captcha') || el.querySelector('iframe,.cf-turnstile,.g-recaptcha,.h-captcha'));
  const tiny = r.width <= 2 || r.height <= 2;
  const anchor = el.tagName === 'A' && /^#./.test(el.getAttribute('href') || '');
  const inView = (x, y) => x >= 0 && y >= 0 && x < iw && y < ih;
  const foreign = (hit) => !!hit && hit !== el && !el.contains(hit) && !hit.contains(el);

  // The five sample points: the centre of the part of the box that is on screen, and four inset corners.
  const vl = Math.max(r.left, 0), vt = Math.max(r.top, 0), vr = Math.min(r.right, iw), vb = Math.min(r.bottom, ih);
  const onScreen = vr > vl && vb > vt;
  const centre = onScreen ? [(vl + vr) / 2, (vt + vb) / 2] : null;
  const inset = Math.max(1, Math.min(4, r.width / 4, r.height / 4));
  const corners = [[r.left + inset, r.top + inset], [r.right - inset, r.top + inset], [r.left + inset, r.bottom - inset], [r.right - inset, r.bottom - inset]];
  const pts = (onScreen ? [centre, ...corners] : []).filter(([x, y]) => inView(x, y));
  let covered = 0;
  let by = '';
  let centreHit = null;
  let centreSampled = false;
  pts.forEach(([x, y], i) => {
    const hit = document.elementFromPoint(x, y);
    if (i === 0 && centre) { centreSampled = true; centreHit = hit; }
    if (foreign(hit)) { covered++; if (!by) by = selectorOf(hit); }
  });
  let opacity = 1;
  for (let p = el; p && p.nodeType === 1; p = p.parentElement) opacity *= Number(getComputedStyle(p).opacity);

  const label = norm(el.getAttribute('aria-label') || (el.tagName === 'INPUT' && /^(submit|button|reset)$/.test(el.type) ? el.value : textOf(el, true)) || el.getAttribute('placeholder') || el.getAttribute('name') || '').slice(0, 40);
  return {
    id, sel: selectorOf(el), text: label, w: Math.round(r.width), h: Math.round(r.height), third, tiny, anchor,
    onScreen, offViewport: !onScreen, opacity,
    centreCovered: centreSampled && foreign(centreHit), centreBy: centreHit && foreign(centreHit) ? selectorOf(centreHit) : '',
    pts: pts.length, covered, by, centreIn: centreSampled,
    outline: cs.outlineStyle !== 'none' && cs.outlineStyle !== 'hidden' && parseFloat(cs.outlineWidth) > 0,
    shadow: cs.boxShadow !== 'none',
  };
};

export async function runFocus(page, { max = 60, settleMs = 250 } = {}) {
  const out = { findings: [], notes: [], stats: { stops: 0, skipLink: 0, partlyCovered: 0, thirdParty: 0, offScreen: 0 }, fault: '' };
  try {
    await inPage(page, RESET);
    let first = null;
    let prev = null;
    let same = 0;
    let ended = false;
    const seen = new Set();
    for (let i = 0; i < max; i++) {
      await page.keyboard.press('Tab');
      const s = await inPage(page, STOP, { waitMs: i === 0 ? settleMs + 150 : settleMs });
      if (!s || s.gone) { ended = true; break; }                // focus left the document
      if (first === null) first = s.id;
      else if (s.id === first) { ended = true; break; }          // came all the way round
      if (s.id === prev) { if (++same >= 5) { ended = true; break; } continue; } // inside an iframe / not moving
      same = 0;
      prev = s.id;
      if (seen.has(s.id)) continue;
      seen.add(s.id);
      out.stats.stops++;

      let skipFired = false;
      if (out.stats.stops === 1 && s.anchor) {
        out.stats.skipLink = 1;
        let why = '';
        if (s.w <= 2 || s.h <= 2) why = `has no visible size when focused (${s.w}×${s.h}px)`;
        else if (s.offViewport) why = 'sits outside the viewport when focused';
        else if (s.opacity < 0.05) why = 'is transparent when focused';
        else if (s.centreCovered) why = `is covered by ${s.centreBy} when focused — a keyboard user presses Tab and sees nothing`;
        if (why) { skipFired = true; out.findings.push({ rule: 'skip-link-hidden', sel: s.sel, text: s.text, detail: `the skip link ${why}` }); }
      }
      if (s.third) { out.stats.thirdParty++; continue; }
      if (s.tiny) continue;
      if (!skipFired) {
        if (s.offViewport || !s.centreIn || s.pts < 3) out.stats.offScreen++;
        else if (s.covered === s.pts) {
          out.findings.push({ rule: 'focus-obscured', sel: s.sel, text: s.text, detail: `entirely covered by ${s.by} when focused (all ${s.pts} sampled points) — WCAG 2.4.11` });
        } else if (s.covered > 0) out.stats.partlyCovered++;
      }
      if (!s.outline && !s.shadow) {
        out.findings.push({ rule: 'focus-no-indicator', sel: s.sel, text: s.text, detail: 'no outline and no box-shadow when focused — a keyboard user cannot see where they are' });
      }
    }
    if (!ended) out.notes.push(`the Tab-walk stopped at the ${max}-stop cap without coming round to the first stop`);
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

export const FOCUS = {
  name: 'focus',
  order: FOCUS_ORDER,
  own: false,
  run: (c) => runFocus(c.page),
  tally: (s) => `${s.stops} Tab stop(s), ${s.skipLink ? 'skip link present' : 'no skip link'}, ${s.partlyCovered} partly covered, ${s.thirdParty} third-party skipped`,
};
