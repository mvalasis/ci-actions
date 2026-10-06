// verify-homepage `consent` check — is refusing as easy as accepting? (opt-in, v1.27.0)
//
// EDPB / CNIL practice for a first-visit cookie banner: a reject on the FIRST layer, as easy to hit as
// accept, and no optional category pre-ticked. The gap it closes: nothing in the fleet looks at the banner a
// first-time visitor gets (EPN's UI/UX review, 2026-10-06, found one that was fine — and had no way to know
// the next edit would not break it). A fresh browser context has no cookies, so the banner every page load
// of this action sees IS the first-visit banner. Read-only: the check never clicks, ticks or types.
//
// Detection (override with the `consent-selector` input): a rendered element that is `position: fixed` or
// `sticky`, or a `[role=dialog]` / `[role=alertdialog]` / `dialog[open]` / `[aria-modal=true]`, containing
// controls (button, a[href], [role=button], input button/submit) whose text or aria-label reads as ACCEPT
// (accept / agree / allow / ok / got it, and Greek αποδοχή / συμφωνώ). An element that holds an accept AND a
// reject control is preferred; one that holds only accept qualifies only if its text, id or class talks about
// cookies / consent / privacy (so a fixed "Allow notifications" widget is not a banner). Smallest wins.
// Reject is matched separately and first: reject / decline / deny / refuse / "necessary only" / "essential
// only" / "do not accept" (and Greek απόρριψη / μόνο απαραίτητα). "Manage / settings / preferences" is not
// a reject. Controls are matched by their own words, as a user reads them.
//   consent-no-reject       an accept control is on the first layer and no reject is
//   consent-reject-smaller  reject's width OR height is under 80% of accept's (the largest accept and the
//                           largest reject control are compared)
//   consent-prechecked      an optional-category checkbox in the banner is checked and not disabled
//                           (always-on "necessary / essential / required" boxes are exempt, and so is a
//                           disabled one). A checkbox in a collapsed preferences panel inside the banner
//                           counts: a pre-ticked box is invalid wherever the user meets it.
// Visual weight (filled vs outline, colour) is reported as an INFO note and in the stats — never a finding:
// whether a gold button against an outline one is "nudging" is a judgement call, size and position are not.
// No banner found → a stat and an INFO note only, never a finding (a site with none, or one that appears
// after the settle time, or lives inside a cross-origin iframe, is not something this check can judge).
//
// NOT here, on purpose: what happens after a click (does rejecting really stop the trackers — that needs
// the network and a cookie jar), the wording of the text, "reject takes more clicks" beyond the first layer,
// and whether the site needs a banner at all.
//
// Report-mode first: `fail-on-consent` defaults to false. Spec: ~/.claude/DISCIPLINES.md §7.
import { inPage } from './ux-page.mjs';

export const CONSENT_ORDER = ['consent-no-reject', 'consent-reject-smaller', 'consent-prechecked'];

const SCAN = (H, a) => {
  const { norm, rendered, selectorOf, textOf } = H;
  const findings = [];
  const notes = [];
  const stats = { banner: 0, accept: 0, reject: 0, checkboxes: 0 };
  const strip = (s) => norm(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  const ACCEPT = /(?<![\p{L}\p{N}])(accept|agree|allow|ok|okay|got it|αποδοχ\p{L}*|αποδεχ\p{L}*|συμφων\p{L}*)(?![\p{L}\p{N}])/u;
  const REJECT = /(?<![\p{L}\p{N}])(reject|decline|deny|refuse|necessary only|essential only|only necessary|only essential|necessary cookies only|do not accept|don't accept|dont accept|απορρι\p{L}*|μονο απαραιτητ\p{L}*)(?![\p{L}\p{N}])/u;
  const ALWAYS_ON = /necessary|essential|required|strictly|απαραιτητ|αναγκαι/;
  const CONTROLS = 'button,a[href],[role="button"],input[type="button"],input[type="submit"]';

  const labelOf = (el) =>
    strip(`${el.tagName === 'INPUT' ? el.value : textOf(el, true)} ${el.getAttribute('aria-label') || ''}`);
  const kind = (el) => {
    const t = labelOf(el);
    if (REJECT.test(t)) return 'reject';
    if (ACCEPT.test(t)) return 'accept';
    return 'other';
  };
  const area = (el) => { const r = el.getBoundingClientRect(); return r.width * r.height; };

  let banner = null;
  if (a.selector) {
    try { banner = [...document.querySelectorAll(a.selector)].find(rendered) || null; } catch { banner = null; }
    if (!banner) notes.push('the consent-selector matched no rendered element');
  } else {
    const cands = [...document.querySelectorAll('*')].filter((el) => {
      if (el.closest('[inert]')) return false;
      const pos = getComputedStyle(el).position;
      if (!(pos === 'fixed' || pos === 'sticky' || el.matches('[role="dialog"],[role="alertdialog"],dialog[open],[aria-modal="true"]'))) return false;
      const r = el.getBoundingClientRect();
      return rendered(el) && r.width > 0 && r.height > 0;
    });
    // A banner offers accept AND reject; a candidate that offers only accept counts as one only if it talks
    // about cookies/consent/privacy — else a fixed "Allow notifications" widget would be judged as a banner.
    const COOKIEISH = /cookie|consent|privacy|gdpr|ccpa|tracking|analytics|ιδιωτικ|απορρητ|συναινεσ/;
    const kinds = (el) => [...el.querySelectorAll(CONTROLS)].filter(rendered).map(kind);
    const both = cands.filter((el) => { const k = kinds(el); return k.includes('accept') && k.includes('reject'); });
    const accOnly = cands.filter((el) => kinds(el).includes('accept') && COOKIEISH.test(strip(`${textOf(el, false)} ${el.id} ${el.getAttribute('class') || ''}`)));
    const viable = both.length ? both : accOnly;
    viable.sort((x, y) => area(x) - area(y));
    banner = viable[0] || null;
  }
  if (!banner) {
    notes.push('no first-visit consent banner found — nothing to judge');
    return { findings, notes, stats };
  }
  stats.banner = 1;

  const controls = [...banner.querySelectorAll(CONTROLS)].filter(rendered);
  const accepts = controls.filter((c) => kind(c) === 'accept');
  const rejects = controls.filter((c) => kind(c) === 'reject');
  stats.accept = accepts.length;
  stats.reject = rejects.length;
  const big = (arr) => arr.slice().sort((x, y) => area(y) - area(x))[0];
  const acc = big(accepts);
  const rej = big(rejects);
  const dim = (el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.width)}×${Math.round(r.height)}px`; };

  if (acc && !rej) {
    const manage = controls.some((c) => /(settings|preferences|manage|customi[sz]e|options|ρυθμισ|προτιμησ)/.test(labelOf(c)));
    findings.push({
      rule: 'consent-no-reject', sel: selectorOf(acc), text: '',
      detail: `the first layer has an accept control (${dim(acc)}) and no reject${manage ? ' — refusing sits behind a settings control' : ''} (EDPB/CNIL: refusing must be as easy as accepting)`,
    });
  }
  if (acc && rej) {
    const ar = acc.getBoundingClientRect();
    const rr = rej.getBoundingClientRect();
    if (rr.width < 0.8 * ar.width || rr.height < 0.8 * ar.height) {
      findings.push({
        rule: 'consent-reject-smaller', sel: selectorOf(rej), text: '',
        detail: `reject is ${dim(rej)} against accept ${dim(acc)} — under 80% in ${rr.width < 0.8 * ar.width ? 'width' : 'height'}`,
      });
    }
    const filled = (el) => {
      const cs = getComputedStyle(el);
      const m = /rgba?\(([^)]+)\)/.exec(cs.backgroundColor);
      const alpha = m ? (m[1].split(',').length > 3 ? parseFloat(m[1].split(',')[3]) : 1) : 0;
      return alpha > 0.5 || cs.backgroundImage !== 'none';
    };
    const fa = filled(acc);
    const fr = filled(rej);
    stats.weight = `${fa ? 'filled' : 'outline'}/${fr ? 'filled' : 'outline'}`;
    if (fa !== fr) notes.push(`INFO: accept is ${fa ? 'filled' : 'an outline'} and reject is ${fr ? 'filled' : 'an outline'} — visual weight differs (a judgement call, never a finding)`);
  }

  const boxes = [...banner.querySelectorAll('input[type="checkbox"],[role="checkbox"],[role="switch"]')];
  stats.checkboxes = boxes.length;
  for (const b of boxes) {
    const input = b.tagName === 'INPUT';
    const checked = input ? b.checked : b.getAttribute('aria-checked') === 'true';
    const disabled = input ? b.disabled || !!b.closest('fieldset:disabled') : b.getAttribute('aria-disabled') === 'true';
    if (!checked || disabled) continue;
    const words = strip(`${[...(b.labels || [])].map((l) => textOf(l, false)).join(' ')} ${b.getAttribute('aria-label') || ''} ${b.name || ''} ${b.id || ''} ${b.value || ''}`);
    if (ALWAYS_ON.test(words)) continue;
    findings.push({
      rule: 'consent-prechecked', sel: selectorOf(b), text: norm([...(b.labels || [])].map((l) => textOf(l, false)).join(' ') || b.getAttribute('aria-label') || '').slice(0, 40),
      detail: `an optional-category box is pre-ticked${rendered(b) ? '' : ' (in a collapsed panel)'} — consent must be an affirmative act`,
    });
  }
  return { findings, notes, stats };
};

export async function runConsent(page, { selector = '' } = {}) {
  const out = { findings: [], notes: [], stats: { banner: 0, accept: 0, reject: 0, checkboxes: 0 }, fault: '' };
  try {
    const r = await inPage(page, SCAN, { selector });
    out.findings.push(...r.findings);
    out.notes.push(...r.notes);
    Object.assign(out.stats, r.stats);
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

export const CONSENT = {
  name: 'consent',
  order: CONSENT_ORDER,
  own: false,
  run: (c) => runConsent(c.page, c.opts),
  tally: (s) => (s.banner ? `banner found: ${s.accept} accept, ${s.reject} reject, ${s.checkboxes} checkbox(es)${s.weight ? `, weight ${s.weight} (accept/reject)` : ''}` : 'no banner found'),
};
