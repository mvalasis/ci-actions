// verify-homepage `forms` check — is the form usable before it is submitted? (opt-in, v1.27.0)
//
// The gap it closes (EPN, 2026-10-06 UI/UX review): /contact/ shipped name / e-mail / question fields
// with a placeholder and an aria-label but no visible <label>, no `autocomplete` (WCAG 1.3.5, AA), a 15.2px
// font on every input (iOS Safari zooms the page on focus below 16px) and three required fields with no
// sign that they were required. axe's `label` rule passes on an aria-label, `autocomplete-valid` only
// validates tokens that exist, and nothing reads a computed font-size or looks for a required cue. All four
// are rendered-DOM facts, read-only, and cheap — one in-page scan per viewport, same page load as `render`.
//
// Scope: every visible <form> (any control with a client box), every <input> / <select> / <textarea> in it
// except type=hidden|submit|button|image|reset, honeypots (autocomplete=off AND off-screen, ≤2px or
// transparent) and search inputs (type=search, role=searchbox, inside role=search). Four rules:
//   label-not-visible    no <label for> / wrapping <label> with visible text, and no aria-labelledby that
//                        points at visible text. A placeholder, an aria-label or a title alone is a finding,
//                        and so is a label that is visually hidden (sr-only). Checkboxes and radios are
//                        `affordance`'s (label-missing), not repeated here.
//   autocomplete-missing a text/email/tel/url/number input whose name / id / aria-label / type reads as an
//                        identity field — name, given-name, family-name, email, tel, organization,
//                        street-address, postal-code, address-level2, country, username — and carries no
//                        autocomplete token. `off` counts as missing (so does a form-level off with no
//                        attribute of its own); `on` and any other value do not (axe validates the token).
//   input-font-size      viewport width ≤600 only: computed font-size under 16px on a text-like input,
//                        select or textarea.
//   required-unmarked    a required / aria-required control with no visible required cue: `*` or the word
//                        required / mandatory / optional (also Greek) in its label, its placeholder, or a
//                        form-level sentence that states the convention ("fields marked * are required").
//
// NOT here, on purpose: how the form behaves when SUBMITTED (error summary, focus to the error, data kept,
// double-submit) — the check never types into or submits anything, and that needs a mocked POST in the
// caller's own Playwright test; input `type`/`inputmode` suitability; per-field validation messages.
//
// Report-mode first: `fail-on-forms` defaults to false. Spec: ~/.claude/DISCIPLINES.md §7.
import { inPage } from './ux-page.mjs';

export const FORMS_ORDER = ['label-not-visible', 'autocomplete-missing', 'required-unmarked', 'input-font-size'];

const SCAN = (H) => {
  const { norm, rendered, clipped, selectorOf, textOf } = H;
  const findings = [];
  const stats = { forms: 0, controls: 0, honeypots: 0 };
  const SKIP_TYPE = /^(hidden|submit|button|image|reset)$/;
  const ID_TYPE = /^(text|email|tel|url|number)$/;
  const TEXT_LIKE = /^(text|email|tel|url|number|password|search)$/;
  const narrow = document.documentElement.clientWidth <= 600;

  // ---- identity table (WCAG 1.3.5): token sets from name / id / aria-label, ordered most specific first ----
  const tokens = (s) =>
    new Set(String(s || '').replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  const has = (t, ...w) => w.some((x) => t.has(x));
  const ID_RULES = [
    ['email', (t, ty) => ty === 'email' || has(t, 'email', 'mail')],
    ['tel', (t, ty) => ty === 'tel' || has(t, 'tel', 'phone', 'telephone', 'mobile')],
    ['username', (t) => has(t, 'username', 'login') || (t.has('user') && has(t, 'name', 'id'))],
    ['given-name', (t) => (t.has('first') && t.has('name')) || has(t, 'given', 'fname', 'forename')],
    ['family-name', (t) => (t.has('last') && t.has('name')) || has(t, 'family', 'surname', 'lname')],
    ['organization', (t) => has(t, 'organization', 'organisation', 'company', 'employer', 'org')],
    ['postal-code', (t) => has(t, 'zip', 'postal', 'postcode') || (t.has('post') && t.has('code'))],
    ['address-level2', (t) => has(t, 'city', 'town')],
    ['country', (t) => t.has('country')],
    ['street-address', (t) => t.has('street') || (t.has('address') && !has(t, 'email', 'mail', 'ip', 'url', 'web'))],
    ['name', (t) => t.has('name')],
  ];
  const purpose = (el) => {
    const t = new Set([...tokens(el.getAttribute('name')), ...tokens(el.id), ...tokens(el.getAttribute('aria-label'))]);
    for (const [tok, test] of ID_RULES) if (test(t, el.type)) return tok;
    return '';
  };

  const hidden = (el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    const absRight = r.right + scrollX;
    const absBottom = r.bottom + scrollY;
    return r.width <= 2 || r.height <= 2 || Number(cs.opacity) === 0 || absRight <= 0 || absBottom <= 0 || clipped(el, cs);
  };
  const isSearch = (el) =>
    el.type === 'search' || el.getAttribute('role') === 'searchbox' || !!el.closest('[role="search"]');

  // ---- the visible label of a control ----
  const labelOf = (el) => {
    let visible = '';
    let hiddenText = '';
    for (const l of [...(el.labels || [])]) {
      const v = textOf(l, true);
      if (v) visible = visible ? `${visible} ${v}` : v;
      else if (textOf(l, false)) hiddenText = 'label';
    }
    const lb = el.getAttribute('aria-labelledby');
    if (lb) {
      for (const id of lb.split(/\s+/)) {
        const n = document.getElementById(id);
        if (!n) continue;
        const v = textOf(n, true);
        if (v) visible = visible ? `${visible} ${v}` : v;
        else if (textOf(n, false)) hiddenText = hiddenText || 'aria-labelledby target';
      }
    }
    return { visible, hiddenText };
  };

  const REQ_CUE = /\*|(?<![\p{L}])(required|mandatory|optional)(?![\p{L}])|υποχρεωτικ|προαιρετικ/iu;
  const REQ_SENTENCE =
    /(?<![\p{L}])(all|every|these|the|those) (fields?|inputs?)[^.\n]{0,40}(?<![\p{L}])(required|mandatory)|(?<![\p{L}])(required|mandatory) (fields?|inputs?)|(?<![\p{L}])fields? (marked|with|denoted)|\*[^.\n]{0,24}(?<![\p{L}])(required|mandatory)|(?<![\p{L}])(required|mandatory)[^.\n]{0,24}\*|υποχρεωτικ[αάοόή]\p{L}* πεδί|πεδία με \*|\*\s*=|όλα τα πεδία/iu;

  for (const form of [...document.forms]) {
    if (form.getAttribute('role') === 'search') continue;
    const els = [...form.elements].filter((e) => /^(INPUT|SELECT|TEXTAREA)$/.test(e.tagName) && !SKIP_TYPE.test(e.type) && rendered(e) && !e.closest('[inert]'));
    const ctl = [];
    for (const el of els) {
      if (isSearch(el)) continue;
      if ((el.getAttribute('autocomplete') || '').trim().toLowerCase() === 'off' && hidden(el)) { stats.honeypots++; continue; }
      ctl.push(el);
    }
    if (!ctl.length) continue;
    stats.forms++;
    const formText = textOf(form, true);
    const sentence = REQ_SENTENCE.test(formText);

    for (const el of ctl) {
      stats.controls++;
      const sel = selectorOf(el);
      const lab = labelOf(el);
      const box = /^(checkbox|radio)$/.test(el.type);
      const ph = norm(el.getAttribute('placeholder'));
      const aria = norm(el.getAttribute('aria-label'));
      const label = (lab.visible || ph || aria || norm(el.getAttribute('name'))).slice(0, 40);

      // 1. a visible label (checkboxes/radios: `affordance` owns them)
      if (!box && !lab.visible) {
        const only = lab.hiddenText
          ? `its ${lab.hiddenText} is visually hidden (sr-only), so a sighted user sees no label`
          : ph ? `only a placeholder ("${ph.slice(0, 30)}") names it — it disappears on typing`
          : aria ? 'only an aria-label names it' : norm(el.getAttribute('title')) ? 'only a title names it' : 'it has no label at all';
        findings.push({ rule: 'label-not-visible', sel, text: label, detail: `no visible <label>: ${only}` });
      }

      // 2. autocomplete on identity fields
      if (el.tagName === 'INPUT' && ID_TYPE.test(el.type)) {
        const want = purpose(el);
        if (want) {
          const own = el.getAttribute('autocomplete');
          const eff = (own != null ? own : form.getAttribute('autocomplete') || '').trim().toLowerCase();
          if (!eff || eff === 'off') {
            findings.push({
              rule: 'autocomplete-missing', sel, text: label,
              detail: `reads as the "${want}" field but has ${eff === 'off' ? 'autocomplete="off"' : 'no autocomplete token'} — expected autocomplete="${want}" (WCAG 1.3.5)`,
            });
          }
        }
      }

      // 3. iOS focus zoom
      if (narrow && (el.tagName !== 'INPUT' || TEXT_LIKE.test(el.type))) {
        const fs = parseFloat(getComputedStyle(el).fontSize);
        if (fs < 16) findings.push({ rule: 'input-font-size', sel, text: label, detail: `computed font-size ${Math.round(fs * 10) / 10}px is under 16px — iOS Safari zooms the page on focus` });
      }

      // 4. a required cue
      if ((el.required || el.getAttribute('aria-required') === 'true') && !sentence && !REQ_CUE.test(`${lab.visible} ${ph}`)) {
        findings.push({ rule: 'required-unmarked', sel, text: label, detail: 'required, but its label carries no asterisk or "required"/"optional" word, and no sentence in the form states the convention' });
      }
    }
  }
  return { findings, stats };
};

export async function runForms(page) {
  const out = { findings: [], notes: [], stats: { forms: 0, controls: 0, honeypots: 0 }, fault: '' };
  try {
    const r = await inPage(page, SCAN);
    out.findings.push(...r.findings);
    Object.assign(out.stats, r.stats);
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

export const FORMS = {
  name: 'forms',
  order: FORMS_ORDER,
  own: false,
  run: (c) => runForms(c.page),
  tally: (s) => `${s.forms} form(s), ${s.controls} control(s) inspected, ${s.honeypots} honeypot(s) skipped`,
};
