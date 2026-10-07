// verify-homepage `affordance` check — does a control LOOK and BEHAVE like what it is?
//
// The gap it closes (EPN, 2026-10-06): /contact/ and /employers/ shipped a consent checkbox whose
// visible text sat OUTSIDE any <label> (clicking the words did nothing), whose aria-label said
// something else than the words, and a submit button + checkbox with no `cursor: pointer`. Nothing in
// the fleet saw it: pa11y/axe flag a MISSING label but not label-in-name or a text-that-is-not-a-label,
// and no gate reads computed `cursor` at all. These are rendered-DOM facts, so they live here with the
// rest of the headless-Chromium tier (verify-homepage), run on the same weekly + cutover schedule.
//
// Four rules, per page × viewport (a finding is identified by rule + selector, merged across viewports):
//   label-missing  a visible checkbox/radio has no associated <label> (wrapping, or for=), or no
//                  accessible name at all. When the control has no label but plain text sits next to it
//                  (the EPN shape) the text is quoted: it is the words that should have been the label.
//   label-in-name  WCAG 2.5.3 Label in Name: the visible label text must be contained in the control's
//                  accessible name. Only an aria-label / aria-labelledby / title can break that (a name
//                  taken from the <label> itself contains it by construction). With no <label> the nearby
//                  visible text stands in for it, so an aria-label that says something else is caught.
//   label-click    a REAL mouse click on the label's own text (hit-tested, so an overlay or
//                  pointer-events:none is caught too) must flip the checkbox / check the radio. The state
//                  is restored afterwards. Disabled and not-rendered controls are skipped.
//   cursor         computed `cursor` must be `pointer` on button, input[type=submit|button|reset|image],
//                  a[href], summary, [role=button], select, input[type=checkbox|radio|file], and on a
//                  <label> that wraps/targets a checkbox or radio. `not-allowed` / `default` are fine
//                  only when the control is disabled.
//
// NOT here, on purpose: a visible :hover / :focus-visible change. Measured against the shape of the
// problem it is neither cheap nor quiet — it needs a pointer move + a style diff + a transition wait
// per element (hundreds of links per page × 4 viewports), a touch viewport has no hover at all, and
// the legitimate change is often on a parent, a pseudo-element or an outline rather than the element's
// own computed style. The focus ring is already gated (DISCIPLINES §7: focus-ring ≥2px/≥3:1, axe).
//
// Report-mode first: verify-homepage's `fail-on-affordance` defaults to false. Spec:
// ~/.claude/DISCIPLINES.md §7 (UI/UX — Gateable).

// The in-page half. ONE self-contained function (Playwright serialises it with .toString(), so it may
// close over nothing from this module). `args.mode`: 'scan' (rules 1, 2's eligibility, 4),
// 'prepare' (scroll a control's label text into view and hand back a click point), 'state'.
export const AFFORDANCE_PAGE = (args) => {
  const norm = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  // Compared form: case-folded, punctuation and spacing collapsed, so "I agree." ⊇ "i agree" and a Greek
  // label compares like a Latin one.
  const fold = (s) => norm(s).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
  const CTRL = 'input[type="checkbox"],input[type="radio"]';
  const SKIP_TAG = /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|OPTION|SELECT|TEXTAREA)$/;
  const rendered = (el) => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  const clipped = (el, cs) => {
    const r = el.getBoundingClientRect();
    return (
      (el.getClientRects().length > 0 && (r.width <= 1 || r.height <= 1) && cs.overflow !== 'visible') ||
      /rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)/.test(cs.clip) ||
      /inset\(\s*50%\s*\)/.test(cs.clipPath)
    );
  };

  // ---- a short, valid, unambiguous-enough selector. Tokens are restricted to [A-Za-z0-9_-] so the
  //      result carries no markup-hostile character and can sit in a code span or an annotation. ----
  const tok = (s) => (/^[A-Za-z_][\w-]*$/.test(s) ? s : '');
  const one = (n) => {
    const tag = n.tagName.toLowerCase();
    const id = tok(n.id);
    if (id && document.querySelectorAll('#' + id).length === 1) return { s: `${tag}#${id}`, anchor: true };
    const cls = [...n.classList].filter((c) => tok(c)).slice(0, 2).map((c) => '.' + c).join('');
    let s = tag + cls;
    const p = n.parentElement;
    if (p) {
      const same = [...p.children].filter((c) => c.tagName === n.tagName);
      if (same.length > 1) s += `:nth-of-type(${same.indexOf(n) + 1})`;
    }
    return { s, anchor: false };
  };
  const selectorOf = (el) => {
    const parts = [];
    let n = el;
    for (let d = 0; n && n.nodeType === 1 && d < 6; d++, n = n.parentElement) {
      const { s, anchor } = one(n);
      parts.unshift(s);
      if (anchor || n === document.body) break;
      try {
        if (document.querySelectorAll(parts.join(' > ')).length === 1) break;
      } catch { /* keep climbing */ }
    }
    return parts.join(' > ');
  };

  // ---- text. `visible` = what a sighted user reads (no sr-only, no display:none); otherwise = what
  //      the accessible-name algorithm reads (sr-only included, display:none / visibility:hidden not). ----
  const textNodes = (root) => {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const out = [];
    for (let n = w.nextNode(); n; n = w.nextNode()) out.push(n);
    return out;
  };
  const nodeOk = (n, root, visible) => {
    if (!norm(n.nodeValue)) return false;
    for (let p = n.parentElement; p; p = p.parentElement) {
      if (SKIP_TAG.test(p.tagName)) return false;
      const cs = getComputedStyle(p);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (visible && clipped(p, cs)) return false;
      if (p === root) break;
    }
    if (visible) {
      const rg = document.createRange();
      rg.selectNodeContents(n);
      const rs = [...rg.getClientRects()].filter((r) => r.width > 1 && r.height > 1);
      if (!rs.length) return false;
    }
    return true;
  };
  const textOf = (root, visible) =>
    norm(textNodes(root).filter((n) => nodeOk(n, root, visible)).map((n) => n.nodeValue).join(' '));

  // ---- accessible name of a form control: aria-labelledby > aria-label > <label> text > title ----
  const nameOf = (el) => {
    const lb = el.getAttribute('aria-labelledby');
    if (lb) {
      const t = norm(
        lb.split(/\s+/).map((id) => document.getElementById(id)).filter(Boolean)
          .map((n) => n.getAttribute('aria-label') || textOf(n, false)).join(' ')
      );
      if (t) return { name: t, src: 'aria-labelledby' };
    }
    const al = norm(el.getAttribute('aria-label'));
    if (al) return { name: al, src: 'aria-label' };
    const labels = [...(el.labels || [])];
    const lt = norm(labels.map((l) => textOf(l, false)).join(' '));
    if (lt) return { name: lt, src: 'label' };
    const ti = norm(el.getAttribute('title'));
    if (ti) return { name: ti, src: 'title' };
    return { name: '', src: '' };
  };

  // The visible text beside a control that has NO label: the nearest ancestor (≤5 up) that holds this
  // one checkbox/radio and no other form control, with some visible text of its own.
  const nearbyOf = (el) => {
    let p = el.parentElement;
    for (let d = 0; p && d < 5 && p !== document.body && !/^(FORM|FIELDSET)$/.test(p.tagName); d++, p = p.parentElement) {
      if (p.querySelectorAll('input:not([type="hidden"]),select,textarea,button').length !== 1) return '';
      const t = textOf(p, true);
      if (fold(t)) return t.length <= 300 ? t : '';
    }
    return '';
  };

  const controls = () => [...document.querySelectorAll(CTRL)];
  const hiddenInput = (el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    return Number(cs.opacity) === 0 || r.width <= 2 || r.height <= 2 || clipped(el, cs);
  };

  if (args.mode === 'state') {
    const el = controls()[args.index];
    return el ? { checked: el.checked, url: location.href } : null;
  }

  if (args.mode === 'dismiss') {
    // What covers the point (args.x, args.y)? If it is a first-visit cookie/consent banner, press the
    // REJECT control on its first layer (privacy-preserving: never accept) so the click leg can reach the
    // control the banner was hiding. Anything else that covers it — a header, a chat widget, a promo — is
    // left alone and stays a finding. Reject words are consent.mjs's.
    const REJECT = /(?<![\p{L}\p{N}])(reject|decline|deny|refuse|necessary only|essential only|only necessary|only essential|necessary cookies only|do not accept|don't accept|dont accept|απορρι\p{L}*|μονο απαραιτητ\p{L}*)(?![\p{L}\p{N}])/u;
    const BANNERISH = /cookie|consent|gdpr|privacy|συναινεση|cookies/i;
    let hit = document.elementFromPoint(args.x, args.y);
    let overlay = null;
    for (let n = hit; n && n !== document.body; n = n.parentElement) {
      const pos = getComputedStyle(n).position;
      if (pos === 'fixed' || pos === 'sticky') { overlay = n; break; }
    }
    if (!overlay) return { skip: 'the cover is not a fixed/sticky overlay' };
    const ident = [overlay.id, overlay.className && overlay.className.baseVal === undefined ? overlay.className : '', overlay.getAttribute('aria-label'), overlay.getAttribute('role')].join(' ');
    if (!BANNERISH.test(ident) && !BANNERISH.test(norm(overlay.textContent).slice(0, 400))) return { skip: 'the cover is not a cookie/consent banner' };
    const btn = [...overlay.querySelectorAll('button,[role="button"],a[href],input[type="button"],input[type="submit"]')]
      .find((b) => rendered(b) && REJECT.test(norm(b.getAttribute('aria-label') || b.value || b.textContent).toLowerCase()));
    if (!btn) return { skip: 'the cookie banner has no reject control on its first layer' };
    const label = norm(btn.getAttribute('aria-label') || btn.value || btn.textContent).slice(0, 30);
    btn.click();
    return { dismissed: label, banner: selectorOf(overlay) };
  }

  if (args.mode === 'prepare') {
    // Where to put the pointer: the first piece of plain label text that is not itself a link/button/
    // control (clicking a privacy-policy link would navigate, and that is not a label click anyway).
    const el = controls()[args.index];
    if (!el || el.disabled || !rendered(el)) return { skip: 'not clickable' };
    const labels = [...(el.labels || [])].filter((l) => l.getClientRects().length > 0);
    for (const l of labels) {
      const node = textNodes(l).find(
        (n) => nodeOk(n, l, true) && !(n.parentElement && n.parentElement.closest('a,button,input,select,textarea,summary,[role="button"],[role="link"]'))
      );
      if (!node) continue;
      // 'instant', not the default: a page with `scroll-behavior: smooth` (EPN) would otherwise scroll
      // AFTER the hit-test below, which then reads whatever sits over the label's OLD position (the fixed
      // header, the cookie banner) and reports a cover the user never sees once the page has settled.
      node.parentElement.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' });
      const rg = document.createRange();
      rg.selectNodeContents(node);
      const r = [...rg.getClientRects()].find((q) => q.width > 1 && q.height > 1);
      if (!r) continue;
      const x = r.left + r.width / 2;
      const y = r.top + r.height / 2;
      if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return { skip: 'label text is off-screen' };
      const hit = document.elementFromPoint(x, y);
      const within = !!hit && (l.contains(hit) || hit === el || hit.closest('label') === l);
      return {
        x, y, checked: el.checked, type: el.type,
        // the radio of this group that is checked NOW, so the restore can put the choice back
        groupPrev: el.type === 'radio' && el.name
          ? controls().findIndex((c) => c !== el && c.type === 'radio' && c.name === el.name && c.form === el.form && c.checked)
          : -1,
        within, hit: hit ? selectorOf(hit) : '(nothing)',
      };
    }
    return { skip: 'no plain-text label to click' };
  }

  // ---- mode: scan ----
  const findings = [];
  const stats = { controls: 0, clickable: 0, cursors: 0 };

  controls().forEach((el) => {
    if (!rendered(el)) return; // display:none / hidden attr / visibility:hidden: not a visible control
    if (el.closest('[inert]')) return;
    stats.controls++;
    const labels = [...(el.labels || [])];
    const { name, src } = nameOf(el);
    const sel = selectorOf(el);
    const visLabel = norm(labels.map((l) => textOf(l, true)).join(' '));
    const nearby = labels.length ? '' : nearbyOf(el);
    if (!labels.length) {
      findings.push({
        rule: 'label-missing', sel, text: nearby,
        detail: nearby
          ? 'no <label> wraps it or targets it with for=, so the words beside it are not its label (clicking them does nothing)'
          : name ? `no <label> wraps it or targets it with for= (named only by ${src})` : 'no <label>, and no accessible name at all',
      });
    } else if (!name) {
      findings.push({ rule: 'label-missing', sel, text: visLabel, detail: 'it has a <label> but no accessible name (the label holds no text)' });
    }
    // 2.5.3 — a name from the <label> contains the label's text by construction; only an override can break it.
    const shown = visLabel || nearby;
    if (src && src !== 'label' && fold(shown) && !fold(name).includes(fold(shown))) {
      findings.push({
        rule: 'label-in-name', sel, text: shown,
        detail: `${src} "${name.slice(0, 80)}" does not contain the visible ${visLabel ? 'label' : 'nearby'} text`,
      });
    }
    if (!el.disabled && !el.closest('fieldset:disabled') && !(el.type === 'radio' && el.checked)) stats.clickable++;
  });

  // Which controls are worth a label-click: index into controls() — the same order 'prepare' uses.
  const clickIdx = [];
  controls().forEach((el, index) => {
    if (!rendered(el)) return;
    if (el.closest('[inert]') || el.matches(':disabled')) return;
    if ([...(el.labels || [])].length === 0) return; // no label to click — label-missing already says so
    clickIdx.push({ index, sel: selectorOf(el), type: el.type, checked: el.checked });
  });

  // ---- cursor ----
  const CUR = [
    'button', 'input[type="submit"]', 'input[type="button"]', 'input[type="reset"]', 'input[type="image"]',
    'a[href]', 'summary', '[role="button"]', 'select', 'input[type="checkbox"]', 'input[type="radio"]',
    'input[type="file"]', 'label',
  ].join(',');
  const DISABLED_OK = new Set(['not-allowed', 'default', 'auto', 'pointer', 'no-drop']);
  for (const el of document.querySelectorAll(CUR)) {
    if (!rendered(el) || el.closest('[inert]')) continue;
    const cs = getComputedStyle(el);
    if (cs.pointerEvents === 'none') continue;
    let disabled = el.matches(':disabled') || el.getAttribute('aria-disabled') === 'true';
    let kind = el.tagName.toLowerCase();
    if (kind === 'label') {
      const c = el.control;
      if (!c || !/^(checkbox|radio)$/.test(c.type)) continue;
      disabled = c.disabled;
      kind = `label for ${c.type}`;
    } else if (kind === 'input') {
      kind = `input type=${el.type}`;
      // A visually-hidden native box (custom checkbox) never shows a cursor: its <label> carries it.
      if (/^(checkbox|radio|file)$/.test(el.type) && hiddenInput(el)) continue;
    } else if (el.getAttribute('role') === 'button' && kind !== 'button') {
      kind = `${kind} role=button`;
    }
    stats.cursors++;
    const cursor = cs.cursor;
    const last = cursor.split(',').pop().trim();
    const ok = disabled ? DISABLED_OK.has(last) : last === 'pointer';
    if (ok) continue;
    const text = norm(
      el.getAttribute('aria-label') ||
        (el.tagName === 'INPUT'
          ? /^(submit|button|reset)$/.test(el.type) ? el.value : el.type === 'image' ? el.alt : [...(el.labels || [])].map((l) => textOf(l, true)).join(' ')
          : textOf(el, true))
    ).slice(0, 40);
    findings.push({
      rule: 'cursor', sel: selectorOf(el), text,
      detail: `${kind} has cursor: ${last}${disabled ? ' while disabled' : ', expected pointer'}`,
    });
  }
  return { findings, clickIdx, stats };
};

// The Node half: run the scan, then the real-click leg. Never throws a finding about the CALLER's page
// as an exception — a fault here is the gate's, and is returned as `fault` so the caller can report it
// as such (scanner-conventions.md: a scanner that could not look is a fault, never a PASS).
export async function runAffordance(page, { settleMs = 60, dismissSettleMs = 500 } = {}) {
  let dismissTried = false;
  const out = { findings: [], notes: [], stats: { controls: 0, clickable: 0, cursors: 0, clicked: 0 }, fault: '' };
  try {
    const scan = await page.evaluate(AFFORDANCE_PAGE, { mode: 'scan' });
    out.findings.push(...scan.findings);
    Object.assign(out.stats, scan.stats);
    const startUrl = page.url();
    for (const c of scan.clickIdx) {
      let p = await page.evaluate(AFFORDANCE_PAGE, { mode: 'prepare', index: c.index });
      if (!p || p.skip) {
        if (p && p.skip && p.skip !== 'no plain-text label to click') out.notes.push(`${c.sel}: label click skipped — ${p.skip}`);
        continue;
      }
      // A checked radio cannot be un-checked by a click, so there is no flip to assert on it.
      if (c.type === 'radio' && p.checked) continue;
      // A first-visit cookie banner can sit over the control (a fresh browser context always sees it). Reject
      // it once and look again; a cover that is not a banner (or a banner with no reject) stays a finding.
      if (!p.within && !dismissTried) {
        dismissTried = true;
        const d = await page.evaluate(AFFORDANCE_PAGE, { mode: 'dismiss', x: p.x, y: p.y });
        if (d && d.dismissed) {
          out.notes.push(`${d.banner}: rejected the cookie banner (“${d.dismissed}”) to reach ${c.sel}`);
          await page.waitForTimeout(dismissSettleMs);
          const again = await page.evaluate(AFFORDANCE_PAGE, { mode: 'prepare', index: c.index });
          if (again && !again.skip) p = again;
        }
      }
      out.stats.clicked++;
      // The scroll above was 'instant', but Chromium hit-tests an input event against the last COMMITTED
      // frame: a click sent in the same tick lands where the label WAS (v1.28.1: ~3 of 4 live clicks on
      // EPN /contact/ missed and read "did not toggle"). Two animation frames put the scrolled layout in.
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await page.mouse.click(p.x, p.y);
      await page.waitForTimeout(settleMs);
      if (page.url().split('#')[0] !== startUrl.split('#')[0]) {
        out.notes.push(`${c.sel}: clicking the label navigated the page — the label-click leg stopped here`);
        break;
      }
      let after = await page.evaluate(AFFORDANCE_PAGE, { mode: 'state', index: c.index });
      let flipped = !!after && after.checked !== p.checked;
      if (!flipped && p.within) {
        // One retry from a fresh scroll + frame wait: a headless click can still land a frame early
        // (1 in ~6 live runs on EPN /contact/). A control that genuinely swallows the click fails twice.
        const p2 = await page.evaluate(AFFORDANCE_PAGE, { mode: 'prepare', index: c.index });
        if (p2 && !p2.skip && p2.within) {
          await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
          await page.mouse.click(p2.x, p2.y);
          await page.waitForTimeout(settleMs);
          after = await page.evaluate(AFFORDANCE_PAGE, { mode: 'state', index: c.index });
          flipped = !!after && after.checked !== p.checked;
        }
      }
      if (!flipped) {
        out.findings.push({
          rule: 'label-click', sel: c.sel, text: '',
          detail: p.within
            ? `clicking the label text did not ${c.type === 'radio' ? 'select' : 'toggle'} the control`
            : `clicking the label text hit ${p.hit}, not the label — something sits over it, so the click never reaches the control`,
        });
        continue;
      }
      // Restore: a checkbox by the same click; a radio by re-selecting the group's previous choice,
      // else by clearing it (a click cannot).
      if (c.type === 'checkbox') {
        const q = await page.evaluate(AFFORDANCE_PAGE, { mode: 'prepare', index: c.index });
        if (q && !q.skip) await page.mouse.click(q.x, q.y);
        else await page.evaluate((i) => { const e = document.querySelectorAll('input[type="checkbox"],input[type="radio"]')[i]; if (e) e.checked = false; }, c.index);
      } else {
        await page.evaluate(({ i, prevIdx }) => {
          const all = [...document.querySelectorAll('input[type="checkbox"],input[type="radio"]')];
          const e = all[i];
          if (!e) return;
          e.checked = false;
          if (prevIdx >= 0 && all[prevIdx]) all[prevIdx].checked = true;
        }, { i: c.index, prevIdx: p.groupPrev });
      }
    }
  } catch (e) {
    out.fault = String((e && e.message) || e).slice(0, 160);
  }
  return out;
}

// ---- report plumbing: grouping, formatting and annotations live in ./ux-report.mjs (shared by every family) ----

// Behavioural findings first: they are the ones a caller cannot see by looking, and the ones a capped
// annotation list must not cut off.
export const AFFORDANCE_ORDER = ['label-click', 'label-in-name', 'label-missing', 'cursor'];
