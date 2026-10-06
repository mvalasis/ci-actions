// verify-homepage — the in-page helpers shared by the opt-in UX check families (focus, forms, target,
// motion, consent; v1.27.0). `affordance` (v1.26.0) carries its own copy and is left untouched.
//
// Playwright serialises a page function with .toString(), so it may close over nothing from the module
// it was written in. A family therefore writes its in-page half as `(H, args) => …` and runs it through
// `inPage(page, fn, args)`, which ships HELPERS' source beside it and hands the result in as `H`. The
// expression starts with a `/*vh-ux*/` marker — the selftest's stubbed `playwright` keys on it to make
// the check fault on demand.

export const HELPERS = () => {
  const norm = (s) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  const SKIP_TAG = /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|OPTION|SELECT|TEXTAREA)$/;
  const rendered = (el) => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  // The visually-hidden idioms (sr-only): a 1px clipped box, clip: rect(0,0,0,0), clip-path: inset(50%).
  const clipped = (el, cs) => {
    const r = el.getBoundingClientRect();
    return (
      (el.getClientRects().length > 0 && (r.width <= 1 || r.height <= 1) && cs.overflow !== 'visible') ||
      /rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)/.test(cs.clip) ||
      /inset\(\s*50%\s*\)/.test(cs.clipPath)
    );
  };

  // A short, valid selector. Tokens are restricted to [A-Za-z0-9_-] so the result carries no markup-hostile
  // character and can sit in a code span or a workflow command. A form control also gets [name=…].
  const tok = (s) => (/^[A-Za-z_][\w-]*$/.test(s) ? s : '');
  const one = (n) => {
    const tag = n.tagName.toLowerCase();
    const id = tok(n.id);
    if (id && document.querySelectorAll('#' + id).length === 1) return { s: `${tag}#${id}`, anchor: true };
    const cls = [...n.classList].filter((c) => tok(c)).slice(0, 2).map((c) => '.' + c).join('');
    let s = tag + cls;
    const nm = /^(input|select|textarea|button)$/.test(tag) ? tok(n.getAttribute('name') || '') : '';
    if (nm) s += `[name=${nm}]`;
    const p = n.parentElement;
    if (p) {
      // a named control is told apart by its name; only a same-named sibling (a radio group) needs the index
      const same = [...p.children].filter((c) => c.tagName === n.tagName && (!nm || c.getAttribute('name') === n.getAttribute('name')));
      if (same.length > 1) s += `:nth-of-type(${[...p.children].filter((c) => c.tagName === n.tagName).indexOf(n) + 1})`;
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

  // `visible` = what a sighted user reads (no sr-only, no display:none); otherwise what the accessible-name
  // algorithm reads (sr-only included, display:none / visibility:hidden not).
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
      if (![...rg.getClientRects()].some((r) => r.width > 1 && r.height > 1)) return false;
    }
    return true;
  };
  const textOf = (root, visible) =>
    norm(textNodes(root).filter((n) => nodeOk(n, root, visible)).map((n) => n.nodeValue).join(' '));

  return { norm, rendered, clipped, tok, selectorOf, textOf };
};

// Run `fn(H, args)` in the page. `fn` may be async. `args` must be JSON-serialisable.
export const inPage = (page, fn, args) =>
  page.evaluate(`/*vh-ux*/(${fn.toString()})((${HELPERS.toString()})(), ${JSON.stringify(args === undefined ? null : args)})`);
