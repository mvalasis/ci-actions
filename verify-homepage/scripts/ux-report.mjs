// verify-homepage — report plumbing shared by every opt-in check family (affordance v1.26.0; focus,
// forms, target, motion, consent v1.27.0). render-check passes its own `safe`.

// One group = one cause. `:nth-of-type(n)` is dropped from the key so fifty identical cards read as one
// finding with a count instead of fifty lines. `order` lists the family's rules, behavioural first: the
// ones a caller cannot see by looking, and the ones a capped annotation list must not cut off.
export function groupFindings(perViewport, order = []) {
  const groups = new Map();
  for (const { viewport, findings } of perViewport) {
    for (const f of findings) {
      const key = `${f.rule}|${f.sel.replace(/:nth-of-type\(\d+\)/g, '')}|${f.detail.replace(/\d+/g, 'N')}`;
      let g = groups.get(key);
      if (!g) { g = { ...f, count: 0, seen: new Set(), viewports: new Set() }; groups.set(key, g); }
      g.viewports.add(viewport);
      if (!g.seen.has(f.sel)) { g.seen.add(f.sel); g.count++; }
    }
  }
  const rank = (r) => { const i = order.indexOf(r); return i < 0 ? order.length : i; };
  return [...groups.values()].sort((a, b) => rank(a.rule) - rank(b.rule));
}

// Selectors are built from [A-Za-z0-9_-] tokens, `#`, `.`, `:`, `(`, `)`, `>`, `[name=…]` and spaces only.
const SEL_SAFE = (s) => String(s).replace(/[^\w\-#.:()>[\]= ]/g, '').slice(0, 160);

export function formatGroup(g, safe, allViewports) {
  const vps = g.viewports.size >= allViewports ? 'all viewports' : [...g.viewports].join(', ');
  const times = g.count > 1 ? ` ×${g.count}` : '';
  const text = g.text ? ` “${safe(g.text, 60)}”` : '';
  return `\`${SEL_SAFE(g.sel)}\`${times}${text} — ${safe(g.detail, 200)} _(${safe(vps, 60)})_`;
}

// `::warning`/`::error` workflow commands, one per group, capped at what GitHub keeps per step PER LEVEL.
// `items`: [{ family, level, url, g }] in report order. Only identifiers go in: family, rule, selector
// (restricted in-page to [\w#.:()>[]= -] tokens) and the page URL — never a label's or a button's text,
// which is page-controlled. The location is IN the message because the file=/line= properties never reach
// the log line (ci-workflows.md).
const escapeData = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeProp = (s) => escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
export function annotationLines(items, cap = 10) {
  const lines = [];
  for (const level of ['error', 'warning']) {
    const all = items.filter((i) => i.level === level);
    for (const { family, url, g } of all.slice(0, cap)) {
      lines.push(
        `::${level} title=${escapeProp(`verify-homepage ${family} ${g.rule}`)}::${escapeData(`${g.rule} at ${String(url).slice(0, 200)} — ${SEL_SAFE(g.sel)}${g.count > 1 ? ` (+${g.count - 1} like it)` : ''}`)}`
      );
    }
    if (all.length > cap) lines.push(`verify-homepage: ${all.length - cap} more finding group(s) not annotated (${level}; GitHub keeps ${cap} per step per level) — the report above lists them all.`);
  }
  return lines;
}
