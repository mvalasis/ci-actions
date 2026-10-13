// verify-homepage — report plumbing shared by every opt-in check family (affordance v1.26.0; focus,
// forms, target, motion, consent v1.27.0) and the whole report's step-summary cut (v1.29.6). render-check
// passes its own `safe`.

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

// ---------- the step summary's cut (pure; render-check.mjs calls it, selftest.mjs covers it) ----------

// GitHub drops a step summary over 1 MiB: the upload fails with an error annotation and the run shows
// none, so until v1.29.6 the report went missing once its pages, viewports and families ran past it (six
// families at 30 finding groups a page reach it within a dozen pages). A report over SUMMARY_CAP BYTES
// keeps its fixed lines — the head, and from the first `---` on the advisory and the verdicts — and as
// many WHOLE rows as fit, the worst first: ❌ lines, the lines under a ❌ family, ⚠️ families, the lines
// under them, then the rest (✅ and what sits under it); report order within each. A row brings its
// page's heading and blank lines; a family's line ranks before the lines under it, so it is never left
// out while one of them is kept. The lines keep the report's order, and a note after the verdicts counts
// the rows left out and gives the run URL; the job log carries every line. Bytes are never fewer than
// characters, so the cap holds however GitHub counts. Under the cap the report is
// `${lines.join('\n')}\n`, byte for byte, and so is one with no row to cut. seo-aeo's and
// form-protection's checks.mjs restate the cut for their own grammar.
export const SUMMARY_CAP = 900000;
// The icon of a line at the margin: `- **desktop** (1920×1080) ❌ — …`, `- **forms** ⚠️ — …`.
const ICON = /^- \*\*.*?\*\* (?:\(\d+×\d+\) )?(❌|⚠️|✅)/;
// Each line to the cut: fixed (always kept), a page's (its `### ` heading and blank lines, kept with the
// page's first kept row) or a row (its rank; the page's lines as its parents).
function classifyReport(lines) {
  const tail = lines.includes('---') ? lines.indexOf('---') : lines.length;
  const pages = new Map();
  let page = -1, family = '';
  const cls = lines.map((line, i) => {
    if (i < tail && line.startsWith('### ')) { page = i; family = ''; pages.set(i, [i]); return {}; }
    if (page < 0 || i >= tail) return { fixed: true };
    if (!line.trim()) { pages.get(page).push(i); return {}; }
    if (line.startsWith(' ')) return { rank: { '❌': 1, '⚠️': 3 }[family] ?? 4, page };
    family = (ICON.exec(line) || [])[1] || '';
    return { rank: { '❌': 0, '⚠️': 2 }[family] ?? 4, page };
  });
  return cls.map((c) => (c.rank === undefined ? c : { rank: c.rank, parents: pages.get(c.page) }));
}
export function fitReport(lines, runUrl, cap = SUMMARY_CAP) {
  const whole = `${lines.join('\n')}\n`;
  const cls = classifyReport(lines);
  const rows = lines.map((_, i) => i).filter((i) => cls[i].rank !== undefined).sort((a, b) => cls[a].rank - cls[b].rank || a - b);
  if (!rows.length || Buffer.byteLength(whole) <= cap) return whole;
  const keep = cls.map((c) => !!c.fixed);
  const size = (i) => Buffer.byteLength(lines[i]) + 1;
  const note = (n) => `(truncated — ${n} more rows; the full report is in the run log: ${runUrl})`;
  // What the rows may take once the fixed lines, the blank line and the longest note (every row left out) are paid for.
  let room = cap - keep.reduce((s, k, i) => s + (k ? size(i) : 0), 0) - 1 - Buffer.byteLength(note(rows.length)) - 1;
  for (const i of rows) {
    const add = [...cls[i].parents.filter((p) => !keep[p]), i];
    const cost = add.reduce((s, j) => s + size(j), 0);
    if (cost > room) break;
    room -= cost;
    for (const j of add) keep[j] = true;
  }
  return `${[...lines.filter((_, i) => keep[i]), '', note(rows.filter((i) => !keep[i]).length)].join('\n')}\n`;
}
