// verify-homepage render-check — the STRUCTURE + CROSS-VIEWPORT RENDER gate.
//
// For each target URL, in a real headless Chromium, across a viewport matrix
// (desktop / laptop / mobile widths), assert:
//   (render) no horizontal overflow, no collapsed (0-height) key landmark, no
//            overlap between in-flow landmarks  — the broken-layout smoke.
//   (nav)    the primary-nav items present, in the declared order, matching a
//            tiny per-repo inventory (verify-nav.json) — catches a silently
//            wrong / missing / reordered menu.
//
// Mechanical structure/render = BLOCK (when FAIL_ON_STRUCTURE=true). Visual
// taste stays advisory (the design-critic subagent), never gated here.
//
// Why a browser (not curl/cheerio like seo-aeo): overflow / collapse / overlap
// are RENDERED-layout facts — they only exist after CSS + the responsive
// breakpoints apply at a given width. This is the a11y-audit tier (headless
// Chromium), run on the WEEKLY schedule + at cutover, never per-push (cost).
//
// Spec: ~/.claude/skills/verify-homepage/SKILL.md §8 + ~/.claude/DISCIPLINES.md
// (UI/UX — structure + cross-viewport render).
import fs from 'node:fs';
import { chromium } from 'playwright';

const env = process.env;
const URLS = (env.URLS || '').split(/\s+/).map((s) => s.trim()).filter(Boolean);
const CHECKS = new Set((env.CHECKS || 'render,nav').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean));
const FAIL = env.FAIL_ON_STRUCTURE !== 'false'; // default true → BLOCK
const MAX_URLS = Math.max(1, parseInt(env.MAX_URLS || '12', 10) || 12);
const VERIFY_TOKEN = env.VERIFY_TOKEN || '';
const WAIT_MS = Math.max(0, parseInt(env.WAIT_MS || '1200', 10) || 1200);
const OVERFLOW_TOL = Math.max(0, parseInt(env.OVERFLOW_TOL || '2', 10) || 2);
const OVERLAP_TOL = Math.max(0, parseInt(env.OVERLAP_TOL || '4', 10) || 4);
const NAV_FILE = env.NAV_FILE || '';
const VIEWPORTS_RAW = env.VIEWPORTS || 'desktop:1920x1080,laptop:1440x900,iphone:393x852,android:384x854';

const DESKTOP_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const MOBILE_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const out = [];
const note = (s = '') => out.push(s);
// Job-log output goes through fs.writeSync, never console.log/console.error:
// process.stdout/stderr writes are ASYNC on macOS pipes (synchronous on
// Linux/Windows), and every terminal path here is a bare process.exit(), which
// does not drain a pending async write. CI runs on Linux so it would be safe
// there, but neither the report nor the no-URLs diagnostic may be the thing
// that silently goes missing on a local mac run. (Same fix, same reason as
// test-suite/scripts/run.mjs v1.7.0.)
const say = (s) => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };
const sayErr = (s) => { try { fs.writeSync(2, `${s}\n`); } catch { console.error(s); } };
// Neutralize page-controlled strings before they reach the markdown summary —
// a hostile nav label / class can't forge verdict lines, autolink, or inject a
// beacon. (The authoritative verdict + exit code derive from rows[].fail, never
// from parsing this text — this is defence in depth for the human-readable table.)
const safe = (s, max = 80) =>
  String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').replace(/[`|<>[\]*_~#]/g, '').slice(0, max);

// ---- viewports ----
function parseViewports(raw) {
  return raw
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((tok) => {
      let name = '';
      let dims = tok;
      if (tok.includes(':')) [name, dims] = tok.split(':');
      const [w, h] = dims.split('x').map((n) => parseInt(n, 10));
      const width = w || 1280;
      const mobile = width <= 600;
      return { name: name || `${width}w`, width, height: h || (mobile ? 800 : 1080), mobile };
    });
}
const VIEWPORTS = parseViewports(VIEWPORTS_RAW);

// ---- token scoping (mirror seo-aeo: token + LiteSpeed cookie go ONLY to the
//      target host + its www/apex variants, never to a CDN/3rd-party subresource) ----
const ALLOWED_HOSTS = new Set();
for (const u of URLS) {
  try {
    const h = new URL(u).host;
    const apex = h.replace(/^www\./, '');
    [h, apex, 'www.' + apex].forEach((x) => ALLOWED_HOSTS.add(x));
  } catch {
    /* ignore */
  }
}

// ---- nav inventory ----
let navSpec = null;
let navSkipReason = '';
// Read the nav file whenever it exists — NOT only when `nav` is in `checks`.
// It carries two independent things: the nav inventory (used by the nav check)
// and `landmarks` (used by the render check). Gating the read on the nav check
// meant `checks: render` silently fell back to the DEFAULT `header/main/footer`
// selectors, measuring different elements than the caller's verify-nav.json
// declares — the same failure mode as an ambiguous selector, one level up. No
// fleet caller sets `checks:` today (all take the `render,nav` default), so this
// disarms a trap rather than changing any live verdict.
if (NAV_FILE && fs.existsSync(NAV_FILE)) {
  try {
    navSpec = JSON.parse(fs.readFileSync(NAV_FILE, 'utf8'));
  } catch (e) {
    navSkipReason = `nav-file unparseable (${e.message})`;
  }
} else {
  navSkipReason = NAV_FILE ? `nav-file not found at ${NAV_FILE}` : 'no nav-file configured';
}
const LANDMARKS =
  (navSpec && Array.isArray(navSpec.landmarks) && navSpec.landmarks.length && navSpec.landmarks) ||
  ['header', 'main', 'footer'];

// href compare: tolerate trailing slash, absolute-vs-relative, query/hash.
function pathOf(href, base) {
  // Normalize percent-octet case so an already-encoded href (e.g. WP's
  // lowercase `/%cf%87…/`) compares equal whether the DOM or the inventory
  // emits it upper- or lower-case — the WHATWG URL API preserves existing
  // encoding case, only uppercasing when it encodes raw UTF-8 itself.
  const norm = (p) => p.replace(/%[0-9a-fA-F]{2}/g, (m) => m.toUpperCase());
  try {
    const u = new URL(href, base || 'https://x.invalid');
    let p = u.pathname.replace(/\/+$/, '');
    return norm(p || '/');
  } catch {
    return norm(String(href || '').split(/[?#]/)[0].replace(/\/+$/, '') || '/');
  }
}
const labelEq = (a, b) => a.replace(/\s+/g, ' ').trim() === b.replace(/\s+/g, ' ').trim();

let overallFail = false;
const rows = [];

const browser = await chromium.launch({ args: ['--no-sandbox'] });

async function newContext(vp) {
  const ctx = await browser.newContext({
    viewport: { width: vp.width, height: vp.height },
    isMobile: vp.mobile,
    hasTouch: vp.mobile,
    deviceScaleFactor: vp.mobile ? 3 : 1,
    userAgent: vp.mobile ? MOBILE_UA : DESKTOP_UA,
  });
  if (VERIFY_TOKEN) {
    await ctx.route('**', async (route) => {
      let host = '';
      try {
        host = new URL(route.request().url()).host;
      } catch {
        /* none */
      }
      if (ALLOWED_HOSTS.has(host)) {
        const h = { ...route.request().headers() };
        h['x-verify-source'] = VERIFY_TOKEN;
        h.cookie = h.cookie ? `${h.cookie}; _lscache_vary=1` : '_lscache_vary=1';
        return route.continue({ headers: h });
      }
      return route.continue();
    });
  }
  return ctx;
}

async function gotoSettle(page, url) {
  await page.goto(url, { waitUntil: 'load', timeout: 35000 });
  await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
  if (WAIT_MS) await page.waitForTimeout(WAIT_MS);
}

// In-page measurement: overflow + landmark geometry. Pure DOM, returns plain data.
const MEASURE = (args) => {
  const { tol, landmarks } = args;
  const docEl = document.documentElement;
  const vw = docEl.clientWidth; // excludes scrollbar — the canonical width
  const scrollW = Math.max(docEl.scrollWidth, document.body ? document.body.scrollWidth : 0);
  const res = { vw, scrollW, overflow: scrollW - vw > tol, offenders: [], landmarks: [] };
  if (res.overflow) {
    const all = document.body ? document.body.querySelectorAll('*') : [];
    for (const el of all) {
      const st = getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden') continue;
      // Off-canvas drawers (fixed/absolute, slid off via transform) are not
      // user-visible overflow — skip them as offenders + as inert subtrees.
      if (el.closest('[inert],[aria-hidden="true"]')) continue;
      if (st.position === 'fixed' || st.position === 'absolute') continue;
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.right > vw + tol && r.left < vw) {
        res.offenders.push({
          tag: el.tagName.toLowerCase(),
          cls: (el.className && el.className.toString ? el.className.toString() : '').slice(0, 36),
          right: Math.round(r.right),
        });
        if (res.offenders.length >= 8) break;
      }
    }
  }
  // A landmark selector resolves the way `document.querySelector` does — FIRST
  // MATCH IN DOCUMENT ORDER — so an unscoped selector can silently measure
  // something that is not the landmark at all: a drawer's chrome `<footer>`, a
  // `<blockquote><footer>` citation, an `<article><header>`. Record WHICH element
  // was resolved, how many others matched, and the two containers that explain
  // a wrong resolution, so the report can name the element instead of only the
  // selector. All report-only — none of these fields reaches a verdict.
  //
  // Identifiers are rendered `‹tag id="x" class="y"›`, NOT `<tag …>`: the
  // reporter's safe() strips `<`, `>` and `#` (page-controlled text must not be
  // able to inject HTML into the markdown step summary), and HTML-entity
  // escaping would leave `&lt;footer&gt;` litter in the job-log mirror — which is
  // the sink you actually read this in. Do not "restore" angle brackets.
  const ident = (n) => {
    if (!n || !n.tagName) return '';
    const tag = n.tagName.toLowerCase();
    const id = n.id ? ` id="${String(n.id).slice(0, 40)}"` : '';
    const raw = (n.getAttribute && n.getAttribute('class')) || '';
    const cls = raw.replace(/\s+/g, ' ').trim().slice(0, 40);
    return `‹${tag}${id}${cls ? ` class="${cls}"` : ''}›`;
  };
  // The nearest display:none ancestor. THE single most useful fact about a
  // 0-height landmark: an element inside a display:none subtree keeps its OWN
  // computed display (`block`) while its rect collapses to 0×0, so it trips the
  // collapse test with nothing in the message pointing at the real cause.
  // (lampakia 2026-07-01→07-30: a `lg:hidden` drawer wrapper at ≥1024px, one
  // month of "collapsed landmark footer" that was never the site footer.)
  const hiddenAncestor = (n) => {
    for (let p = n.parentElement; p; p = p.parentElement) {
      if (getComputedStyle(p).display === 'none') return p;
    }
    return null;
  };
  // Containers whose descendants are chrome or content, never page structure —
  // if the "landmark" sits inside one of these, the selector resolved wrong.
  const WRAP_SEL =
    'aside,dialog,[role="dialog"],[aria-modal="true"],[inert],[aria-hidden="true"],blockquote,figure,article,section';
  for (const sel of landmarks) {
    let els = [];
    try {
      // querySelectorAll()[0] === querySelector(): same element, same document
      // order — the resolution is unchanged, only now we can see the runners-up.
      els = Array.from(document.querySelectorAll(sel));
    } catch {
      /* bad selector */
    }
    const el = els[0] || null;
    if (!el) {
      res.landmarks.push({ sel, present: false, matchCount: 0 });
      continue;
    }
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    const hid = hiddenAncestor(el);
    // Start at parentElement so a landmark that IS an `<aside>`/`<section>`
    // doesn't report itself as its own wrapper.
    const wrapEl = el.parentElement ? el.parentElement.closest(WRAP_SEL) : null;
    // The runner-up that is probably the element the author meant: the first
    // other match that actually renders. Turns "the selector is ambiguous" into
    // "here is the one you wanted".
    let alt = null;
    for (let k = 1; k < els.length && k < 12; k++) {
      const rk = els[k].getBoundingClientRect();
      if (rk.height > 0 && rk.width > 0) {
        alt = { n: k + 1, ident: ident(els[k]), h: Math.round(rk.height) };
        break;
      }
    }
    res.landmarks.push({
      sel,
      present: true,
      matchCount: els.length,
      ident: ident(el),
      hiddenAnc: hid ? ident(hid) : '',
      // Suppress the wrapper when it IS the display:none ancestor — one clause
      // naming that element is the useful message, two is noise.
      wrap: wrapEl && wrapEl !== hid ? ident(wrapEl) : '',
      alt,
      h: Math.round(r.height),
      w: Math.round(r.width),
      top: Math.round(r.top),
      left: Math.round(r.left),
      right: Math.round(r.right),
      bottom: Math.round(r.bottom),
      pos: st.position,
      display: st.display,
    });
  }
  return res;
};

// ---- landmark identification (report-only) ----
// A landmark verdict that names only the SELECTOR is unactionable when the
// selector is ambiguous: `collapsed landmark footer (0-height)` cost a month on
// lampakia because nothing in it said the flagged element was a mobile drawer's
// chrome `<footer>` (first in document order), not the site footer. These three
// clauses turn the same finding into a two-minute fix. Composition order is
// fixed: WHAT resolved → WHY it measured that way → WHAT ELSE matched.

// Does this landmark's resolution need explaining? True when the selector is
// ambiguous, or when the resolved element sits inside a container that means it
// is not the landmark (a drawer, a blockquote, a display:none subtree).
const needsIdent = (l) => !!(l && l.present && (l.matchCount > 1 || l.wrap || l.hiddenAnc));

// `resolved to ‹footer class="border-t px-5"›, whose ancestor ‹aside
//  id="mobile-menu"› is display:none — that ancestor is the cause, not this element`
function resolvedClause(l) {
  if (!l || !l.ident) return '';
  let s = `resolved to ${safe(l.ident, 72)}`;
  if (l.hiddenAnc) s += `, whose ancestor ${safe(l.hiddenAnc, 56)} is display:none — that ancestor is the cause, not this element`;
  else if (l.wrap) s += ` inside ${safe(l.wrap, 56)}`;
  return s;
}

// `3 elements match "footer" (first match in document order wins) — match 3 of 3
//  ‹footer class="site-footer"› renders 412px tall`
//
// Ordinals are spelled "match 3 of 3", never "#3": the composed problem string
// is passed through safe() again at the note() call, which strips `#` along with
// every other markdown-hostile character — so a `#` here silently becomes a bare
// digit. Same reason the identifiers use ‹…› instead of <…>.
function ambiguityClause(l) {
  if (!l || !(l.matchCount > 1)) return '';
  let s = `${l.matchCount} elements match "${safe(l.sel, 28)}" (first match in document order wins)`;
  if (l.alt) s += ` — match ${l.alt.n} of ${l.matchCount} ${safe(l.alt.ident, 56)} renders ${l.alt.h}px tall`;
  return s;
}

// The full "which element, and why" tail for one landmark.
function identTail(l) {
  return [resolvedClause(l), ambiguityClause(l)].filter(Boolean).join('; ');
}

function overlapFailures(landmarks) {
  // Only consider in-flow (static/relative), present, sized landmarks. Fixed /
  // sticky / absolute landmarks legitimately overlay content (e.g. a fixed
  // header above the main padding-top) — never an overlap bug.
  const flow = landmarks.filter(
    (l) => l.present && l.h > 0 && l.w > 0 && (l.pos === 'static' || l.pos === 'relative')
  );
  const fails = [];
  for (let i = 0; i < flow.length; i++) {
    for (let j = i + 1; j < flow.length; j++) {
      const a = flow[i];
      const b = flow[j];
      const dx = Math.min(a.right, b.right) - Math.max(a.left, b.left);
      const dy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (dx > OVERLAP_TOL && dy > OVERLAP_TOL) {
        // Overlap needs identification MORE than collapse does, because an
        // ambiguous selector here produces a false FAIL rather than a
        // mis-attributed one: `main#main ∩ footer` reads as broken layout when
        // the truth is that `footer` resolved to a `<blockquote><footer>`
        // citation nested inside main, so of course the boxes intersect.
        // (prevedourou.gr is one populated `author` field away from exactly
        // this — landmarks ["header","main#main","footer"], gate ENFORCING.)
        // Annotate only the ambiguous side(s): two clean selectors that really
        // do overlap keep the terse original message.
        const why = [a, b]
          .filter(needsIdent)
          .map((l) => `${safe(l.sel, 28)} ${identTail(l)}`)
          .join(' · ');
        fails.push(`${safe(a.sel, 28)} ∩ ${safe(b.sel, 28)} (${dx}×${dy}px)${why ? ` — ${why}` : ''}`);
      }
    }
  }
  return fails;
}

// Ambiguous / mis-resolved landmark selectors seen anywhere in the run, deduped.
// Reported once at the end even when every check PASSED: a selector quietly
// measuring the wrong element is a latent false verdict in both directions, and
// a green run is exactly when nobody goes looking. Pass/fail is untouched.
const ambiguous = new Map();
function noteAmbiguity(url, vp, l) {
  if (!needsIdent(l)) return;
  const key = `${l.sel}|${l.ident}|${l.matchCount}|${l.hiddenAnc}|${l.wrap}`;
  if (!ambiguous.has(key)) ambiguous.set(key, { l, url, vp });
}

// ---- run ----
const targets = URLS.slice(0, MAX_URLS);
if (!targets.length) {
  sayErr('verify-homepage render-check: no URLs provided');
  process.exit(2);
}

note('## verify-homepage · structure + cross-viewport render');
note('');
note(`Viewports: ${VIEWPORTS.map((v) => `${v.name} ${v.width}×${v.height}`).join(' · ')}`);
if (CHECKS.has('nav')) note(navSpec ? `Nav inventory: \`${safe(NAV_FILE, 120)}\`` : `Nav inventory: _skipped — ${safe(navSkipReason, 120)}_`);
note('');

for (const url of targets) {
  note(`### ${safe(url, 120)}`);
  note('');

  // ---- NAV inventory (once per URL, at the first/desktop viewport; the menu
  //      source is in the DOM regardless of which breakpoint hides it) ----
  if (CHECKS.has('nav') && navSpec && navSpec.nav_selector) {
    const vp = VIEWPORTS[0];
    const ctx = await newContext(vp);
    const page = await ctx.newPage();
    let navFail = false;
    const lines = [];
    try {
      await gotoSettle(page, url);
      const actual = await page.evaluate((sel) => {
        let els = [];
        try {
          els = Array.from(document.querySelectorAll(sel));
        } catch {
          return null;
        }
        return els.map((a) => ({
          label: (a.textContent || '').replace(/\s+/g, ' ').trim(),
          href: a.getAttribute('href') || '',
        }));
      }, navSpec.nav_selector);

      const expected = Array.isArray(navSpec.items) ? navSpec.items : [];
      if (actual === null) {
        navFail = true;
        lines.push(`invalid nav_selector \`${safe(navSpec.nav_selector, 60)}\``);
      } else if (actual.length !== expected.length) {
        navFail = true;
        lines.push(
          `count ${actual.length} ≠ expected ${expected.length} — got [${actual.map((a) => safe(a.label, 24)).join(', ')}]`
        );
      } else {
        for (let i = 0; i < expected.length; i++) {
          const e = expected[i];
          const a = actual[i];
          const okLabel = labelEq(e.label, a.label);
          const okHref = pathOf(e.href, url) === pathOf(a.href, url);
          if (!okLabel || !okHref) {
            navFail = true;
            lines.push(
              `#${i + 1} expected "${safe(e.label, 24)}"→${safe(pathOf(e.href, url), 40)} got "${safe(a.label, 24)}"→${safe(pathOf(a.href, url), 40)}`
            );
          }
        }
      }
    } catch (e) {
      navFail = true;
      lines.push(`error: ${safe(e.message, 80)}`);
    } finally {
      await ctx.close();
    }
    rows.push({ url, viewport: 'nav', kind: 'nav', fail: navFail, detail: lines.join('; ') });
    if (navFail) overallFail = true;
    note(`- **nav inventory** ${navFail ? '❌' : '✅'}${navFail ? ' — ' + lines.map((l) => safe(l, 160)).join(' · ') : ` (${(navSpec.items || []).length} items in order)`}`);
  }

  // ---- RENDER matrix (per viewport) ----
  if (CHECKS.has('render')) {
    for (const vp of VIEWPORTS) {
      const ctx = await newContext(vp);
      const page = await ctx.newPage();
      const problems = [];
      try {
        await gotoSettle(page, url);
        const m = await page.evaluate(MEASURE, { tol: OVERFLOW_TOL, landmarks: LANDMARKS });
        if (m.overflow) {
          const who = m.offenders.length
            ? ' — ' + m.offenders.map((o) => `${o.tag}.${safe(o.cls, 24)}@${o.right}`).join(', ')
            : '';
          problems.push(`horizontal overflow: scrollW ${m.scrollW} > ${m.vw}${who}`);
        }
        for (const l of m.landmarks) {
          noteAmbiguity(url, vp.name, l);
          if (!l.present) {
            problems.push(`missing landmark ${safe(l.sel, 28)}`);
          } else if (l.display !== 'none' && l.display !== 'contents' && l.h <= 0) {
            // display:contents generates no box (height 0) but its children
            // render — not a collapse. (overlapFailures already skips it: its
            // 0×0 rect fails the h>0/w>0 in-flow filter.)
            const tail = identTail(l);
            problems.push(`collapsed landmark ${safe(l.sel, 28)} (0-height)${tail ? ` — ${tail}` : ''}`);
          }
        }
        for (const f of overlapFailures(m.landmarks)) problems.push(`overlap ${f}`);
      } catch (e) {
        problems.push(`load error: ${safe(e.message, 80)}`);
      } finally {
        await ctx.close();
      }
      const fail = problems.length > 0;
      if (fail) overallFail = true;
      rows.push({ url, viewport: vp.name, kind: 'render', fail, detail: problems.join('; ') });
      note(
        // 320, not the original 200: a landmark finding now carries the resolved
        // element + its wrapper + the runner-up match, and truncating that tail
        // would cut off exactly the part that makes the finding actionable.
        // Still a bounded length — safe() caps every page-derived fragment too.
        `- **${vp.name}** (${vp.width}×${vp.height}) ${fail ? '❌' : '✅'}${fail ? ' — ' + problems.map((p) => safe(p, 320)).join(' · ') : ''}`
      );
    }
  }
  note('');
}

await browser.close();

// ---- landmark-resolution advisory (report-only, printed on PASS too) ----
if (ambiguous.size) {
  const seen = [...ambiguous.values()];
  note('---');
  note('');
  note('#### ⚠️ landmark selectors that did not resolve cleanly (advisory — no verdict effect)');
  note('');
  note(
    'Landmarks resolve with `document.querySelector` — **first match in document order wins**. ' +
      'Each row below measured an element that is either one of several matches, or nested in a ' +
      'container that means it is not the landmark. That makes the geometry asserts (collapse, ' +
      'overlap) fire on — or silently pass over — the wrong box.'
  );
  note('');
  for (const { l, url, vp } of seen.slice(0, 8)) {
    const bits = [`${l.matchCount} match${l.matchCount === 1 ? '' : 'es'}`, `resolved ${safe(l.ident, 72)}`];
    if (l.hiddenAnc) bits.push(`ancestor ${safe(l.hiddenAnc, 56)} is display:none`);
    else if (l.wrap) bits.push(`inside ${safe(l.wrap, 56)}`);
    if (l.alt) bits.push(`match ${l.alt.n} of ${l.matchCount} ${safe(l.alt.ident, 56)} is ${l.alt.h}px tall`);
    note(`- \`${safe(l.sel, 40)}\` — ${bits.join(' · ')}  _(first seen: ${safe(url, 60)} @ ${safe(vp, 16)})_`);
  }
  if (seen.length > 8) note(`- …and ${seen.length - 8} more`);
  note('');
  note(
    'Fix at the source: scope the selector in `verify-nav.json` (`body > footer`, `main#main`), ' +
      'or stop using landmark elements for non-landmark chrome (drawer headers/footers, citation ' +
      '`<footer>`s). A scoped selector is precise but only asserts what it names — see ' +
      '`verify-homepage/README.md` → "Selector precision vs. catching markup regressions".'
  );
  note('');
}

// ---- verdict ----
const failed = rows.filter((r) => r.fail);
note('---');
note('');
if (failed.length === 0) {
  note(`✅ **PASS** — ${rows.length} checks across ${targets.length} page(s), ${VIEWPORTS.length} viewport(s).`);
} else {
  note(`${FAIL ? '❌ **FAIL**' : '⚠️ **WARN (report-only)**'} — ${failed.length}/${rows.length} checks broke.`);
}

try {
  fs.appendFileSync(summaryFile, out.join('\n') + '\n');
} catch {
  // Summary sink unwritable (no GITHUB_STEP_SUMMARY and /dev/stdout not
  // openable) — nothing to do here: the job-log mirror below is unconditional,
  // so the report still reaches stdout exactly once.
}
say(out.join('\n'));

if (failed.length && FAIL) process.exit(1);
process.exit(0);
