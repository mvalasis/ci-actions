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
if (CHECKS.has('nav')) {
  if (NAV_FILE && fs.existsSync(NAV_FILE)) {
    try {
      navSpec = JSON.parse(fs.readFileSync(NAV_FILE, 'utf8'));
    } catch (e) {
      navSkipReason = `nav-file unparseable (${e.message})`;
    }
  } else {
    navSkipReason = NAV_FILE ? `nav-file not found at ${NAV_FILE}` : 'no nav-file configured';
  }
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
  for (const sel of landmarks) {
    let el = null;
    try {
      el = document.querySelector(sel);
    } catch {
      /* bad selector */
    }
    if (!el) {
      res.landmarks.push({ sel, present: false });
      continue;
    }
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    res.landmarks.push({
      sel,
      present: true,
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
        fails.push(`${safe(a.sel, 28)} ∩ ${safe(b.sel, 28)} (${dx}×${dy}px)`);
      }
    }
  }
  return fails;
}

// ---- run ----
const targets = URLS.slice(0, MAX_URLS);
if (!targets.length) {
  console.error('verify-homepage render-check: no URLs provided');
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
          if (!l.present) {
            problems.push(`missing landmark ${safe(l.sel, 28)}`);
          } else if (l.display !== 'none' && l.display !== 'contents' && l.h <= 0) {
            // display:contents generates no box (height 0) but its children
            // render — not a collapse. (overlapFailures already skips it: its
            // 0×0 rect fails the h>0/w>0 in-flow filter.)
            problems.push(`collapsed landmark ${safe(l.sel, 28)} (0-height)`);
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
        `- **${vp.name}** (${vp.width}×${vp.height}) ${fail ? '❌' : '✅'}${fail ? ' — ' + problems.map((p) => safe(p, 200)).join(' · ') : ''}`
      );
    }
  }
  note('');
}

await browser.close();

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
  console.log(out.join('\n'));
}
console.log(out.join('\n'));

if (failed.length && FAIL) process.exit(1);
process.exit(0);
