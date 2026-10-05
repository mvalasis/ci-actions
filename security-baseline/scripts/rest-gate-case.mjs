// rest-gate-case — a WordPress REST gate that a re-cased route walks past. PURE: no I/O, no process
// exit; scan.mjs finds the files (git grep) and reads them, this module parses and grades them.
//
// THE DEFECT CLASS (CWE-178): WordPress core matches a request to its route CASE-INSENSITIVELY.
// WP_REST_Server::match_request_to_handler() first narrows the routes by namespace with a
// case-sensitive str_starts_with(), falls back to ALL routes when no namespace matches, then runs
// preg_match('@^' . $route . '$@i', $path). So /wp-json/My-Plugin/v1/x and ?rest_route=/MY-PLUGIN/v1/x
// both reach the handler registered as my-plugin/v1/x. A plugin that guards a namespace in a
// rest_pre_dispatch (or rest_request_before_callbacks / rest_authentication_errors) filter by testing
// the route case-sensitively sees "not our namespace" and lets the request through to that handler.
// Shipped twice in this fleet: a CF7 proxy gate, then a second plugin's namespace gate (2026-10).
//
// THE RULE: inside a function hooked (add_filter / add_action, or a WPPB-style ->add_filter) to one
// of HOOKS, a case-sensitive comparison of a route-derived string — $x->get_route(),
// $_SERVER['REQUEST_URI'] / ['PATH_INFO'], anything subscripted or fetched by 'rest_route', and any
// variable assigned from one — against anything that may hold letters: ===, ==, !==, !=, <>,
// str_starts_with / str_ends_with / str_contains, strpos / strrpos / strstr / strrchr, strcmp /
// strncmp, substr_compare without its case-insensitive flag, in_array / array_search /
// array_key_exists, preg_match(_all) without the i modifier, switch / match on the route. A value
// passed through strtolower / mb_strtolower (or another case-folding call in FOLD) is normalized; a
// case-insensitive comparator (stripos, stristr, strcasecmp, str_istarts_with, preg /i) is not a sink.
// One level of helper is followed: a function the gate calls is graded too, its parameters carrying
// the call's arguments.
//
// FALSE-POSITIVE DISCIPLINE: a comparison against a value with no letters ('/', '', 0, false,
// rest_get_url_prefix(), the literal wp-json — core's rewrite matches that prefix case-sensitively) is
// not a namespace test. A comparison whose MATCH leads to an exemption (`if (match) return $result;`)
// or whose MISMATCH leads to a denial (`if (!match) return new WP_Error(...)`) fails CLOSED on a
// re-cased route — a re-cased request is refused, never let through — so it is not reported. Any
// shape whose direction cannot be read (a ternary, an assignment, a nested call) is reported.
// Waive one with `// lint-allow-wp-rest-gate-case: <reason>` on the flagged line or the line above;
// a reason is required, as for this gate's other pragmas.
//
// KNOWN LIMITS, stated rather than papered over: a callback held in a variable, a hook name held in
// one, or a named-argument registration; a route kept in an object property ($this->route) or an array
// element ($ctx['route']); a helper more than one call deep, one called on another object
// ($this->router->is_ours()), or one whose name more than three functions share; a route test inside
// a permission_callback (per-route already, so it needs none — but one that tests the route there is
// bypassable the same way and is not seen); isset($map[$route]) and $map[$route] ?? …; $wp->request.
// A dynamic regex pattern, a case-insensitive flag held in a variable, and a case-folding wrapper
// outside FOLD are graded as case-sensitive. A route test in an unbalanced file is graded as far as its
// brackets pair. REQUEST_URI has bypasses of its own that lower-casing does not close (the
// ?rest_route= form never contains /wp-json/): the message says lower-case, the README says prefer
// $request->get_route() or a permission_callback.

export const CHECK_ID = 'wp-rest-gate-case';
export const HOOKS = ['rest_pre_dispatch', 'rest_request_before_callbacks', 'rest_authentication_errors'];
const HOOK_SET = new Set(HOOKS);
// `git grep -E` pattern scan.mjs uses to find the files that register one of HOOKS.
export const HOOK_GREP = `(${HOOKS.join('|')})`;

// ---------- which files are graded ----------
// Third-party code (WP core, Composer, WooCommerce — the same set the WP/PHP rule pack excludes),
// and the test and fixture corpora that must spell the banned form to test it.
const SKIP_PATH = [
  /(^|\/)(node_modules|vendor|wp-admin|wp-includes|bower_components|woocommerce)\//,
  /(^|\/)tests?\//, /(^|\/)selftest[^/]*$/, /(^|\/)selftest\//, /(^|\/)(fixtures?|__fixtures__)\//,
  /(^|\/)[^/]*(Test|[-_]test)\.php$/, /(^|\/)test-[^/]*\.php$/,
];
export const restGateCandidate = (f) => /\.php$/i.test(String(f)) && !SKIP_PATH.some((re) => re.test(String(f)));

// ---------- tokenizer ----------
// Tokens: { t, v, o } — t is 'v' variable, 'i' identifier/keyword (a leading `\` and namespace path
// kept), 's' string literal (v is its value; `interp` when a double-quoted/heredoc string
// interpolates), 'n' number, 'o' multi-character operator, 'p' single character. Comments and the
// inline HTML outside <?php … ?> are dropped; `?>` reads as `;`.
const OPS = ['<=>', '===', '!==', '**=', '...', '<<=', '>>=', '??=', '?->', '==', '!=', '<>', '<=', '>=', '&&', '||', '??', '->', '=>', '::', '++', '--', '+=', '-=', '*=', '/=', '.=', '%=', '&=', '|=', '^=', '<<', '>>', '**'];
const WORD0 = /[A-Za-z_\u0080-￿\\]/;
const WORD = /[A-Za-z0-9_\u0080-￿\\]/;
const DQ_ESC = { n: '\n', t: '\t', r: '\r', v: '\v', f: '\f', e: '\x1b', 0: '\0', '"': '"', '\\': '\\', $: '$', '`': '`' };

export function tokenize(src) {
  const s = String(src); const n = s.length; const toks = [];
  let i = 0; let php = false;
  while (i < n) {
    if (!php) {
      const j = s.indexOf('<?', i);
      if (j < 0) break;
      i = s.startsWith('<?php', j) ? j + 5 : s.startsWith('<?=', j) ? j + 3 : j + 2;
      php = true; continue;
    }
    const c = s[i], d = s[i + 1] || '';
    if (c === '?' && d === '>') { toks.push({ t: 'p', v: ';', o: i }); i += 2; php = false; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if ((c === '/' && d === '/') || (c === '#' && d !== '[')) {
      while (i < n && s[i] !== '\n' && !(s[i] === '?' && s[i + 1] === '>')) i++;
      continue;
    }
    if (c === '/' && d === '*') { const j = s.indexOf('*/', i + 2); i = j < 0 ? n : j + 2; continue; }
    if (c === '#') { // a PHP 8 attribute, #[...]: no route logic lives in one
      let depth = 0;
      for (; i < n; i++) {
        if (s[i] === "'" || s[i] === '"') { const q = s[i]; for (i++; i < n && s[i] !== q; i++) if (s[i] === '\\') i++; continue; }
        if (s[i] === '[') depth++; else if (s[i] === ']' && --depth === 0) { i++; break; }
      }
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      let j = i + 1, v = '', interp = false;
      while (j < n && s[j] !== c) {
        if (s[j] === '\\' && j + 1 < n) {
          const e = s[j + 1];
          v += c === "'" ? (e === "'" || e === '\\' ? e : `\\${e}`) : (DQ_ESC[e] ?? `\\${e}`);
          j += 2; continue;
        }
        if (c !== "'" && ((s[j] === '$' && /[A-Za-z_{]/.test(s[j + 1] || '')) || (s[j] === '{' && s[j + 1] === '$'))) interp = true;
        v += s[j]; j++;
      }
      toks.push({ t: 's', v, o: i, interp });
      i = j + 1; continue;
    }
    if (c === '<' && s.startsWith('<<<', i)) {
      const m = /^<<<[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1\r?\n/.exec(s.slice(i, i + 200));
      if (m) {
        const body = i + m[0].length;
        const re = new RegExp(`\\n[ \\t]*${m[2]}(?![A-Za-z0-9_])`, 'g');
        re.lastIndex = body - 1;
        const e = re.exec(s);
        const v = s.slice(body, e ? e.index : n);
        toks.push({ t: 's', v, o: i, interp: m[1] !== "'" && /\$[A-Za-z_{]|\{\$/.test(v) });
        i = e ? e.index + e[0].length : n; continue;
      }
    }
    if (c === '$' && /[A-Za-z_\u0080-￿]/.test(d)) {
      let j = i + 1; while (j < n && /[A-Za-z0-9_\u0080-￿]/.test(s[j])) j++;
      toks.push({ t: 'v', v: s.slice(i, j), o: i }); i = j; continue;
    }
    if (WORD0.test(c)) {
      let j = i; while (j < n && WORD.test(s[j])) j++;
      toks.push({ t: 'i', v: s.slice(i, j), o: i }); i = j; continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i; while (j < n && /[0-9A-Za-z_.]/.test(s[j]) && !(s[j] === '.' && !/[0-9]/.test(s[j + 1] || ''))) j++;
      toks.push({ t: 'n', v: s.slice(i, j), o: i }); i = j; continue;
    }
    const op = OPS.find((x) => s.startsWith(x, i));
    if (op) { toks.push({ t: 'o', v: op, o: i }); i += op.length; continue; }
    toks.push({ t: 'p', v: c, o: i }); i++;
  }
  return toks;
}

// Matching bracket for every (, [, { and back. An unbalanced file leaves gaps. Brackets nested deeper
// than MAX_DEPTH throw (the file is reported unparsed), so every walk up the nesting — a closer's search
// for its opener included — is bounded, and 20k `(` then 20k `]` is not quadratic. No PHP anyone writes
// nests 256 deep.
const MAX_DEPTH = 256;
function brackets(toks) {
  const M = new Array(toks.length).fill(null); const st = [];
  const close = { ')': '(', ']': '[', '}': '{' };
  toks.forEach((t, k) => {
    if (t.t !== 'p') return;
    if (t.v === '(' || t.v === '[' || t.v === '{') { st.push(k); if (st.length > MAX_DEPTH) throw new Error(`brackets nested over ${MAX_DEPTH} deep`); }
    else if (close[t.v]) {
      for (let x = st.length - 1; x >= 0; x--) {
        if (toks[st[x]].v === close[t.v]) { M[st[x]] = k; M[k] = st[x]; st.length = x; break; }
      }
    }
  });
  return M;
}

const low = (t) => (t && t.t === 'i' ? t.v.toLowerCase() : '');
const is = (t, v) => !!t && (t.t === 'p' || t.t === 'o') && t.v === v;
const base = (name) => String(name).split('\\').pop().toLowerCase();
const lastSeg = (s) => String(s).split('::').pop().split('\\').pop();

// End (exclusive) of the expression starting at k: the first depth-0 `,` `;` or unmatched closer.
function exprEnd(toks, M, k, stop = toks.length) {
  for (; k < stop; k++) {
    const t = toks[k];
    if (t.t === 'p' && (t.v === '(' || t.v === '[' || t.v === '{')) { if (M[k] == null) return k; k = M[k]; continue; }
    if (t.t === 'p' && (t.v === ',' || t.v === ';' || t.v === ')' || t.v === ']' || t.v === '}')) return k;
  }
  return stop;
}
// The depth-0 argument ranges [a, b) inside the bracket opened at `open`.
function splitArgs(toks, M, open) {
  const end = M[open]; const out = [];
  if (end == null) return out;
  let a = open + 1;
  while (a < end) { const b = exprEnd(toks, M, a, end); if (b > a) out.push([a, b]); a = b + 1; }
  return out;
}

// ---------- functions, closures, hook registrations ----------
const NOT_A_CALL = new Set(['if', 'elseif', 'while', 'for', 'foreach', 'switch', 'match', 'return', 'and', 'or', 'xor', 'echo', 'print', 'fn', 'function', 'use', 'catch', 'declare', 'array', 'list', 'isset', 'empty', 'unset', 'exit', 'die', 'new', 'clone', 'include', 'require', 'include_once', 'require_once']);
const CASTS = new Set(['string', 'int', 'integer', 'bool', 'boolean', 'float', 'double', 'array', 'object']);

function paramNames(toks, M, open) {
  return splitArgs(toks, M, open).map(([a, b]) => { for (let k = a; k < b; k++) if (toks[k].t === 'v') return toks[k].v; return ''; });
}

function functions(toks, M) {
  const out = [];
  for (let k = 0; k < toks.length; k++) {
    const kw = low(toks[k]);
    if (kw !== 'function' && kw !== 'fn') continue;
    if (low(toks[k - 1]) === 'use' || is(toks[k - 1], '->') || is(toks[k - 1], '::')) continue;
    let j = k + 1;
    if (is(toks[j], '&')) j++;
    let name = null;
    if (kw === 'function' && toks[j] && toks[j].t === 'i') { name = toks[j].v; j++; }
    if (!is(toks[j], '(') || M[j] == null) continue;
    const params = paramNames(toks, M, j);
    j = M[j] + 1;
    if (kw === 'fn') {
      while (j < toks.length && !is(toks[j], '=>') && !is(toks[j], ';') && !is(toks[j], '{')) j++;
      if (!is(toks[j], '=>')) continue;
      out.push({ name: null, k, params, b0: j + 1, b1: exprEnd(toks, M, j + 1), arrow: true });
      continue;
    }
    while (j < toks.length && !is(toks[j], '{') && !is(toks[j], ';')) { if (is(toks[j], '(') && M[j] != null) j = M[j]; j++; }
    if (!is(toks[j], '{') || M[j] == null) continue; // abstract or interface: no body
    out.push({ name, k, params, b0: j + 1, b1: M[j], arrow: false });
  }
  return out;
}

// What a callback argument names: a closure here, or a function/method by name with a class hint
// ('self' for $this/self/static/__CLASS__, a class name, or '' for none).
function callbackOf(toks, M, [a, b], fns) {
  if (low(toks[a]) === 'static') a++;
  const kw = low(toks[a]);
  if (kw === 'function' || kw === 'fn') { const fn = fns.find((f) => f.k === a); return fn ? { kind: 'closure', fn } : { kind: 'unresolved' }; }
  if (b - a === 1 && toks[a].t === 's') {
    const v = toks[a].v; const cls = v.includes('::') ? lastSeg(v.split('::')[0]) : '';
    return { kind: 'name', name: lastSeg(v), hint: cls };
  }
  const hintOf = (x, y) => {
    if (y - x === 1 && (toks[x].t === 'v' && toks[x].v === '$this')) return 'self';
    if (y - x === 1 && low(toks[x]) === '__class__') return 'self';
    if (y - x === 1 && toks[x].t === 's') return lastSeg(toks[x].v);
    if (y - x === 3 && is(toks[x + 1], '::') && low(toks[x + 2]) === 'class') return ['self', 'static'].includes(low(toks[x])) ? 'self' : lastSeg(toks[x].v);
    return '';
  };
  if ((is(toks[a], '[') && M[a] === b - 1) || (low(toks[a]) === 'array' && is(toks[a + 1], '(') && M[a + 1] === b - 1)) {
    const els = splitArgs(toks, M, is(toks[a], '[') ? a : a + 1);
    if (els.length === 2 && els[1][1] - els[1][0] === 1 && toks[els[1][0]].t === 's') {
      let [x, y] = els[0]; if (is(toks[x], '&')) x++;
      return { kind: 'name', name: lastSeg(toks[els[1][0]].v), hint: hintOf(x, y) };
    }
  }
  // first-class callable syntax: $this->gate(...), self::gate(...), gate(...)
  if (b - a >= 4 && is(toks[b - 1], ')') && is(toks[b - 2], '...') && is(toks[b - 3], '(') && toks[b - 4].t === 'i') {
    const before = toks[b - 5];
    return { kind: 'name', name: lastSeg(toks[b - 4].v), hint: before && (is(before, '->') || is(before, '::')) ? 'self' : '' };
  }
  // __NAMESPACE__ . '\gate'
  if (toks[b - 1] && toks[b - 1].t === 's' && toks.slice(a, b).some((t) => is(t, '.'))) return { kind: 'name', name: lastSeg(toks[b - 1].v), hint: '' };
  return { kind: 'unresolved' };
}

function registrations(toks, M, fns) {
  const out = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.t !== 'i' || !['add_filter', 'add_action'].includes(base(t.v)) || !is(toks[k + 1], '(')) continue;
    const args = splitArgs(toks, M, k + 1);
    if (args.length < 2) continue;
    const [h0, h1] = args[0];
    if (h1 - h0 !== 1 || toks[h0].t !== 's' || !HOOK_SET.has(toks[h0].v)) continue;
    let cb = callbackOf(toks, M, args[1], fns);
    // A loader method (the WordPress Plugin Boilerplate): ->add_filter('hook', $component, 'method').
    const method = is(toks[k - 1], '->') || is(toks[k - 1], '::');
    if (cb.kind === 'unresolved' && method && args[2] && args[2][1] - args[2][0] === 1 && toks[args[2][0]].t === 's') {
      cb = { kind: 'name', name: lastSeg(toks[args[2][0]].v), hint: '' };
    }
    out.push({ hook: toks[h0].v, k, cb });
  }
  return out;
}

// One parsed file.
export function parsePhp(file, src) {
  const toks = tokenize(src);
  const M = brackets(toks);
  const fns = functions(toks, M);
  const nl = []; for (let i = 0; i < src.length; i++) if (src[i] === '\n') nl.push(i);
  const lineOf = (o) => { let lo = 0, hi = nl.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < o) lo = mid + 1; else hi = mid; } return lo + 1; };
  const classes = new Set();
  toks.forEach((t, k) => { if (low(t) === 'class' && toks[k + 1] && toks[k + 1].t === 'i' && !is(toks[k - 1], '::')) classes.add(toks[k + 1].v.toLowerCase()); });
  return { file, src, toks, M, fns, regs: registrations(toks, M, fns), lineOf, classes, lines: String(src).split('\n') };
}

// ---------- grading one function body ----------
// Case-folding calls: a route through one is normalized. Only TO_LOWER's are known to give lower case,
// so only they make a literal holding capitals dead code; strtoupper or mb_convert_case just fold.
const TO_LOWER = new Set(['strtolower', 'mb_strtolower', 'wc_strtolower', 'sanitize_key', 'sanitize_title', 'sanitize_title_with_dashes']);
const FOLD = new Set([...TO_LOWER, 'strtoupper', 'mb_strtoupper', 'wc_strtoupper', 'mb_convert_case']);
// A call whose result is not the route string: comparing it to a constant is not a namespace test.
const NON_STRING = new Set(['count', 'strlen', 'mb_strlen', 'substr_count', 'strpos', 'stripos', 'strrpos', 'strripos', 'mb_strpos', 'mb_stripos',
  'str_starts_with', 'str_ends_with', 'str_contains', 'str_istarts_with', 'str_iends_with', 'preg_match', 'preg_match_all', 'in_array', 'array_key_exists',
  'array_search', 'strcmp', 'strcasecmp', 'strncmp', 'strncasecmp', 'substr_compare', 'isset', 'empty', 'is_string', 'is_array', 'is_null', 'intval', 'absint',
  'boolval', 'floatval', 'is_wp_error', 'is_numeric', 'ctype_digit']);
const PAIR = new Set(['str_starts_with', 'str_ends_with', 'str_contains', 'strpos', 'strrpos', 'strstr', 'strrchr', 'strcmp', 'strncmp', 'substr_compare', 'mb_strpos', 'mb_strrpos', 'mb_strstr']);
const HAYSTACK = new Set(['in_array', 'array_search', 'array_key_exists']);
const ZERO_ON_MATCH = new Set(['strcmp', 'strncmp', 'substr_compare']);
const EQ = new Set(['===', '==', '!==', '!=', '<>']);
const SOURCE_KEYS = new Set(['REQUEST_URI', 'PATH_INFO', 'rest_route']);
const SOURCE_CALLS = new Set(['get_param', 'filter_input', 'getenv']);
const BOOL_JOIN = new Set(['&&', '||', 'and', 'or']);
const isJoin = (t) => !!t && ((t.t === 'o' && (t.v === '&&' || t.v === '||')) || (t.t === 'i' && BOOL_JOIN.has(t.v.toLowerCase())));
const letters = (s) => /[A-Za-z]/.test(String(s).replace(/wp-json/g, ''));

function grade(P, fn, { gateParams = [], seed = new Map(), helper = false, hook = '' } = {}) {
  const { toks, M } = P;
  const b0 = fn.b0, b1 = fn.b1;
  // Innermost enclosing ( or [ of each token, and the call each ( belongs to (null: grouping/cast).
  const parent = new Array(toks.length).fill(-1); const callOf = new Map(); const st = [];
  for (let k = b0; k < b1; k++) {
    parent[k] = st.length ? st[st.length - 1] : -1;
    const t = toks[k];
    if (is(t, '(') || is(t, '[')) {
      const prev = toks[k - 1];
      let name = null;
      if (is(t, '(') && prev && prev.t === 'i' && !NOT_A_CALL.has(prev.v.toLowerCase()) && !is(toks[k - 2], 'function')) name = base(prev.v);
      if (is(t, '(') && low(prev) === 'isset') name = 'isset';
      if (is(t, '(') && low(prev) === 'empty') name = 'empty';
      if (is(t, '(') && toks[k + 1] && CASTS.has(low(toks[k + 1])) && is(toks[k + 2], ')')) name = null;
      callOf.set(k, name);
      st.push(k);
    } else if ((is(t, ')') || is(t, ']')) && st.length) st.pop();
  }
  // Assignments, in order: var → [{ k, state, free }]. state: 'route' | 'lower' | 'fold' | null.
  const events = new Map();
  for (const [v, state] of seed) events.set(v, [{ k: b0 - 1, state, free: false }]);
  const stateAt = (v, k) => { const ev = events.get(v); if (!ev) return null; let s = null; for (const e of ev) if (e.k < k) s = e; return s; };
  // The outermost case-folding call around q inside [r0, …): 'lower', 'fold', or '' for none.
  const enclosingFold = (q, r0) => {
    let f = '';
    for (let p = parent[q]; p >= r0 && p >= 0; p = parent[p]) { const c = callOf.get(p) || ''; if (FOLD.has(c)) f = TO_LOWER.has(c) ? 'lower' : 'fold'; }
    return f;
  };
  const isSource = (q) => {
    const t = toks[q];
    if (t.t === 'i' && t.v.toLowerCase() === 'get_route' && (is(toks[q - 1], '->') || is(toks[q - 1], '?->')) && is(toks[q + 1], '(')) return true;
    if (t.t !== 's' || !SOURCE_KEYS.has(t.v)) return false;
    if (is(toks[q - 1], '[') && is(toks[q + 1], ']')) return true;   // $_SERVER['REQUEST_URI'], $wp->query_vars['rest_route']
    return (is(toks[q - 1], '(') || is(toks[q - 1], ',')) && SOURCE_CALLS.has(callOf.get(parent[q]) || '');
  };
  const evaluate = (r0, r1, at) => {
    let route = false, folded = '';
    for (let q = r0; q < r1; q++) {
      let s = null;
      if (isSource(q)) s = 'route';
      else if (toks[q].t === 'v' && !is(toks[q - 1], '->') && !is(toks[q - 1], '::')) { const e = stateAt(toks[q].v, at); s = e ? e.state : null; }
      if (!s) continue;
      const f = enclosingFold(q, r0) || (s === 'route' ? '' : s);
      if (!f) route = true; else folded = !folded || folded === f ? f : 'fold';
    }
    return route ? 'route' : (folded || null);
  };
  // Can this operand hold a namespace? Not when it is built only from letter-free literals, numbers,
  // true/false/null, rest_get_url_prefix() and variables assigned from such.
  const free = (r0, r1, at) => {
    for (let q = r0; q < r1; q++) {
      const t = toks[q];
      if (t.t === 's') { if (t.interp || letters(t.v)) return false; continue; }
      if (t.t === 'n' || is(t, '.') || is(t, '(') || is(t, ')') || is(t, '-')) continue;
      if (t.t === 'i' && ['true', 'false', 'null'].includes(t.v.toLowerCase())) continue;
      if (t.t === 'i' && base(t.v) === 'rest_get_url_prefix' && is(toks[q + 1], '(') && is(toks[q + 2], ')')) { q += 2; continue; }
      if (t.t === 'v') { const e = stateAt(t.v, at); if (e && e.free) continue; }
      return false;
    }
    return true;
  };
  const upperLiteral = (r0, r1) => { for (let q = r0; q < r1; q++) if (toks[q].t === 's' && /[A-Z]/.test(toks[q].v) && !enclosingFold(q, r0)) return true; return false; };
  const stringValued = (r0, r1) => {
    const t = toks[r0];
    if (t.t === 'i' && is(toks[r0 + 1], '(') && M[r0 + 1] === r1 - 1 && NON_STRING.has(base(t.v))) return false;
    if (is(t, '(') && toks[r0 + 1] && ['int', 'integer', 'bool', 'boolean', 'float', 'double'].includes(low(toks[r0 + 1])) && is(toks[r0 + 2], ')')) return false;
    if (is(t, '!')) return false;
    return true;
  };
  for (let k = b0; k < b1; k++) {
    const t = toks[k];
    const assign = (is(t, '=') || is(t, '.=') || is(t, '??=')) && toks[k - 1] && toks[k - 1].t === 'v' && !is(toks[k - 2], '->') && !is(toks[k - 2], '::') && !is(toks[k - 2], '$');
    if (assign) {
      const r1 = exprEnd(toks, M, k + 1, b1);
      // A count, a position or a bool computed from the route is not the route.
      let state = stringValued(k + 1, r1) ? evaluate(k + 1, r1, k) : null; let fr = free(k + 1, r1, k);
      if (!is(t, '=')) { const prev = stateAt(toks[k - 1].v, k); if (prev && prev.state === 'route') state = 'route'; else if (prev && prev.state && !state) state = prev.state; fr = fr && !!(prev && prev.free); }
      const list = events.get(toks[k - 1].v) || []; list.push({ k, state, free: fr }); events.set(toks[k - 1].v, list);
    }
    // [$a, $b] = … / list($a, $b) = …: every variable destructured takes the right side's state
    if (is(t, '=') && (is(toks[k - 1], ']') || (is(toks[k - 1], ')') && M[k - 1] != null && low(toks[M[k - 1] - 1]) === 'list')) && M[k - 1] != null) {
      const r1 = exprEnd(toks, M, k + 1, b1); const state = evaluate(k + 1, r1, k);
      for (let q = M[k - 1]; q < k - 1; q++) if (toks[q].t === 'v') { const list = events.get(toks[q].v) || []; list.push({ k, state, free: false }); events.set(toks[q].v, list); }
    }
    // foreach (EXPR as [$k =>] $v): $v carries EXPR's state
    if (low(t) === 'foreach' && is(toks[k + 1], '(') && M[k + 1] != null) {
      const close = M[k + 1]; let asAt = -1;
      for (let q = k + 2; q < close; q++) if (low(toks[q]) === 'as') { asAt = q; break; }
      if (asAt > 0) {
        const state = evaluate(k + 2, asAt, k); const vars = toks.slice(asAt + 1, close).filter((x) => x.t === 'v');
        const v = vars[vars.length - 1];
        if (v) { const list = events.get(v.v) || []; list.push({ k: asAt, state, free: false }); events.set(v.v, list); }
      }
    }
  }

  // ---- the direction a comparison's MATCH takes ----
  const condOf = new Map();
  for (let k = b0; k < b1; k++) {
    if ((low(toks[k]) === 'if' || low(toks[k]) === 'elseif') && is(toks[k + 1], '(') && M[k + 1] != null) condOf.set(k + 1, { close: M[k + 1], then: M[k + 1] + 1 });
  }
  const first = gateParams[0] || '';
  // What the branch an if-condition guards does first: 'exempt' (pass the request on), 'deny', or for
  // a helper 'true'/'false' (what it returns); '' when it cannot be read.
  const branch = (s) => {
    let a = s, end = exprEnd(toks, M, s, b1);
    const skipped = [];
    if (is(toks[s], '{')) {
      const close = M[s]; if (close == null) return '';
      for (a = s + 1; a < close;) {
        const w = low(toks[a]);
        if (['return', 'throw', 'exit', 'die', 'wp_die', 'wp_send_json_error', 'status_header'].includes(w)) break;
        if (is(toks[a], '{') || ['if', 'foreach', 'for', 'while', 'switch'].includes(w)) return '';
        skipped.push(a);
        a = exprEnd(toks, M, a, close) + 1;
      }
      if (a >= close) return '';
      end = exprEnd(toks, M, a, close);
    }
    const w = low(toks[a]);
    if (['throw', 'exit', 'die', 'wp_die', 'wp_send_json_error', 'status_header'].includes(w)) return 'deny';
    if (w !== 'return') return '';
    const r = toks.slice(a + 1, end);
    // `$result = new WP_Error(…); return $result;` denies; any other reassignment of what is returned
    // cannot be read, so the comparison is reported.
    if (r.length === 1 && r[0].t === 'v') {
      const set = skipped.filter((q) => toks[q].t === 'v' && toks[q].v === r[0].v && toks[q + 1] && ['=', '.=', '??=', '+='].includes(toks[q + 1].v) && !is(toks[q - 1], '->'));
      if (set.length) {
        const q = set[set.length - 1];
        return is(toks[q + 1], '=') && low(toks[q + 2]) === 'new' && toks[q + 3] && ['wp_error', 'wp_rest_response'].includes(base(toks[q + 3].v || '')) ? 'deny' : '';
      }
    }
    if (r.length === 0) return 'exempt';
    if (r.length === 1 && low(r[0]) === 'null') return 'exempt';
    if (r.length === 1 && r[0].t === 'v' && r[0].v === first && !helper) return 'exempt';
    if (r.length === 1 && low(r[0]) === 'true') return helper ? 'true' : (hook === 'rest_authentication_errors' ? 'exempt' : '');
    if (r.length === 1 && low(r[0]) === 'false') return helper ? 'false' : '';
    if (low(r[0]) === 'new' && r[1] && ['wp_error', 'wp_rest_response'].includes(base(r[1].v || ''))) return 'deny';
    if (r[0].t === 'i' && base(r[0].v) === 'rest_ensure_response') return 'deny';
    return '';
  };
  // From the atom [a, z] (inclusive) out to its if-condition: { match: does a MATCH make the condition
  // true?, kind: branch() of that if } — or null when the atom is not a plain conjunct of one.
  const direction = (a, z, pos) => {
    for (;;) {
      if (is(toks[a - 1], '!')) { pos = !pos; a--; continue; }
      const cond = condOf.get(a - 1);
      if (cond && cond.close === z + 1) return { match: pos, kind: branch(cond.then) };
      if (is(toks[a - 1], '(') && M[a - 1] === z + 1 && callOf.get(a - 1) == null) { a--; z++; continue; }
      if ((isJoin(toks[a - 1]) || is(toks[a - 1], '(')) && (isJoin(toks[z + 1]) || is(toks[z + 1], ')'))) {
        const p = parent[a];
        if (p < 0 || callOf.get(p) != null || !is(toks[p], '(')) return null;
        const c = condOf.get(p);
        if (c) return { match: pos, kind: branch(c.then) };
        a = p; z = M[p]; continue;
      }
      if (helper && low(toks[a - 1]) === 'return' && is(toks[z + 1], ';')) return { match: pos, kind: 'true' };
      return null;
    }
  };
  // A comparison of a call's result with a constant: `=== 0`, `false !==`, … → [new a, new z, pos].
  const withConstant = (a, z, fname) => {
    const constant = (t) => t && (t.t === 'n' || ['true', 'false', 'null'].includes(low(t)));
    let op = null, c = null;
    if (toks[z + 1] && EQ.has(toks[z + 1].v) && constant(toks[z + 2])) { op = toks[z + 1].v; c = toks[z + 2]; z += 2; }
    else if (toks[a - 1] && EQ.has(toks[a - 1].v) && constant(toks[a - 2])) { op = toks[a - 1].v; c = toks[a - 2]; a -= 2; }
    const zero = ZERO_ON_MATCH.has(fname);
    if (!op) return [a, z, !zero];
    const eq = op === '===' || op === '==';
    const cv = low(c) || c.v;
    const truthyConst = cv === 'true' || (c.t === 'n' && Number(c.v) !== 0);
    let pos;
    if (zero) pos = (cv === '0') === eq;
    else if (fname === 'strpos' || fname === 'strrpos' || fname === 'mb_strpos' || fname === 'mb_strrpos') pos = (cv === 'false' || cv === 'null') ? !eq : eq;
    else pos = truthyConst ? eq : !eq;
    return [a, z, pos];
  };

  const hits = [];
  const decide = (a, z, pos) => {
    const d = direction(a, z, pos);
    if (!d) return { report: true, d: null };
    if (helper) return { report: true, d };
    if (d.kind === 'exempt') return { report: !d.match, d };
    if (d.kind === 'deny') return { report: d.match, d };
    return { report: true, d };
  };
  const hit = (k, op, kind, a, z, pos) => {
    const r = decide(a, z, pos);
    if (r.report) hits.push({ k, line: P.lineOf(toks[k].o), op, kind, dir: r.d });
  };
  for (let k = b0; k < b1; k++) {
    const t = toks[k];
    // function sinks
    if (t.t === 'i' && !NOT_A_CALL.has(t.v.toLowerCase()) && is(toks[k + 1], '(') && M[k + 1] != null && !is(toks[k - 1], '->') && !is(toks[k - 1], '::') && !is(toks[k - 1], '?->') && low(toks[k - 1]) !== 'function') {
      const fname = base(t.v);
      const args = splitArgs(toks, M, k + 1);
      const close = M[k + 1];
      if ((PAIR.has(fname) || HAYSTACK.has(fname)) && args.length >= 2) {
        // substr_compare's fifth argument is case_insensitive: only a literal true or non-zero is known to turn it on
        if (fname === 'substr_compare' && args[4] && args[4][1] - args[4][0] === 1 && (low(toks[args[4][0]]) === 'true' || (toks[args[4][0]].t === 'n' && Number(toks[args[4][0]].v) !== 0))) continue;
        const s0 = evaluate(...args[0], k), s1 = evaluate(...args[1], k);
        let kind = null, other = null;
        if (s0 === 'route') { kind = 'route'; other = args[1]; }
        else if (s1 === 'route') { kind = 'route'; other = args[0]; }
        else if (s0 === 'lower' && upperLiteral(...args[1])) kind = 'dead';
        else if (s1 === 'lower' && !HAYSTACK.has(fname) && upperLiteral(...args[0])) kind = 'dead';
        if (!kind || (kind === 'route' && free(...other, k))) continue;
        const [a, z, pos] = withConstant(k, close, fname);
        hit(k, fname, kind, a, z, pos);
      } else if ((fname === 'preg_match' || fname === 'preg_match_all') && args.length >= 2) {
        if (evaluate(...args[1], k) !== 'route') continue;
        const pt = toks.slice(...args[0]);
        const lits = pt.filter((x) => x.t === 's');
        if (lits.length && pt[0].t === 's' && pt[pt.length - 1].t === 's') {
          const body = lits.map((x) => x.v).join('');
          const open = body.trim()[0] || '';
          const closeD = ({ '(': ')', '{': '}', '[': ']', '<': '>' })[open] || open;
          const last = lits[lits.length - 1].v; const mods = last.slice(last.lastIndexOf(closeD) + 1);
          const raw = body.slice(body.indexOf(open) + 1, body.lastIndexOf(closeD));
          // /i, or a leading global (?i) — a scoped (?i:…) or one mid-pattern leaves the rest case-sensitive
          if (/i/.test(mods) || /^\^?\(\?[a-zA-Z]*i[a-zA-Z-]*\)/.test(raw)) continue;
          const inner = raw.replace(/\\./g, '');
          if (lits.length === pt.filter((x) => !is(x, '.')).length && !lits.some((x) => x.interp) && !letters(inner)) continue;
        }
        const [a, z, pos] = withConstant(k, close, fname);
        hit(k, fname, 'route', a, z, pos);
      }
      continue;
    }
    // binary comparisons
    if (t.t === 'o' && EQ.has(t.v)) {
      const left = (() => { let q = k - 1; for (; q >= b0; q--) { const x = toks[q]; if (is(x, ')') || is(x, ']')) { if (M[q] == null) break; q = M[q]; continue; } if (is(x, '(') || is(x, '[') || is(x, ',') || is(x, ';') || is(x, '{') || is(x, '}') || is(x, '=') || is(x, '?') || is(x, ':') || is(x, '!') || is(x, '&') || is(x, '|') || is(x, '^') || is(x, '<') || is(x, '>') || (x.t === 'o' && !['->', '?->', '::', '**'].includes(x.v)) || isJoin(x) || ['return', 'echo', 'case', 'xor'].includes(low(x))) break; } return [q + 1, k]; })();
      const right = [k + 1, (() => { let q = k + 1; for (; q < b1; q++) { const x = toks[q]; if (is(x, '(') || is(x, '[')) { if (M[q] == null) break; q = M[q]; continue; } if (is(x, ')') || is(x, ']') || is(x, ',') || is(x, ';') || is(x, '}') || is(x, '?') || is(x, ':') || is(x, '&') || is(x, '|') || is(x, '^') || is(x, '<') || is(x, '>') || (x.t === 'o' && !['->', '?->', '::', '**'].includes(x.v)) || isJoin(x) || low(x) === 'xor') break; } return q; })()];
      if (left[0] >= left[1] || right[0] >= right[1]) continue;
      const sl = evaluate(...left, k), sr = evaluate(...right, k);
      let kind = null, other = null;
      if (sl === 'route' && stringValued(...left)) { kind = 'route'; other = right; }
      else if (sr === 'route' && stringValued(...right)) { kind = 'route'; other = left; }
      else if (sl === 'lower' && stringValued(...left) && upperLiteral(...right)) kind = 'dead';
      else if (sr === 'lower' && stringValued(...right) && upperLiteral(...left)) kind = 'dead';
      if (!kind || (kind === 'route' && free(...other, k))) continue;
      hit(k, t.v, kind, left[0], right[1] - 1, t.v === '===' || t.v === '==');
      continue;
    }
    // switch / match on the route: every arm is a case-sensitive ==/===
    if ((low(t) === 'switch' || low(t) === 'match') && is(toks[k + 1], '(') && M[k + 1] != null) {
      const r = [k + 2, M[k + 1]];
      if (evaluate(...r, k) === 'route' && stringValued(...r)) hits.push({ k, line: P.lineOf(t.o), op: low(t), kind: 'route', dir: null });
    }
  }
  // The calls this body makes, with the state of each argument — for one level of helper.
  const calls = [];
  for (let k = b0; k < b1; k++) {
    const t = toks[k];
    if (t.t !== 'i' || !is(toks[k + 1], '(') || M[k + 1] == null || NOT_A_CALL.has(t.v.toLowerCase()) || low(toks[k - 1]) === 'function' || low(toks[k - 1]) === 'new') continue;
    const via = is(toks[k - 1], '->') || is(toks[k - 1], '?->') ? (toks[k - 2] && toks[k - 2].v === '$this' ? 'self' : 'object')
      : is(toks[k - 1], '::') ? (['self', 'static', 'parent'].includes(low(toks[k - 2])) ? 'self' : lastSeg((toks[k - 2] || {}).v || '')) : '';
    if (via === 'object') continue;
    const args = splitArgs(toks, M, k + 1).map(([a, b]) => evaluate(a, b, k));
    const close = M[k + 1];
    const [a, z, pos] = withConstant(k - (via ? 2 : 0), close, '');
    const d = direction(a, z, pos);
    calls.push({ name: lastSeg(t.v), hint: via, args, k, line: P.lineOf(t.o), dir: d });
  }
  return { hits, calls };
}

// ---------- the whole check ----------
// `sources`: [{ file, src }] — the files that register a hook, at least. `resolve(names)` returns
// more [{ file, src }]: the files that may DEFINE those functions (scan.mjs: a git grep). It is asked
// twice — for the hooked callbacks, then for the helpers they call — and may return files already
// given. Returns { hits, notes, unparsed }: a hit is one comparison, reported once per file:line;
// `unparsed` names the candidate files the parser threw on.
export function findRestGateCase(sources, { resolve = () => [] } = {}) {
  const parsed = new Map();
  const unparsed = new Set();   // a candidate file the parser threw on: not graded, and the caller says so
  const add = (list) => { for (const { file, src } of list || []) if (!parsed.has(file) && !unparsed.has(file) && restGateCandidate(file)) { try { parsed.set(file, parsePhp(file, src)); } catch { unparsed.add(file); } } };
  add(sources);
  const notes = [];
  const regs = [];
  for (const P of parsed.values()) for (const r of P.regs) regs.push({ P, ...r });
  let unresolved = 0;
  const named = [...new Set(regs.filter((r) => r.cb.kind === 'name').map((r) => r.cb.name))];
  if (named.length) add(resolve(named));
  // Definitions of `name`, preferring the hint: the same file for self, a file declaring the class.
  const defsOf = (name, hint, fromP) => {
    const all = [];
    for (const P of parsed.values()) for (const fn of P.fns) if (fn.name && fn.name.toLowerCase() === name.toLowerCase()) all.push({ P, fn });
    if (hint === 'self') { const same = all.filter((d) => d.P === fromP); if (same.length) return same; }
    else if (hint) { const cls = all.filter((d) => d.P.classes.has(hint.toLowerCase())); if (cls.length) return cls; }
    return all;
  };
  // One entry per distinct (function, hook): a gate registered many times is graded once, and keeps
  // every file that registers it.
  const gateOf = new Map();
  const addGate = (P, fn, hook, gate, regFile) => {
    const key = `${P.file}\0${fn.k}\0${hook}`;
    const g = gateOf.get(key);
    if (g) { if (!g.regFiles.includes(regFile)) g.regFiles.push(regFile); return; }
    gateOf.set(key, { P, fn, hook, gate, regFile, regFiles: [regFile] });
  };
  for (const r of regs) {
    if (r.cb.kind === 'closure') { addGate(r.P, r.cb.fn, r.hook, 'closure', r.P.file); continue; }
    if (r.cb.kind !== 'name') { unresolved++; continue; }
    const defs = defsOf(r.cb.name, r.cb.hint, r.P);
    if (!defs.length) { unresolved++; continue; }
    for (const d of defs) addGate(d.P, d.fn, r.hook, d.fn.name, r.P.file);
  }
  const gates = [...gateOf.values()];
  if (unresolved) notes.push(`${unresolved} callback${unresolved === 1 ? '' : 's'} on ${HOOKS.join('/')} could not be resolved to a function body — a variable callback, or one defined outside the tracked tree — not graded`);
  const hits = [];
  const seen = new Map();   // file:line → its hit, or null when waived
  const report = (P, h, g, helperName) => {
    const key = `${P.file}:${h.line}`;
    if (seen.has(key)) {   // the same line reached through another gate: it changes with that gate's files too
      const was = seen.get(key);
      if (was) for (const f of [g.P.file, ...g.regFiles]) if (!was.regFiles.includes(f) && f !== was.gateFile) was.regFiles.push(f);
      return;
    }
    // The pragma, on the flagged line or in the run of comment lines directly above it.
    const pragma = /(?:\/\/|#|\/\*|\*)[ \t]*lint-allow-wp-rest-gate-case:[ \t]*\S/;
    let waived = pragma.test(P.lines[h.line - 1] || '');
    for (let l = h.line - 2; !waived && l >= 0 && /^\s*(\/\/|#|\/\*|\*)/.test(P.lines[l]); l--) waived = pragma.test(P.lines[l]);
    if (waived) { seen.set(key, null); return; }
    const hit = { file: P.file, line: h.line, hook: g.hook, gate: g.gate, helper: helperName || '', op: h.op, kind: h.kind, regFile: g.regFile, regFiles: [...g.regFiles], gateFile: g.P.file };
    seen.set(key, hit);
    hits.push(hit);
  };
  const pending = [];
  for (const g of gates) {
    const params = g.fn.params;
    const res = grade(g.P, g.fn, { gateParams: params, hook: g.hook });
    for (const h of res.hits) report(g.P, h, g);
    for (const c of res.calls) pending.push({ g, c });
  }
  // One level of helper: a function the gate calls, its parameters seeded from the call's arguments.
  // Each (gate, helper, argument states) is graded once.
  const helperNames = [...new Set(pending.map((p) => p.c.name))];
  if (helperNames.length) add(resolve(helperNames));
  const graded = new Set();
  for (const { g, c } of pending) {
    const once = `${g.P.file}\0${g.fn.k}\0${g.hook}\0${c.name}\0${c.hint}\0${c.args.join(',')}\0${c.dir ? `${c.dir.kind}${c.dir.match}` : ''}`;
    if (graded.has(once)) continue;
    graded.add(once);
    const defs = defsOf(c.name, c.hint, g.P);
    if (!defs.length || defs.length > 3) continue;   // a builtin, or a name too common to pin down
    for (const d of defs) {
      if (d.fn === g.fn) continue;
      const seed = new Map();
      d.fn.params.forEach((p, i) => { if (p && c.args[i]) seed.set(p, c.args[i]); });
      const res = grade(d.P, d.fn, { seed, helper: true, hook: g.hook });
      for (const h of res.hits) {
        // Fail-closed only when both directions are read: the helper's (its return on a match) and the call's.
        if (h.dir && c.dir && h.dir.kind && (h.dir.kind === 'true' || h.dir.kind === 'false')) {
          const helperTrueOnMatch = h.dir.kind === 'true' ? h.dir.match : !h.dir.match;
          const condTrueOnMatch = helperTrueOnMatch === c.dir.match;
          if ((c.dir.kind === 'exempt' && condTrueOnMatch) || (c.dir.kind === 'deny' && !condTrueOnMatch)) continue;
        }
        report(d.P, h, g, d.fn.name);
      }
    }
  }
  return { hits, notes, unparsed: [...unparsed] };
}

// A finding for the tier engine. `rule` names the hook, the gate (and helper) and the comparison.
export function restGateFinding(hit) {
  const where = `${hit.gate === 'closure' ? 'a closure' : `${hit.gate}()`}${hit.helper ? ` via ${hit.helper}()` : ''} on ${hit.hook}`;
  const msg = hit.kind === 'dead'
    ? `${where} compares the lower-cased route with a literal holding capitals (${hit.op}): it never matches, so the gate never applies — lower-case the literal`
    : `${where} compares the route case-sensitively (${hit.op}); WP matches routes with /i, so a re-cased namespace skips this gate yet reaches the handler — strtolower both sides, or lint-allow-wp-rest-gate-case: why`;
  return {
    checkId: CHECK_ID, tool: 'rest-gate-case', file: hit.file, line: hit.line, cwe: 'CWE-178',
    rule: `${hit.hook} ${hit.gate === 'closure' ? 'closure' : `${hit.gate}()`}${hit.helper ? ` → ${hit.helper}()` : ''} ${hit.op}`,
    msg,
  };
}
