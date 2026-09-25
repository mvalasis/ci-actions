// JavaScript source scrubber — PURE, no I/O. Shared by security-baseline's `argv-secret` check
// (argv-secret.mjs, run with literals kept) and the repo-internal lint
// (.github/scripts/lint-entrypoint-output.mjs, rules 1, 2 and 4), which imports it from here: one
// scrubber, not two. It moved here verbatim from the lint in v1.17.0; because it now ships, a
// change to it is a release, not a lint edit.
//
// Blank every non-code span (comments, string and template literals, regex
// literals) so a matcher only ever sees CODE. Offsets and line numbers
// are preserved: each blanked character becomes a space, newlines are kept.
//
// Without this the lint would fire on its own remediation advice — run.mjs:37
// and render-check.mjs:44 both spell out `console.log` in a comment explaining
// why they do not use it — and a regex such as /['"]/ would desync a naive
// string scanner and swallow real code after it.
const REGEX_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'case', 'do', 'else', 'yield', 'await',
]);

// Decide whether `/` opens a regex literal or is a division operator, from the
// last significant code token. 'w' = identifier/number, 'x' = a completed
// literal. After a value, `/` divides; after an operator or a keyword, it opens
// a regex.
function regexAllowed(prev, word) {
  if (prev === '') return true;                       // start of file
  if (prev === 'w') return REGEX_KEYWORDS.has(word);  // `return /re/` vs `a / b`
  if (prev === 'x') return false;                     // after a string/regex
  if (prev === ')' || prev === ']') return false;     // (a+b)/2, arr[0]/2
  return true;                                        // ( , = : [ ! & | ? { } ; …
}

// `literals: false` blanks comments ONLY and keeps string, template and regex
// literals as written — the argv-secret view, since the secret-bearing header lives in a
// literal. The scan is the same either way; only what gets wiped differs.
export function blankNonCode(src, { literals = true } = {}) {
  // UTF-16 code units, the unit `src[i]` indexes by — NOT Array.from(src), which
  // splits by code point: after an astral character (an emoji; six .mjs
  // entrypoints carry one) every wipe landed one slot late per astral char, so a
  // comment's wipe ate the newline after it and, from the second on, the first
  // characters of the next line's code. That can hide a finding — the permissive
  // direction. (No live result changed when this was fixed.)
  const out = src.split('');
  const n = src.length;
  const wipe = (i) => { if (i < n && src[i] !== '\n') out[i] = ' '; };
  const wipeLit = literals ? wipe : () => {};
  const interp = [];   // brace depths at which a `${` interpolation was opened
  let depth = 0;
  let prev = '';
  let word = '';
  let mode = 'code';
  let i = 0;

  while (i < n) {
    if (mode === 'tmpl') {
      if (src[i] === '\\') { wipeLit(i); wipeLit(i + 1); i += 2; continue; }
      if (src[i] === '`') { wipeLit(i); i++; mode = 'code'; prev = 'x'; word = ''; continue; }
      if (src[i] === '$' && src[i + 1] === '{') {
        wipeLit(i); wipeLit(i + 1); i += 2;
        interp.push(depth); depth++;              // the `{` of `${`
        mode = 'code'; prev = '{'; word = '';
        continue;
      }
      wipeLit(i); i++; continue;
    }

    const c = src[i], d = src[i + 1];

    if (c === '/' && d === '/') {                 // line comment
      while (i < n && src[i] !== '\n') wipe(i++);
      continue;
    }
    if (c === '/' && d === '*') {                 // block comment
      wipe(i); wipe(i + 1); i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) wipe(i++);
      if (i < n) { wipe(i); wipe(i + 1); i += 2; }
      continue;
    }
    if (c === "'" || c === '"') {                 // string literal
      wipeLit(i); i++;
      while (i < n && src[i] !== c && src[i] !== '\n') {
        if (src[i] === '\\') { wipeLit(i); wipeLit(i + 1); i += 2; continue; }
        wipeLit(i); i++;
      }
      if (i < n && src[i] === c) { wipeLit(i); i++; }
      prev = 'x'; word = '';
      continue;
    }
    if (c === '`') { wipeLit(i); i++; mode = 'tmpl'; continue; }
    if (c === '/' && regexAllowed(prev, word)) {  // regex literal
      wipeLit(i); i++;
      let inClass = false;
      while (i < n && src[i] !== '\n') {
        const r = src[i];
        if (r === '\\') { wipeLit(i); wipeLit(i + 1); i += 2; continue; }
        if (r === '[') inClass = true;
        else if (r === ']') inClass = false;
        else if (r === '/' && !inClass) break;
        wipeLit(i); i++;
      }
      if (i < n && src[i] === '/') { wipeLit(i); i++; }
      while (i < n && /[a-z]/.test(src[i])) { wipeLit(i); i++; }   // flags
      prev = 'x'; word = '';
      continue;
    }
    if (c === '{') { depth++; prev = '{'; word = ''; i++; continue; }
    if (c === '}') {
      if (interp.length && depth === interp[interp.length - 1] + 1) {
        interp.pop(); depth--; wipeLit(i); i++; mode = 'tmpl';  // close `${…}`
        continue;
      }
      depth--; prev = '}'; word = ''; i++;
      continue;
    }
    if (/\s/.test(c)) { i++; continue; }
    if (/[A-Za-z_$0-9]/.test(c)) {                // identifier / number / member path
      let j = i, w = '';
      while (j < n && /[A-Za-z_$0-9.]/.test(src[j])) { w += src[j]; j++; }
      word = w; prev = 'w'; i = j;
      continue;
    }
    prev = c; word = ''; i++;
  }

  return out.join('');
}
