// argv-secret — a secret spelled into a child process's argv. PURE: no I/O, no process exit; the
// caller reads the files (scan.mjs) and decides the scope (scan.mjs for the fleet, the repo lint
// for this repo's own entrypoints). ONE detector with two consumers: security-baseline's T1
// `argv-secret` check, and rule 4 of .github/scripts/lint-entrypoint-output.mjs, which moved its
// matcher here in v1.17.0 rather than keeping a second copy.
//
// THE DEFECT CLASS: argv is world-readable — `ps`, /proc/<pid>/cmdline — to every process on the
// machine (on a runner: the caller's other steps and every action they use), and an argv-logging
// wrapper first on PATH records it verbatim. Nothing about a green run shows it. This fleet shipped
// it by hand at least five times, always as a curl header carrying the WAF token, and fixed each by
// hand: an array assignment on a line that never names curl (`hdr=(-H "X-Verify-Source: $TOKEN")`
// — which is why the match keys on the flag and its value, never on the command name), a Python
// argv list (`["-H", f"X-Verify-Source: {TOKEN}"]`), and a workflow `run:` step expanding
// `${{ secrets.* }}` inside the header. Every fix hands curl `-H @file` from a mode-600 file, so
// the value never enters argv. That shape has no `Name:` after the flag, so it never matches.
//
// THE RULE: a `-H` / `--header` whose VALUE expands a variable named like TOKEN, SECRET, KEY or
// PASS — a substring match, case-insensitive (VERIFY_TOKEN, apiKey, self.token,
// process.env.X_SECRET, secrets.API_KEY). The value is a `Name: …` literal, and the variable enters
// it as `$VAR` / `${VAR}` (bash, JS template), `{expr}` (Python f-string — and, by the same branch,
// a GitHub Actions `${{ expr }}`) or `"Name: " + VAR`. The flag and the value may sit on different
// lines, as in a Python list exploded one element per line.
//
// Comments are not code: whole `#` comment lines in shell, Python and YAML (audit.sh explains its
// fix in exactly the text this rule matches), and every `//` / `/* */` comment in JavaScript via
// the scrubber, run with its literals kept.
//
// KNOWN LIMITS, stated rather than papered over. Not seen: a header string built on an earlier
// line and passed as `-H "$hdr"` (that is dataflow), `%` / `.format()` formatting, a trailing `#`
// comment on a code line (it is scanned, so it can fire), and other argv spellings of a secret
// (`-u user:$PASS`, `-d token=…`, a query string, a CLI flag like `--api-token $T`). A substring
// match also fires on a non-secret that merely looks like one (`$CACHE_KEY`) — annotate that,
// don't narrow the regex.
import { blankNonCode } from './js-scrub.mjs';

// 1 flag · 2 value's opening quote · 3 header name · 4 rest of the literal ·
// 5 a `+ VAR` concatenated onto it. Between flag and value: bash whitespace,
// wget's `=`, or a list's closing quote and comma (newlines included).
const HEADER_ARG = /(-H|--header)(?:=|["'`]?\s*(?:,\s*)?)[fF]?(["'`])([A-Za-z][\w-]*):([^\n]*?)\2(?:\s*\+\s*([A-Za-z_][\w.]*))?/dg;
const EXPANSION = /\$\{?\s*([A-Za-z_][\w.]*)|\{\s*([A-Za-z_][\w.]*)/g;
const SECRET_NAME = /token|secret|key|pass/i;

// `# lint-allow-argv-secret: <reason>` (`//` in JavaScript), on the flagged line or
// the line directly above it. A reason is REQUIRED, as for the lint's other two pragmas:
// the point is to record why the value is not a secret, not to switch the rule off.
const ARGV_PRAGMA = /(?:\/\/|#)[ \t]*lint-allow-argv-secret:[ \t]*\S/;

// The source with its comments blanked and everything else intact — offsets and
// line numbers preserved, so a match maps straight back to the raw line.
function commentsBlanked(src, lang) {
  if (lang === 'js') return blankNonCode(src, { literals: false });
  return src.split('\n').map((l) => (/^\s*#/.test(l) ? ' '.repeat(l.length) : l)).join('\n');
}

// Every header argument in `src` whose value expands a secret-named variable, as
// { line, col, flag, header, secret, text } — `secret` is the variable's NAME (the scan is static;
// it never sees a value). `lang` is 'sh' | 'py' | 'js' | 'yaml' and only chooses the comment syntax.
export function findArgvSecrets(src, lang) {
  const code = commentsBlanked(src, lang);
  const rawLines = src.split('\n');
  const found = [];
  for (const m of code.matchAll(HEADER_ARG)) {
    const exprs = [...m[4].matchAll(EXPANSION)].map((e) => e[1] || e[2]);
    if (m[5]) exprs.push(m[5]);
    const secret = exprs.find((e) => SECRET_NAME.test(e));
    if (!secret) continue;
    // Report where the secret is spelled: the value, not the flag.
    const before = code.slice(0, m.indices[2][0]).split('\n');
    const line = before.length, col = before[before.length - 1].length + 1;
    if (ARGV_PRAGMA.test(rawLines[line - 1] || '') || ARGV_PRAGMA.test(rawLines[line - 2] || '')) continue;
    found.push({ line, col, flag: m[1], header: m[3], secret, text: (rawLines[line - 1] || '').trim() });
  }
  return found;
}

// ---------- which files the FLEET check grades ----------
// Languages that spawn processes on a runner or a laptop: shell, Python, the JavaScript/TypeScript
// a build or CI step runs, and the YAML that holds `run:` steps. Not UI components (.tsx/.jsx/
// .astro), and not prose: a README that shows `curl -H "Authorization: Bearer $TOKEN"` to a human
// is a one-off on that person's machine, not a script re-running under whatever PATH it inherits.
const LANG_BY_EXT = {
  '.sh': 'sh', '.bash': 'sh', '.zsh': 'sh', '.ksh': 'sh',
  '.py': 'py',
  '.mjs': 'js', '.cjs': 'js', '.js': 'js', '.ts': 'js', '.mts': 'js', '.cts': 'js',
};
// Never graded: third-party code, and fixture corpora that must spell the banned form to test it
// (this repo's selftests — the same exclusion the lint's entrypoint discovery makes).
const SKIP_PATH = [
  /(^|\/)(node_modules|vendor|wp-admin|wp-includes|bower_components)\//,
  /\.min\.js$/,
  /(^|\/)selftest[^/]*$/, /\.selftest\.[^/]+$/, /(^|\/)selftest\//,
  /(^|\/)(fixtures?|__fixtures__)\//,
];
// Workflows and local composite actions: graded on EVERY run, not just when they change — the
// same always-on pass `gha.yaml` gets, since a workflow is small and a leak there runs on every push.
export const isGithubYaml = (f) => /^\.github\/.+\.ya?ml$/i.test(String(f));
const extOf = (f) => { const base = String(f).split('/').pop(); const i = base.lastIndexOf('.'); return i > 0 ? base.slice(i).toLowerCase() : ''; };

// The language to grade `file` as, or null to skip it. `head` is the file's first line, consulted
// only for an extensionless file (a `bin/` tool is identified by its shebang).
export function argvLang(file, head = '') {
  const f = String(file);
  if (SKIP_PATH.some((re) => re.test(f))) return null;
  if (isGithubYaml(f) || /(^|\/)action\.ya?ml$/i.test(f)) return 'yaml';
  const ext = extOf(f);
  if (ext) return LANG_BY_EXT[ext] || null;
  const first = String(head).split('\n')[0];
  if (!first.startsWith('#!')) return null;
  if (/python/.test(first)) return 'py';
  if (/\b(node|bun|deno)\b/.test(first)) return 'js';
  if (/\b(ba|z|k|da)?sh\b/.test(first)) return 'sh';
  return null;
}

// The files to grade, as [{ file, lang }]. `changed` is the diff's file list, or null for a
// full-tree scan; `tracked` is every tracked path (the full-tree list, and the source of the
// always-on .github YAML pass); `headOf(file)` returns a file's first line.
export function argvTargets({ changed, tracked, headOf = () => '' }) {
  const out = new Map();
  const add = (f) => {
    if (out.has(f)) return;
    const lang = argvLang(f, extOf(f) ? '' : headOf(f));
    if (lang) out.set(f, lang);
  };
  for (const f of (changed || tracked)) add(f);
  for (const f of tracked) if (isGithubYaml(f)) add(f);
  return [...out].map(([file, lang]) => ({ file, lang }));
}

// A finding for the tier engine. `rule` names the header and the variable, never a value.
export function argvFinding(file, hit) {
  return {
    checkId: 'argv-secret', tool: 'argv-secret', rule: `${hit.flag} ${hit.header} ← ${hit.secret}`,
    file, line: hit.line, cwe: 'CWE-214',
    msg: `${hit.flag} ${hit.header} expands ${hit.secret} into a child's argv, readable by any process via ps and /proc — pass it as -H @file from a mode-600 file, or annotate a non-secret with lint-allow-argv-secret: why`,
  };
}
