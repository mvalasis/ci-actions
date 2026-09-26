// security-baseline outcome — did a scanner LOOK? PURE: no I/O, no process exit. scan.mjs runs a
// scanner and hands the finished process here; the answer is one of three, never two:
//   { looked: true,  results }          — it ran as asked; `results` may be empty (it found nothing)
//   { looked: false, reason, results }  — it could NOT look; `results` keeps whatever it did report
// Until v1.19.0 every adapter folded the third answer into the second: semgrep's exit status and
// errors[] were never read, gitleaks' missing report parsed as `[]`, and a failed trufflehog or
// osv-scanner run read as empty output. The report then said "PASS — no critical findings" about
// code nothing had scanned (VERIFICATION-TRAPS failed-probe-is-not-evidence).
//
// `r` is scan.mjs's run() result: { missing, status, signal, error, ms, stdout, stderr }.
import { CHECKS, safe, redact } from './tiers.mjs';

const ids = (re) => Object.keys(CHECKS).filter((k) => re.test(k));

// Every scanner leg scan.mjs runs, and the checkIds it can emit. A leg that could not look is judged
// by what it could have found (canBeCritical in tiers.mjs): it faults the run only when one of these
// could have been CRITICAL for this caller. selftest.mjs pins every rule pack's metadata.checkId to
// its leg, so a pack cannot gain a rule family its leg does not claim.
export const LEGS = {
  community: { name: 'semgrep community SAST', checks: ['sast-critical'] },
  custom: { name: 'semgrep WP/PHP + Astro/TS rule packs', checks: ids(/^(wp|ts|rn)-|^turnstile-test-key$/) },
  gha: { name: 'semgrep GitHub-Actions rule pack', checks: ids(/^gha-/) },
  // secrets-history: what the diff range found in a commit the base already holds (v1.19.8).
  gitleaks: { name: 'gitleaks secret scan', checks: ['secret-pattern', 'secrets-history'] },
  gitleaksHistory: { name: 'gitleaks full-history baseline', checks: ['secrets-history'] },
  // secrets-history: what a diff-scoped walk found in a commit the base holds (v1.19.7).
  trufflehog: { name: 'trufflehog verified-live secrets', checks: ['secret-verified', 'secrets-history'] },
  trufflehogHistory: { name: 'trufflehog verified-live secrets, full history', checks: ['secrets-history'] },
  osv: { name: 'osv-scanner dependency audit', checks: ids(/^sca-/) },
  hadolint: { name: 'hadolint Dockerfile lint', checks: ['dockerfile-lint'] },
  argvSecret: { name: 'argv-secret', checks: ['argv-secret'] },
};
// The changed-file list feeds every diff-scoped leg; a diff that fails leaves all of them grading nothing.
LEGS.diff = {
  name: 'changed-file list',
  checks: [...new Set([...LEGS.community.checks, ...LEGS.custom.checks, ...LEGS.hadolint.checks, ...LEGS.argvSecret.checks])],
};

// Every reason below reaches the report through safe(), which strips parentheses and brackets, so
// none is written with them.
//
// Free text a tool prints about its own failure reaches the report and the job log. Beyond safe()'s
// structural strip, a URL's userinfo is dropped and every long run that mixes letters and digits is
// cut to redact()'s first4…last4, so a credential echoed inside an error (a DSN, a token in a URL)
// cannot land whole in a log. Letters-only runs survive, so a rule id stays readable.
export const scrub = (s, max = 160) => safe(String(s == null ? '' : s)
  .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, '$1')
  .replace(/[A-Za-z0-9_+=-]{20,}/g, (m) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? redact(m) : m)), max);

// The stderr line that says what went wrong: the first `fatal:`/`error:` line or zerolog FTL/ERR line
// (git prints its reason first and usage hints after it), else the last line that is not a Python
// warning (semgrep is a pip install; its tracebacks end on the exception, its warnings do not).
const NOISE = /Warning: |warnings\.warn\(/;
export const errorLine = (text) => {
  const ls = String(text || '').split('\n').map((l) => l.trim()).filter((l) => l && !NOISE.test(l));
  return ls.find((l) => /^(fatal|error)\b|\s(FTL|ERR)\s/i.test(l)) || ls.pop() || '';
};

// How long a run that took 10 s or more took: a registry fetch that stalls for ~100 s and then fails
// leaves no other trace (measured: semgrep exit 2, empty stdout and stderr).
const took = (r) => (Number.isFinite(r.ms) && r.ms >= 10000 ? ` after ${Math.round(r.ms / 1000)} s` : '');
// A process that never finished is could-not-look whatever its output says.
function processFault(r) {
  if (r.missing) return 'not installed';
  if (r.error === 'ETIMEDOUT') return `timed out${took(r)}`;
  if (r.error === 'ENOBUFS') return 'output over the 64 MB buffer';
  if (r.signal) return `killed by ${r.signal}`;
  if (r.error) return `could not run: ${scrub(r.error, 80)}`;
  return '';
}
const exitReason = (r, detail) => `exit ${r.status}${took(r)}${detail ? `: ${scrub(detail)}` : ''}`;
const parse = (text) => { try { return JSON.parse(text); } catch { return undefined; } };

// ---------- semgrep ----------
// Without --error (never passed here) semgrep exits 0 whether or not it found anything; 1 means
// "findings" only under --error; 2 and up are errors (measured on 1.178.0: a registry config that
// will not download, or a rule schema it rejects, exits 7 with the reason in errors[]; a bad
// pattern exits 2 and keeps the other rules' results; no network exits 2 with no JSON at all).
// Its exit code reflects only the LAST error it recorded, so errors[] is read in full. An entry at
// `level: "error"` is semgrep's own verdict that the run did not go as asked — a rule or config that
// did not load, or its engine failing on a file (AST builder / fatal error, which it exits 2 for).
// `warn`/`info` entries are one scanned FILE it could not fully parse or finish (a syntax error, a
// timeout), with every other file still scanned: listed in the report, not a fault.
const errType = (e) => String(Array.isArray(e.type) ? e.type[0] : (e.type || 'error'));
export function semgrepOutcome(r) {
  const pf = processFault(r);
  if (pf) return { looked: false, reason: pf, results: [], skipped: [] };
  const json = parse(r.stdout);
  if (!json || typeof json !== 'object' || !Array.isArray(json.results)) {
    return { looked: false, reason: exitReason(r, errorLine(r.stderr) || 'no JSON report'), results: [], skipped: [] };
  }
  const errors = Array.isArray(json.errors) ? json.errors.filter((e) => e && typeof e === 'object') : [];
  const fatal = errors.filter((e) => e.level === 'error');
  const skipped = errors.filter((e) => e.level !== 'error' && e.path).map((e) => String(e.path));
  const first = fatal[0] || errors[0];
  const detail = first ? `${errType(first)}${first.message ? ` — ${first.message}` : ''}` : errorLine(r.stderr);
  const findingsExit = r.status === 1 && json.results.length > 0;
  if (r.status !== 0 && !findingsExit) return { looked: false, reason: exitReason(r, detail), results: json.results, skipped };
  if (fatal.length) return { looked: false, reason: `exit ${r.status} with ${fatal.length} error${fatal.length === 1 ? '' : 's'} — ${scrub(detail)}`, results: json.results, skipped };
  return { looked: true, results: json.results, skipped };
}

// ---------- gitleaks ----------
// Run with --exit-code 0: 0 = it ran, leaks or none; anything else is an error (log.Fatal exits 1).
// A run that finished writes its report even for zero findings (`[]`; `null` read the same). No
// report, or one that is not a JSON array, is a run that did not finish — never "no secrets".
// Its exit code has two blind spots scan.mjs covers before it runs (measured on 8.30.1): outside a
// git repository, and on a --log-opts range git cannot resolve, it exits 0 with `[]`.
export function gitleaksOutcome(r, report) {
  const pf = processFault(r);
  if (pf) return { looked: false, reason: pf, results: [] };
  if (r.status !== 0) return { looked: false, reason: exitReason(r, errorLine(r.stderr)), results: [] };
  if (report == null) return { looked: false, reason: 'exit 0 but wrote no report', results: [] };
  let arr = parse(report);
  if (arr === null) arr = [];
  if (!Array.isArray(arr)) return { looked: false, reason: 'its report is not a JSON array', results: [] };
  return { looked: true, results: arr };
}

// ---------- trufflehog ----------
// trufflehog exits 0 whether or not it found anything (183 is --fail, never passed here); anything
// else is an error. Without --fail-on-scan-errors (scan.mjs passes it) a scan that failed inside —
// a --since-commit it cannot resolve — ALSO exits 0, having scanned nothing (measured on 3.95.6).
// stdout is one JSON object per line, and one that starts like an object and does not parse is
// output cut short. Its stderr is NEVER quoted: that is where trufflehog logs, and a live credential
// must not reach the report, not even redacted.
export function trufflehogOutcome(r) {
  const pf = processFault(r);
  if (pf) return { looked: false, reason: pf, results: [] };
  const results = [];
  let broken = 0;
  for (const ln of String(r.stdout || '').split('\n')) {
    const t = ln.trim();
    if (!t || t[0] !== '{') continue;
    const o = parse(t);
    if (o && typeof o === 'object') results.push(o); else broken++;
  }
  if (r.status !== 0) return { looked: false, reason: `exit ${r.status} — its log is not quoted here, rerun trufflehog to read it`, results };
  if (broken) return { looked: false, reason: `${broken} JSON line(s) cut short`, results };
  return { looked: true, results };
}

// ---------- osv-scanner ----------
// 0 = no vulnerabilities, 1 = vulnerabilities found — both looked, both print the report. 128 prints
// "No package sources found" and no stdout for three different trees (measured on v2.4.0,
// 2026-09-25): one with no lockfile; one whose every lockfile it read holds no package (stderr:
// `Scanned <path> file and found 0 packages`); and one whose lockfiles it could not read, a
// truncated or junk one (stderr: `Error during extraction: …`) or a bun.lockb, which it does not
// read at all and says nothing about. Only the first two looked. A readable lockfile beside an
// unreadable one exits 127. 129 is the osv.dev API failing, 130 an invalid config, 127 any other
// error: none looked.
const EXTRACT_ERROR = /^Error during extraction\b.*$/m;
const SCANNED = /^Scanned .+ and found \d+ packages?$/m;
// osv names a file by its absolute path without the leading slash. Under the scanned root that
// prefix is noise, and at the reason's 160 characters it would push the error itself out.
const underRoot = (line, root) => {
  const prefix = String(root || '').replace(/^\/+|\/+$/g, '');
  return prefix ? line.split(`${prefix}/`).join('') : line;
};
const listed = (files) => `${files.slice(0, 3).join(', ')}${files.length > 3 ? ` and ${files.length - 3} more` : ''}`;
// `lockfiles` are the tracked npm/composer lockfiles (scan.mjs, git ls-files) and `root` the
// directory osv-scanner scanned: on exit 128 they tell a tree with nothing to audit from one whose
// lockfiles osv-scanner could not read.
export function osvOutcome(r, { lockfiles = [], root = '' } = {}) {
  const pf = processFault(r);
  if (pf) return { looked: false, reason: pf, results: [] };
  if (r.status === 128) {
    const stderr = String(r.stderr || '');
    const failed = stderr.match(EXTRACT_ERROR);
    if (failed) return { looked: false, reason: exitReason(r, underRoot(failed[0], root)), results: [] };
    if (lockfiles.length && !SCANNED.test(stderr)) return { looked: false, reason: exitReason(r, `it read none of the tree's lockfiles: ${listed(lockfiles)}`), results: [] };
    return { looked: true, results: [] };
  }
  const json = parse(r.stdout);
  const results = json && typeof json === 'object' && Array.isArray(json.results) ? json.results : [];
  if (r.status !== 0 && r.status !== 1) return { looked: false, reason: exitReason(r, errorLine(r.stderr)), results };
  if (!json || typeof json !== 'object' || !Array.isArray(json.results)) return { looked: false, reason: exitReason(r, 'no JSON report'), results: [] };
  if (r.status === 1 && results.length === 0) return { looked: false, reason: 'exit 1, vulnerabilities found, with no results in its report', results };
  return { looked: true, results };
}

// ---------- hadolint ----------
// Exits 1 when a rule fires (its default failure threshold) and 0 when none does; both print a JSON
// array, and a Dockerfile it cannot parse arrives in that array as DL1000. No array means it failed.
export function hadolintOutcome(r) {
  const pf = processFault(r);
  if (pf) return { looked: false, reason: pf, results: [] };
  const arr = parse(r.stdout);
  if (!Array.isArray(arr)) return { looked: false, reason: exitReason(r, errorLine(r.stderr) || 'no JSON report'), results: [] };
  if (r.status !== 0 && r.status !== 1) return { looked: false, reason: exitReason(r, errorLine(r.stderr)), results: arr };
  return { looked: true, results: arr };
}
