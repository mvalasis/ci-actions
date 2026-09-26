// security-baseline CLI — runs the air-gapped scanners, normalizes their output into findings,
// tiers them via the pure engine (tiers.mjs), renders a per-check report to GITHUB_STEP_SUMMARY and
// the same report to the job log, annotates each CRITICAL (`::error file=…,line=…::`), and exits
// non-zero under fail-on-critical only when a CRITICAL (T0, or a per-caller-promoted T1) fires, or
// when a scanner leg that could have produced one could not look (outcome.mjs) — a FAULT, reported
// as the gate's own, never as a finding and never as a PASS. Mirrors seo-aeo's check.mjs shape.
//
// EGRESS (honest enumeration — see README §Sovereignty): NO source ever leaves the runner.
//   - semgrep: --metrics=off (telemetry off). The default `p/security-audit` registry config is
//     a RULE-DEFINITION fetch (no code); vendor a local config to remove it. Custom rules/ are
//     vendored → zero fetch.
//   - gitleaks / hadolint: self-contained binaries, zero egress.
//   - trufflehog --only-verified: a test-auth to the credential's OWN provider (permitted) — opt
//     out with verified-secrets:off for a fully air-gapped runner.
//   - osv-scanner: sends package COORDINATES (name@version) to osv.dev — never your lockfile body.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { SEV, evaluate, parsePromote, groupByCheck, sevRank, CHECKS, safe, redact, annotations, canBeCritical, faultAnnotation, shortSha } from './tiers.mjs';
import { firstPartyOwners, filterFirstPartyGha } from './firstparty.mjs';
import { argvTargets, findArgvSecrets, argvFinding } from './argv-secret.mjs';
import { LEGS, semgrepOutcome, gitleaksOutcome, trufflehogOutcome, osvOutcome, hadolintOutcome, scrub, errorLine } from './outcome.mjs';

const env = process.env;
const ACTION_PATH = env.GITHUB_ACTION_PATH || path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const RULES_DIR = path.join(ACTION_PATH, 'rules');
const SCAN_SCOPE = (env.SCAN_SCOPE || 'diff').trim();
const FAIL_ON_CRITICAL = (env.FAIL_ON_CRITICAL || 'true').trim() !== 'false';
const REPORT_MODE = (env.REPORT_MODE || 'false').trim() === 'true';
const SEMGREP_CONFIG = (env.SEMGREP_CONFIG || 'p/security-audit').trim();
const VERIFIED_SECRETS = (env.VERIFIED_SECRETS || 'auto').trim();   // auto | on | off
const ENABLE_SCA = (env.ENABLE_SCA || 'true').trim() !== 'false';
const ENABLE_HISTORY = (env.ENABLE_SECRETS_HISTORY || 'true').trim() !== 'false';
const { promote, ignored } = parsePromote(env.CRITICAL_CHECKS || '');
// First-party owners for the GHA supply-chain rule = caller's owner ∪ THIS action's own owner ∪
// whatever the caller declares. The action's own owner is the 2026-08 addition: the fleet's callers
// no longer share an account with ci-actions, so deriving "first-party" from the caller alone would
// report every `mvalasis/ci-actions/<action>@v1` ref on the six migrated callers.
//
// The action's own owner has TWO sources with the same documented meaning, and both are read
// because GitHub documents NEITHER for the shape this runs in (a composite action's own step):
// ACTION_REPOSITORY is `${{ github.action_repository }}` handed over by action.yml, and
// GITHUB_ACTION_REPOSITORY is the runner's ambient copy — which survives only because action.yml
// deliberately does not write the `GITHUB_` name and shadow it (see the comment there). Either
// source being EMPTY (a local `./` invocation empties both — this repo's own smoke job) just drops
// out: firstPartyOwners() filters empties rather than admitting an ''-owner that matches all.
const FIRST_PARTY = firstPartyOwners({
  repository: env.GITHUB_REPOSITORY,
  actionRepository: env.ACTION_REPOSITORY || env.GITHUB_ACTION_REPOSITORY,
  extra: env.FIRST_PARTY_OWNERS,
});

const BIN = {
  semgrep: env.SEMGREP_BIN || 'semgrep',
  gitleaks: env.GITLEAKS_BIN || 'gitleaks',
  trufflehog: env.TRUFFLEHOG_BIN || 'trufflehog',
  osv: env.OSV_BIN || 'osv-scanner',
  hadolint: env.HADOLINT_BIN || 'hadolint',
};

// The report goes to the job LOG always, and to the step summary when there is one. The summary
// alone needs a signed-in browser: `gh run view --log-failed` showed only "exit code 1", the
// check-run API's `output` was empty, and a headless session learned THAT the gate blocked, never
// why (2026-09-23, luxairportlu 739c623). The log is written through fd 1, never by opening
// /dev/stdout: on Linux that open fails (ENXIO) when stdout is a socket, which is what node's
// child_process hands a child. `/dev/stdout` as the summary (a documented local idiom) means none.
const summaryFile = env.GITHUB_STEP_SUMMARY && env.GITHUB_STEP_SUMMARY !== '/dev/stdout' ? env.GITHUB_STEP_SUMMARY : '';
const ANNOTATE = env.GITHUB_ACTIONS === 'true';   // runner commands are for the runner, not a local run
const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };
const lines = [];
const note = (s = '') => lines.push(s);
const ICON = { critical: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };
const infra = [];   // informational scanner notes (not findings, not faults)
// Scanner legs that could not look: { leg, reason }. Never a finding, and never read as "nothing
// found" — one whose checks can be CRITICAL for this caller takes the verdict away (see main).
const faults = [];
const couldNotLook = (leg, reason) => { if (!faults.some((f) => f.leg === leg)) faults.push({ leg, reason }); };
// safe() + redact() are imported from tiers.mjs (pure, selftest-covered disclosure guards).

// `signal` and `error` say a process never finished (a timeout, the output cap): outcome.mjs reads
// them before any output, which a killed scanner may have left half-written.
function run(bin, args, opts = {}) {
  const t0 = Date.now();
  try {
    const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: opts.timeout || 300000, ...opts });
    if (r.error && r.error.code === 'ENOENT') return { missing: true, status: 127, signal: '', error: '', ms: 0, stdout: '', stderr: '' };
    return {
      missing: false, status: r.status == null ? 1 : r.status, signal: r.signal || '', ms: Date.now() - t0,
      error: r.error ? String(r.error.code || r.error.message || r.error) : '', stdout: r.stdout || '', stderr: r.stderr || '',
    };
  } catch (e) { return { missing: false, status: 1, signal: '', error: String(e && e.message || e), ms: Date.now() - t0, stdout: '', stderr: '' }; }
}
const have = (bin) => !run(bin, ['--version'], { timeout: 15000 }).missing;
const sh = (args) => { const r = run('git', args, { timeout: 30000 }); return r.status === 0 ? r.stdout.trim() : ''; };

// ---------- diff base + changed files ----------
function resolveBase() {
  if (env.BASE_REF) return env.BASE_REF.trim();
  if (env.GITHUB_BASE_REF) return `origin/${env.GITHUB_BASE_REF}`;
  // a multi-commit push: diff the whole pushed range (event.before), not just HEAD~1
  const before = env.GITHUB_EVENT_BEFORE || '';
  if (/^[0-9a-f]{40}$/.test(before) && before !== '0'.repeat(40) && run('git', ['cat-file', '-e', before]).status === 0) return before;
  return sh(['rev-parse', '--verify', '--quiet', 'HEAD~1']);
}
const BASE = resolveBase();
const DIFF = SCAN_SCOPE === 'diff' && BASE;
function changedFiles() {
  if (!DIFF) return null; // full tree
  const r = run('git', ['diff', '--name-only', '--diff-filter=d', `${BASE}...HEAD`], { timeout: 30000 });
  // A diff that failed is not a diff with nothing in it: every diff-scoped leg would grade an empty
  // list and call it clean. (A base named by base-ref or the PR is not verified to exist.)
  if (r.status !== 0 || r.error) {
    couldNotLook(LEGS.diff, `git diff ${safe(BASE, 60)}...HEAD failed, exit ${r.status}${errorLine(r.stderr) ? `: ${scrub(errorLine(r.stderr))}` : ''}`);
    return [];
  }
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}
const CHANGED = changedFiles();
const byExt = (files, exts) => (files || []).filter((f) => exts.some((e) => f.toLowerCase().endsWith(e)) && fs.existsSync(f));

// ---------- semgrep ----------
// One semgrep leg. A leg that could not look is recorded as a fault and still hands back every
// finding it did report: a scanner that half-failed has not un-found anything.
function semgrepRun(leg, configs, targets, { severity } = {}) {
  if (!targets || targets.length === 0) return { results: [] };
  const args = ['scan', '--json', '--metrics=off', '--disable-version-check', '--quiet', '--no-git-ignore'];
  if (severity) args.push('--severity', severity);
  for (const c of configs) args.push('--config', c);
  args.push(...targets);
  const o = semgrepOutcome(run(BIN.semgrep, args, { timeout: 420000 }));
  if (!o.looked) couldNotLook(leg, `semgrep ${o.reason}`);
  if (o.skipped.length) infra.push(`${leg.name}: semgrep could not fully parse or finish ${o.skipped.length} file${o.skipped.length === 1 ? '' : 's'}, the rest were scanned — ${o.skipped.slice(0, 3).map((p) => safe(p, 80)).join(', ')}${o.skipped.length > 3 ? ', …' : ''}`);
  return { results: o.results };
}
// `rule` names the rule in annotations. A registry id is a dotted namespace worth keeping whole; a
// vendored rule's id arrives prefixed with its config's filesystem path (`home.runner.work.….rules.
// <id>`), so only the last segment is kept there — its checkId already says which pack it came from.
const sgFinding = (r, checkId) => ({
  checkId, tool: 'semgrep', rule: checkId === 'sast-critical' ? (r.check_id || '') : String(r.check_id || '').split('.').pop(),
  file: r.path, line: (r.start && r.start.line) || 0,
  cwe: (r.extra && r.extra.metadata && [].concat(r.extra.metadata.cwe || []).join(',')) || '',
  msg: (r.extra && r.extra.message) || r.check_id || '',
});

function collectSemgrep() {
  const out = [];
  const sastTargets = DIFF ? byExt(CHANGED, ['.php', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.java']) : ['.'];
  const codeTargets = DIFF ? byExt(CHANGED, ['.php', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.astro']) : ['.'];
  const ghaTargets = fs.existsSync('.github/workflows') ? ['.github/workflows'] : [];
  if (!have(BIN.semgrep)) {
    // Every leg that had something to grade could not look; one with nothing to grade missed nothing.
    for (const [leg, targets] of [[LEGS.community, sastTargets], [LEGS.custom, codeTargets], [LEGS.gha, ghaTargets]]) {
      if (targets.length) couldNotLook(leg, 'semgrep not installed');
    }
    return out;
  }
  // T0 — community ERROR on the diff (or full tree). This IS today's block, preserved.
  const community = semgrepRun(LEGS.community, [SEMGREP_CONFIG], sastTargets, { severity: (env.SAST_SEVERITY || 'ERROR').trim() });
  for (const r of community.results) out.push(sgFinding(r, 'sast-critical'));
  // T1/T2 — vendored custom rules (php/ts), diff-scoped (diff: only when code files changed; full:
  // ['.']); emit by metadata.checkId.
  const custom = semgrepRun(LEGS.custom, [path.join(RULES_DIR, 'wp-php.yaml'), path.join(RULES_DIR, 'astro-ts.yaml')], codeTargets);
  for (const r of custom.results) {
    const id = r.extra && r.extra.metadata && r.extra.metadata.checkId;
    if (id) out.push(sgFinding(r, id));
  }
  // GitHub Actions supply-chain — always over .github/workflows (small, high value).
  // The rule pack is static YAML and cannot know whose actions these are, so it flags the caller's
  // OWN shared actions too (55 `<owner>/ci-actions/<action>@v1` refs across the 10 callers). Those
  // are first-party and deliberately floating-tag-pinned by the fleet's versioning policy; drop
  // them here, where the owner set is knowable. Anything unrecoverable stays — see firstparty.mjs.
  const gha = semgrepRun(LEGS.gha, [path.join(RULES_DIR, 'gha.yaml')], ghaTargets);
  for (const r of filterFirstPartyGha(gha.results, FIRST_PARTY)) {
    const id = r.extra && r.extra.metadata && r.extra.metadata.checkId;
    if (id) out.push(sgFinding(r, id));
  }
  return out;
}

// ---------- gitleaks (pattern secrets) ----------
// The report goes to a directory made for this one run. The old fixed name under the shared tmp
// (`gl-<hash of the args>.json`, the same on every run with the same base) could hand back a
// previous run's report, or one planted there, whenever this run wrote none.
// `ignore`: .gitleaksignore entries of this run's own, read beside the checkout's (collectGitleaks).
function gitleaksRun(leg, extraArgs, { env: runEnv, ignore = [], what = 'gitleaks' } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-gitleaks-'));
  try {
    const report = path.join(dir, 'report.json');
    const args = ['detect', '--redact', '--no-banner', '--report-format', 'json', '--report-path', report, '--exit-code', '0', ...extraArgs];
    if (ignore.length) {
      fs.writeFileSync(path.join(dir, 'merges.gitleaksignore'), `${ignore.join('\n')}\n`);
      args.push('--gitleaks-ignore-path', path.join(dir, 'merges.gitleaksignore'));
    }
    const r = run(BIN.gitleaks, args, { timeout: 300000, ...(runEnv ? { env: runEnv } : {}) });
    let text = null;
    try { text = fs.readFileSync(report, 'utf8'); } catch { /* never written: gitleaksOutcome says why */ }
    const o = gitleaksOutcome(r, text);
    if (!o.looked) couldNotLook(leg, `${what} ${o.reason}`);
    return o.results;
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}
// Where a finding was introduced. gitleaks reads commit patches, so its file:line is the line in
// THAT commit — under scan-scope: full, often not the tip's (the literal may have moved since).
const inCommit = (f) => (shortSha(f.Commit) ? ` in commit ${shortSha(f.Commit)}` : '');
function collectGitleaks() {
  const out = [];
  const legs = [LEGS.gitleaks, ...(ENABLE_HISTORY ? [LEGS.gitleaksHistory] : [])];
  if (!have(BIN.gitleaks)) { for (const leg of legs) couldNotLook(leg, 'gitleaks not installed'); return out; }
  // gitleaks reads git history, and outside a repository it exits 0 with `[]` — clean, having read
  // nothing. (A diff range git cannot resolve does the same; the changed-file list faults on it first.)
  if (sh(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']) === '') {
    for (const leg of legs) couldNotLook(leg, 'no git history here — not a git repository, or no commit — so gitleaks would read nothing');
    return out;
  }
  const inHistory = (f) => ({ checkId: 'secrets-history', tool: 'gitleaks', rule: f.RuleID || 'secret', file: f.File, line: f.StartLine || 0, commit: f.Commit, msg: `${f.RuleID || 'secret'} in history (${redact(f.Secret)})${inCommit(f)} — rotate at the provider, then scrub history`, cwe: 'CWE-798' });
  // T0 — diff range (today's block). `--log-opts BASE..HEAD` is `git log`'s range, and past a clock
  // skew git lists commits the base already holds in it (baseHolds, below). What gitleaks found in one
  // of those is pre-existing, so it is secrets-history and never blocks (v1.19.8). A finding with no
  // commit counts as the change's own, and so does one whose ancestry git cannot tell: that blocks,
  // and the leg could not look.
  const scoped = DIFF && BASE;
  const diff = gitleaksRun(LEGS.gitleaks, scoped ? ['--log-opts', `${BASE}..HEAD`] : []);
  // …and what the range's merges add (mergePass), in a run of its own: each pass commit named with its
  // parent excluded, so the log prints it alone, read from the clone that holds it. gitleaks 8.30.1
  // exits 0 with `[]` when its `git log` dies ("0 commits scanned", said only in its log), so the same
  // log runs here first, its output discarded (any size): a pass commit gitleaks could not read is a
  // fault, never a PASS, and the range's own run above cannot be blinded by one.
  const own = new Map();
  if (scoped) {
    const mp = mergePass();
    if (mp.reason) couldNotLook(LEGS.gitleaks, mp.reason);
    if (mp.pairs.length) {
      const opts = mp.pairs.flatMap((p) => [p.tip, `^${p.since}`]);
      const passEnv = { ...env, GIT_ALTERNATE_OBJECT_DIRECTORIES: [mp.objects, env.GIT_ALTERNATE_OBJECT_DIRECTORIES].filter(Boolean).join(path.delimiter) };
      const pre = run('git', ['log', '-p', '-U0', '--format=%H', ...opts], { env: passEnv, timeout: 300000, stdio: ['ignore', 'ignore', 'pipe'] });
      if (pre.status !== 0 || pre.error || pre.signal) couldNotLook(LEGS.gitleaks, `what the range's merges add could not be read by gitleaks: git log of the pass's commits failed, exit ${pre.status}${errorLine(pre.stderr) ? `: ${scrub(errorLine(pre.stderr))}` : ''}`);
      else {
        for (const p of mp.pairs) own.set(p.tip, p.merge);
        diff.push(...gitleaksRun(LEGS.gitleaks, ['--log-opts', opts.join(' ')], { env: passEnv, ignore: pinnedToMerges(mp.pairs), what: "gitleaks, on what the range's merges add," }));
      }
    }
  }
  const past = new Set();
  let pastFindings = 0;
  for (const f of diff) {
    // A pass commit exists only in the clone: it is named, and asked about, as its merge.
    const merge = own.get(f.Commit);
    const id = String(merge || f.Commit || '').toLowerCase();
    const holds = scoped && isSha(id) ? baseHolds(id) : false;
    if (holds && holds.reason) couldNotLook(LEGS.gitleaks, holds.reason);
    if (holds === true) { past.add(id); pastFindings++; out.push(inHistory({ ...f, Commit: merge || f.Commit })); continue; }
    out.push({ checkId: 'secret-pattern', tool: 'gitleaks', rule: f.RuleID || 'secret', file: f.File, line: f.StartLine || 0, commit: merge || f.Commit, msg: `${f.RuleID || 'secret'} (${redact(f.Secret)})${merge ? ownChanges(merge) : inCommit(f)}`, cwe: 'CWE-798' });
  }
  if (past.size) infra.push(`gitleaks: its range listed ${past.size === 1 ? 'a commit' : `${past.size} commits`} the base already holds, as git does past a clock skew, so the ${pastFindings === 1 ? 'finding there is' : `${pastFindings} findings there are`} pre-existing: secrets-history, not secret-pattern`);
  // T2 — full-history baseline (WARN; never blocks). Dedup against the diff hits by file+rule.
  if (ENABLE_HISTORY) {
    const seen = new Set(diff.map((f) => `${f.File}:${f.RuleID}`));
    for (const f of gitleaksRun(LEGS.gitleaksHistory, [])) {
      const k = `${f.File}:${f.RuleID}`; if (seen.has(k)) continue; seen.add(k);
      out.push(inHistory(f));
    }
  }
  return out;
}

// ---------- trufflehog (verified-live secrets) ----------
const isSha = (s) => /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(s);
// The commits the verified probe walks, handed over as commit ids, never as ref names.
// trufflehog does not scan a range. It clones `file://.` (it does not trust this checkout's git
// config), walks `git log` in that clone from --branch (from every ref without it), newest commit
// date first, and stops at --since-commit. Both halves failed every pull_request run (v1.19.6):
//   - A ref NAME resolves in trufflehog's clone, not here. actions/checkout leaves a PR detached on
//     refs/remotes/pull/N/merge with no local branch, and the clone files every ref of the checkout
//     under refs/remotes/origin/ (origin/main arrives as refs/remotes/origin/remotes/origin/main).
//     So `origin/main`, the PR base, never resolved: exit 0 having scanned nothing until v1.19.0, a
//     FAULT on every PR run since.
//   - Walked from that test merge, the base branch's tip comes before every PR commit dated earlier
//     than it, so a PR behind its base would scan nothing and pass. Walked from the PR's own head,
//     the stop is where the PR left its base: exactly the PR's commits when its branch is linear.
// Off a pull_request (a push, a dispatch, a local run) the walk starts at HEAD.
// One walk covers the range only while it is linear (v1.19.7). Past a merge it holds both parents
// and takes the newer first, so it reaches its stop before the other side's commits dated earlier:
// the commits of a PR branch that merged its base in, and on a push those of a branch merged onto
// the base. Measured on the fleet's runs since each caller adopted the gate, 19 of the 56 whose
// range held a merge skipped commits. So the range is walked from every segment tip: the head, and
// each in-range parent of an in-range merge, each back to where it left the base. A walk holds one
// commit, and so cannot stop, until it reaches its first merge or leaves the range, and every
// commit of the range sits on such a run below some tip: together the walks cover the range
// whatever the dates. gitleaks' `BASE..HEAD` range, the T0 pattern floor, is the same range.
// Where the range ends, shared with mergePass (once a run): the PR's own head when the checkout holds
// it, else HEAD. Past a pull_request's PR head, HEAD is GitHub's test merge, never the author's.
let headOfRange = null;
function rangeHead() {
  if (headOfRange) return headOfRange;
  let head = '', note = '';
  const pr = String(env.PR_HEAD_SHA || '').trim().toLowerCase();
  if (isSha(pr)) {
    if (run('git', ['merge-base', '--is-ancestor', pr, 'HEAD'], { timeout: 30000 }).status === 0) head = pr;
    else note = `trufflehog: the PR head ${pr.slice(0, 7)} is not in this checkout, so the walk starts at HEAD`;
  }
  if (!head) head = sh(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  headOfRange = isSha(head) ? { head, note, testMerge: isSha(pr) && head !== pr ? head : '' } : { note, reason: 'no commit checked out to walk from' };
  return headOfRange;
}
function trufflehogRange() {
  const h = rangeHead();
  if (h.note) infra.push(h.note);
  if (h.reason) return { reason: h.reason };
  const { head } = h;
  const stopFor = (tip) => {
    const r = run('git', ['merge-base', BASE, tip], { timeout: 30000 });
    const since = r.status === 0 ? r.stdout.trim() : '';
    if (isSha(since)) return { since };
    const err = errorLine(r.stderr);
    // A git that timed out or was killed never answered, which is not "no common commit" (run()
    // reports its exit as 1, with nothing on stderr).
    const died = r.error === 'ETIMEDOUT' ? 'timed out' : r.signal ? `killed by ${r.signal}` : r.error ? safe(r.error, 40) : '';
    const why = died || (err ? `exit ${r.status}: ${scrub(err)}` : r.status === 1 ? 'they share no commit' : `exit ${r.status}`);
    return { disjoint: !died && r.status === 1 && !err, reason: `no commit to stop the walk at: git merge-base ${safe(BASE, 60)} ${tip.slice(0, 7)} failed, ${why}` };
  };
  const first = stopFor(head);
  if (first.reason) return first;
  // The range, each commit with its parents. Past a clock skew this lists some base commits too
  // (see baseHolds below), which only adds walks that stop at once.
  const r = run('git', ['rev-list', '--parents', `${BASE}..${head}`], { timeout: 60000 });
  if (r.status !== 0 || r.error || r.signal) return { reason: `git rev-list ${safe(BASE, 60)}..${head.slice(0, 7)} failed, exit ${r.status}${errorLine(r.stderr) ? `: ${scrub(errorLine(r.stderr))}` : ''}` };
  const parents = new Map(r.stdout.split('\n').filter(Boolean).map((l) => { const [c, ...ps] = l.trim().split(/\s+/); return [c, ps]; }));
  const tips = new Set([head]);
  for (const ps of parents.values()) if (ps.length > 1) for (const p of ps) if (parents.has(p)) tips.add(p);
  const walks = [{ tip: head, since: first.since }];
  for (const tip of [...tips].slice(1)) {
    // A tip that shares no commit with the base (an unrelated history merged in) has all of its
    // history in the range: it is walked to its root, with no --since-commit.
    const s = stopFor(tip);
    if (s.reason && !s.disjoint) return s;
    walks.push({ tip, since: s.since || '' });
  }
  const merges = [...parents.values()].filter((ps) => ps.length > 1).length;
  return { walks, merges };
}
// Whether the base already holds a commit, asked of git by ancestry, once per commit. The range
// list is no test for it: `git rev-list BASE..head` stops walking the base's side once that side's
// commits are dated older than everything left on the other, so past a clock skew it lists base
// commits as new (measured on git 2.54: seven base commits dated before the fork put the fork in the
// range). true or false, or the reason git could not answer.
const held = new Map();
const baseHolds = (c) => {
  if (!held.has(c)) {
    const r = run('git', ['merge-base', '--is-ancestor', c, BASE], { timeout: 30000 });
    const answered = !r.signal && !r.error && (r.status === 0 || r.status === 1);
    held.set(c, answered ? r.status === 0
      : { reason: `git merge-base --is-ancestor ${c.slice(0, 7)} ${safe(BASE, 60)} failed, ${r.signal ? `killed by ${r.signal}` : r.error ? safe(r.error, 40) : `exit ${r.status}`}${errorLine(r.stderr) ? `: ${scrub(errorLine(r.stderr))}` : ''} — so its key counts as new` });
  }
  return held.get(c);
};
// ONE clone serves every walk and the merge pass: the clone trufflehog makes of `file://.` on each
// run (same refspec), made once, on first use, and without a worktree, then named with
// --trust-local-git-config, under which trufflehog scans the repository it is given in place.
// Nothing of the checkout's git config reaches a clone, so trusting it trusts only what `git clone`
// wrote. With no index, trufflehog's staged-changes pass reads nothing, as on a clean checkout. The
// directory's name must not start with `trufflehog`: after a scan trufflehog deletes the repository
// it read when its path starts with $TMPDIR/trufflehog (its own clones' prefix; measured on
// 3.95.6), which would take the clone away from every walk after the first. It is removed when the
// scan exits: gitleaks reads the merge pass's commits in it before trufflehog runs.
// Every object a walk reads must be in the clone itself: trufflehog resolves commits in the
// repository it is given and does not read an alternate object directory (3.95.6: "unable to resolve
// commit: object not found"). So git runs for the clone without the variables that point it at other
// object stores: through an inherited alternate, git would skip an object it can already see there,
// in the clone and in the merge pass alike, and trufflehog's `git log` would die on it and exit 0.
const OWN_OBJECTS = Object.fromEntries(Object.entries(env).filter(([k]) => !/^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|COMMON_DIR)$/.test(k)));
let cloned = null;
function checkoutClone() {
  if (cloned) return cloned;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sb-trufflehog-'));
  process.on('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } });
  const clone = path.join(dir, 'repo');
  const c = run('git', ['clone', '--quiet', '--no-checkout', '-c', 'remote.origin.fetch=+refs/*:refs/remotes/origin/*', `file://${process.cwd()}`, clone], { timeout: 300000, env: OWN_OBJECTS });
  cloned = c.status !== 0 || c.error || c.signal
    ? { reason: `git clone of the checkout for trufflehog failed, exit ${c.status}${errorLine(c.stderr) ? `: ${scrub(errorLine(c.stderr))}` : ''}` }
    : { clone };
  return cloned;
}
function walkRange(leg, walks, flags) {
  const c = checkoutClone();
  if (c.reason) { couldNotLook(leg, c.reason); return []; }
  const results = [];
  walks.forEach((w, i) => {
    const o = trufflehogOutcome(run(BIN.trufflehog, ['git', `file://${c.clone}`, '--trust-local-git-config', ...flags, '--branch', w.tip, ...(w.since ? ['--since-commit', w.since] : [])], { timeout: 300000 }));
    if (!o.looked) couldNotLook(leg, `trufflehog${walks.length > 1 ? ` walk ${i + 1} of ${walks.length}, ${w.merge ? `of what merge ${w.merge.slice(0, 7)} adds` : `from ${w.tip.slice(0, 7)}`},` : ''} ${o.reason}`);
    results.push(...o.results);
  });
  return results;
}
function collectTrufflehog() {
  const out = [];
  if (VERIFIED_SECRETS === 'off') { infra.push('verified-secrets:off — live-credential probe disabled (gitleaks pattern floor still blocks)'); return out; }
  const scoped = DIFF && !!BASE;
  const leg = scoped ? LEGS.trufflehog : LEGS.trufflehogHistory;
  if (!have(BIN.trufflehog)) { couldNotLook(leg, 'trufflehog not installed — verified-secrets: off runs without it, on the gitleaks pattern floor'); return out; }
  // CRITICAL `secret-verified` is the DIFF-scoped check: the walks (trufflehogRange) cover the NEW
  // commits, so it can only fire on a just-added live key (never pre-existing state). When there
  // is no diff range (scan-scope:full, or an unresolved base), the verified probe widens to full
  // history — a pre-existing live key must NOT block, so those are emitted as WARN `secrets-history`
  // (loud, but a history finding can't be a merge precondition). The raw value of a LIVE secret is
  // NEVER printed (not even redacted) — detector + file:line is enough.
  // --fail-on-scan-errors: without it, a scan that failed inside (a --since-commit it cannot
  // resolve) exits 0, having scanned nothing.
  const flags = ['--only-verified', '--no-update', '--json', '--fail-on-scan-errors'];
  let range = null, results;
  const own = new Map();
  if (scoped) {
    range = trufflehogRange();
    if (range.reason) { couldNotLook(leg, range.reason); return out; }
    if (range.walks.length > 1) infra.push(`trufflehog: the range holds ${range.merges} merge${range.merges === 1 ? '' : 's'}, so it was walked from ${range.walks.length} segment tips, each back to where it left the base${range.walks.some((w) => !w.since) ? ', or to its root where it shares no commit with the base' : ''}`);
    const c = checkoutClone();
    if (c.reason) { couldNotLook(leg, c.reason); return out; }
    // What the range's merges add: one more walk each, of the pass's one commit (mergePass).
    const mp = mergePass();
    if (mp.reason) couldNotLook(leg, mp.reason);
    for (const p of mp.pairs) own.set(p.tip, p.merge);
    results = walkRange(leg, [...range.walks, ...mp.pairs.map(({ tip, since, merge }) => ({ tip, since, merge }))], flags);
  } else {
    const o = trufflehogOutcome(run(BIN.trufflehog, ['git', 'file://.', ...flags], { timeout: 300000 }));
    if (!o.looked) couldNotLook(leg, `trufflehog ${o.reason}`);
    results = o.results;
  }
  const seen = new Set();
  for (const obj of results) {
    if (obj.Verified !== true) continue;
    const g = (obj.SourceMetadata && obj.SourceMetadata.Data && obj.SourceMetadata.Data.Git) || {};
    // A line of the merge pass's commit is the merge's own: it is named, and graded, as the merge.
    const merge = own.get(String(g.commit || '').toLowerCase());
    const commit = merge || g.commit;
    // Two walks that meet report the commits they share twice.
    const key = [g.commit, g.file, g.line, obj.DetectorName].join('\n');
    if (seen.has(key)) continue;
    seen.add(key);
    // A walk stops at a commit the base holds, but only once it gets there: a skewed commit date, or
    // a second merge base, can take it through older base commits first. What it found in a commit
    // the base holds is pre-existing, so it warns and never blocks. A finding without a commit id
    // counts as the change's own (trufflehog names staged content `Staged`; a clone with no index has
    // none), and so does one whose ancestry git could not tell: that blocks, and the leg could not look.
    // A pass commit exists only in the clone: it is asked about as its merge, which the checkout holds.
    const id = String(commit || '').toLowerCase();
    const holds = scoped && isSha(id) ? baseHolds(id) : false;
    if (holds && holds.reason) couldNotLook(leg, holds.reason);
    const fresh = scoped && holds !== true;
    out.push({
      checkId: fresh ? 'secret-verified' : 'secrets-history', tool: 'trufflehog', rule: obj.DetectorName || 'secret',
      file: g.file || '(history)', line: g.line || 0, commit, cwe: 'CWE-798',
      msg: `🔴 VERIFIED-LIVE ${obj.DetectorName || 'secret'}${merge ? ownChanges(merge) : shortSha(g.commit) ? ` in commit ${shortSha(g.commit)}` : ''} — ROTATE NOW${fresh ? '' : ' (pre-existing in history — WARN, not a block; rotate then scrub history)'}`,
    });
  }
  return out;
}

// ---------- what a merge commit adds (v1.20.0) ----------
// Both secret legs read commits as `git log -p` prints them, gitleaks over `BASE..HEAD` and trufflehog
// on each walk, and `git log -p` prints no patch for a merge. So what only a merge commit adds, a
// conflict resolution or an edit made while merging, was read by neither: measured on gitleaks 8.30.1
// and trufflehog 3.95.6, beside a control commit both reported. Of the 76 merges the 11 callers made
// after adopting the gate, 17 added lines found in neither parent (673 lines, on 5 callers).
// Each in-range merge is merged again from its parents, in the checkout's clone, by `git merge-tree
// --write-tree`: git's own merge, conflict markers and all (an octopus one head at a time onto the
// merge of those before it, as git's octopus strategy merges). A merge whose tree differs from that
// re-merge is handed to both legs as ONE ordinary commit, whose parent holds the re-merge and whose
// tree is the merge's. Its patch is what `git show --remerge-diff` prints for the merge, and never
// either parent's commits: a finding in it is the merge's own, new in the range, and blocks.
//   - Why not `--remerge-diff` itself: gitleaks' parser stops at the `remerge CONFLICT` header lines
//     and names each conflicted file `b/<path>`, which path allowlists and .gitleaksignore entries
//     match on, and an octopus merge gets no patch at all. trufflehog takes no log options.
//   - Why in the clone: trufflehog walks it, and sees only the objects it holds (OWN_OBJECTS); git
//     writes into it whatever it lacks. gitleaks' git reads the clone as an alternate.
//   - GitHub's test merge is never merged again: it is GitHub's own, and where its result differed
//     from git's, the parents' lines would be handed over as the merge's.
const PASS_ID = {
  GIT_AUTHOR_NAME: 'security-baseline', GIT_AUTHOR_EMAIL: 'security-baseline@invalid', GIT_AUTHOR_DATE: '@0 +0000',
  GIT_COMMITTER_NAME: 'security-baseline', GIT_COMMITTER_EMAIL: 'security-baseline@invalid', GIT_COMMITTER_DATE: '@0 +0000',
};
let mergesRead = null;
function mergePass() {
  if (mergesRead) return mergesRead;
  const done = (o) => (mergesRead = { pairs: [], ...o });
  const h = rangeHead();
  if (h.reason) return done({ reason: h.reason });
  const r = run('git', ['rev-list', '--merges', '--parents', `${BASE}..${h.head}`], { timeout: 60000 });
  if (r.status !== 0 || r.error || r.signal) return done({ reason: `git rev-list --merges ${safe(BASE, 60)}..${h.head.slice(0, 7)} failed, exit ${r.status}${errorLine(r.stderr) ? `: ${scrub(errorLine(r.stderr))}` : ''}` });
  // `git rev-list BASE..head` lists commits the base holds past a clock skew (see baseHolds): a merge
  // the base already holds is pre-existing, and what it added is never read as new.
  const merges = r.stdout.split('\n').filter(Boolean).map((l) => l.trim().split(/\s+/)).filter(([m]) => m !== h.testMerge && baseHolds(m) !== true);
  if (!merges.length) return done({});
  const lost = (why) => done({ reason: `what ${merges.length === 1 ? "the range's merge adds" : `the range's ${merges.length} merges add`} could not be read: ${why}` });
  const c = checkoutClone();
  if (c.reason) return lost(c.reason);
  const git = (args, opts = {}) => run('git', args, { cwd: c.clone, env: { ...OWN_OBJECTS, ...PASS_ID }, timeout: 300000, ...opts });
  const failure = (res, what) => `${what} failed, exit ${res.status}${errorLine(res.stderr) ? `: ${scrub(errorLine(res.stderr))}` : ''}`;
  const commitTree = (tree, parents, msg) => {
    const res = git(['commit-tree', '--no-gpg-sign', tree, ...parents.flatMap((p) => ['-p', p]), '-m', msg]);
    const sha = res.stdout.trim();
    return res.status === 0 && !res.signal && isSha(sha) ? { sha } : { reason: failure(res, 'git commit-tree') };
  };
  const pairs = [];
  for (const [merge, ...parents] of merges) {
    let at = parents[0], tree = '';
    for (let i = 1; i < parents.length; i++) {
      // Exit 1 is a merge with conflicts, its markers in the tree; above that, git could not merge.
      const m = git(['merge-tree', '--write-tree', '--no-messages', '--allow-unrelated-histories', at, parents[i]]);
      tree = (m.stdout.split('\n')[0] || '').trim();
      if (m.status > 1 || m.error || m.signal || !isSha(tree)) return lost(failure(m, `git merge-tree for merge ${merge.slice(0, 7)}`));
      if (i < parents.length - 1) {
        const step = commitTree(tree, [at, parents[i]], `security-baseline: octopus step of ${merge}`);
        if (step.reason) return lost(step.reason);
        at = step.sha;
      }
    }
    const mine = git(['rev-parse', '--verify', '--quiet', `${merge}^{tree}`]);
    if (!isSha(mine.stdout.trim())) return lost(failure(mine, `git rev-parse ${merge.slice(0, 7)}^{tree}`));
    if (mine.stdout.trim() === tree) continue;   // nothing git's own merge lacks
    const since = commitTree(tree, [], `security-baseline: git's own merge of ${merge}'s parents`);
    if (since.reason) return lost(since.reason);
    const tip = commitTree(mine.stdout.trim(), [since.sha], `security-baseline: what ${merge} adds`);
    if (tip.reason) return lost(tip.reason);
    pairs.push({ merge, tip: tip.sha, since: since.sha });
  }
  // trufflehog exits 0 having read nothing when its `git log` dies on an object it lacks (3.95.6,
  // --fail-on-scan-errors or not): the log it runs is run here first on every pass commit, its
  // output discarded (any size).
  if (pairs.length) {
    const log = git(['log', '-p', '-U0', '--format=%H', ...pairs.flatMap((p) => [p.tip, `^${p.since}`])], { stdio: ['ignore', 'ignore', 'pipe'] });
    if (log.status !== 0 || log.error || log.signal) return lost(failure(log, "git log of the pass's commits"));
  }
  const n = merges.length, k = pairs.length;
  const held = `merges: the range holds ${n} merge${n === 1 ? '' : 's'}`;
  infra.push(k === 0 ? `${held}, and ${n === 1 ? 'it adds nothing' : 'none adds anything'} to git's own merge of ${n === 1 ? 'its' : 'their'} parents`
    : `${held}; ${n === 1 ? 'it adds' : k === 1 ? '1 adds' : `${k} add`} lines of ${k === 1 ? 'its' : 'their'} own, a conflict resolution or an edit made while merging, read as one commit ${k === 1 ? '' : 'each '}from git's own merge of the parents to the merge`);
  return done({ pairs, objects: path.join(c.clone, '.git', 'objects') });
}
// gitleaks pins a finding to the commit it read the line in: for a merge's own lines, the pass's
// commit, never the merge. So an entry of the checkout's .gitleaksignore pinned to one of the range's
// merges (`<merge>:<file>:<rule-id>:<line>`, the fleet's only form) is pinned again to that commit,
// read as gitleaks 8.30.1 reads the file: each line trimmed, `#` a comment, four fields a commit's.
function pinnedToMerges(pairs) {
  let text = '';
  try { text = fs.readFileSync('.gitleaksignore', 'utf8'); } catch { return []; }
  const tipOf = new Map(pairs.map((p) => [p.merge, p.tip]));
  const out = [];
  for (const raw of text.split('\n')) {
    const l = raw.trim();
    if (!l || l.startsWith('#')) continue;
    const s = l.split(':');
    if (s.length === 4 && tipOf.has(s[0])) out.push([tipOf.get(s[0]), ...s.slice(1)].join(':'));
  }
  return out;
}
const ownChanges = (merge) => ` in merge ${shortSha(merge)}'s own changes`;

// ---------- osv-scanner (dependency / SCA) ----------
// osv-scanner v2 emits results[].packages[].groups[] with a computed numeric `max_severity`
// (CVSS, e.g. "9.2") — one group per vuln/alias cluster. Tier by that score; never block (WARN).
function scaCheckId(score) {
  if (score >= 9.0) return 'sca-critical';
  if (score >= 7.0) return 'sca-high';
  if (score >= 4.0) return 'sca-moderate';
  if (score > 0) return 'sca-low';
  return 'sca-high'; // no CVSS → conservative WARN (still non-blocking)
}
// The npm and composer lockfile names deps-currency looks for (its LOCK_NAMES): the fleet's ecosystems.
const LOCKFILE_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'composer.lock']);
function collectOsv() {
  const out = [];
  if (!ENABLE_SCA) return out;
  if (!have(BIN.osv)) { couldNotLook(LEGS.osv, 'osv-scanner not installed — enable-sca: false runs without it'); return out; }
  // The tracked npm/composer lockfiles, so that an exit 128 with one osv-scanner did not read is not
  // taken for a tree with nothing to audit. node_modules is left out because osv-scanner skips it
  // too. A failed listing leaves the list empty: only osv's own extraction error then speaks.
  const ls = run('git', ['ls-files', '-z'], { timeout: 30000 });
  const lockfiles = ls.status === 0 && !ls.error
    ? ls.stdout.split('\0').filter((f) => LOCKFILE_NAMES.has(path.basename(f)) && !/(^|\/)node_modules\//.test(f))
    : [];
  const root = process.cwd();   // getcwd() resolves symlinks, as the paths osv-scanner prints do
  const o = osvOutcome(run(BIN.osv, ['scan', 'source', '--recursive', '--format', 'json', '.'], { timeout: 300000 }), { lockfiles, root });
  if (!o.looked) couldNotLook(LEGS.osv, `osv-scanner ${o.reason}`);
  for (const res of o.results) {
    const src = (res.source && res.source.path) || '';
    for (const pkg of (res.packages || [])) {
      const name = (pkg.package && pkg.package.name) || '?';
      const ver = (pkg.package && pkg.package.version) || '?';
      for (const g of (pkg.groups || [])) {
        const score = parseFloat(g.max_severity || '0') || 0;
        const ids = (g.ids || []).slice(0, 3).join(', ');
        out.push({ checkId: scaCheckId(score), tool: 'osv-scanner', rule: ids, file: src, line: 0, msg: `${name}@${ver} — ${ids}${score ? ` (CVSS ${score})` : ' (no CVSS)'} — present-in-tree, reachability unknown`, cwe: 'CWE-1395' });
      }
    }
  }
  return out;
}

// ---------- hadolint (Dockerfile lint — conditional) ----------
function collectHadolint() {
  const out = [];
  const dfChanged = DIFF ? (CHANGED || []).filter((f) => /(^|\/)Dockerfile(\.|$)|\.dockerfile$/i.test(f) && fs.existsSync(f)) : [];
  let targets = dfChanged;
  if (!DIFF) {
    const ls = run('git', ['ls-files'], { timeout: 30000 });
    if (ls.status !== 0 || ls.error) { couldNotLook(LEGS.hadolint, `git ls-files failed, exit ${ls.status} — no Dockerfile was listed`); return out; }
    targets = ls.stdout.split('\n').filter((f) => /(^|\/)Dockerfile(\.|$)/i.test(f) && fs.existsSync(f)).slice(0, 20);
  }
  if (targets.length === 0) return out;
  if (!have(BIN.hadolint)) { couldNotLook(LEGS.hadolint, 'hadolint not installed, with a Dockerfile in scope'); return out; }
  for (const df of targets) {
    const o = hadolintOutcome(run(BIN.hadolint, ['--format', 'json', df], { timeout: 60000 }));
    if (!o.looked) couldNotLook(LEGS.hadolint, `hadolint ${o.reason} on ${safe(df, 80)}`);
    for (const h of o.results) if (h.level === 'error' || h.level === 'warning') out.push({ checkId: 'dockerfile-lint', tool: 'hadolint', rule: h.code || '', file: df, line: h.line || 0, msg: `${h.code}: ${h.message}`, cwe: 'CWE-1395' });
  }
  return out;
}

// ---------- argv-secret (a secret spelled into a child's argv) — zero egress ----------
// The matcher is argv-secret.mjs, shared with this repo's own lint. Scripts are graded on the diff
// (or the whole tree), like the custom rule packs; `.github` YAML on EVERY run, like gha.yaml: a
// workflow is small, rarely edited, and a leak there runs on every push, so a diff-only pass would
// never report one that predates the check. Only tracked files are read. A tree it cannot list, or a
// file it cannot read, is a scanner note — never a silent "clean" for what it did not see.
function collectArgvSecret() {
  const out = [];
  const ls = run('git', ['ls-files', '-z'], { timeout: 30000 });
  if (ls.status !== 0 || ls.error) { couldNotLook(LEGS.argvSecret, `git ls-files failed, exit ${ls.status} — no file was graded for secrets in argv`); return out; }
  const tracked = ls.stdout.split('\0').filter(Boolean);
  const headOf = (f) => {
    try {
      const fd = fs.openSync(f, 'r');
      try { const b = Buffer.alloc(256); return b.subarray(0, fs.readSync(fd, b, 0, 256, 0)).toString('utf8'); } finally { fs.closeSync(fd); }
    } catch { return ''; }
  };
  const targets = argvTargets({ changed: DIFF ? CHANGED : null, tracked, headOf });
  if (targets.length === 0) infra.push('argv-secret: nothing in scope to grade — no changed script and no .github YAML');
  let unread = 0, big = 0;
  for (const { file, lang } of targets) {
    let src;
    try {
      const st = fs.lstatSync(file);
      if (!st.isFile()) continue;   // a tracked symlink is not followed out of the tree
      if (st.size > 2 * 1024 * 1024) { big++; continue; }
      src = fs.readFileSync(file, 'utf8');
    } catch { unread++; continue; }
    if (src.includes('\0')) continue;   // binary, not a script
    for (const hit of findArgvSecrets(src, lang)) out.push(argvFinding(file, hit));
  }
  if (unread) infra.push(`argv-secret: ${unread} file(s) could not be read — not graded`);
  if (big) infra.push(`argv-secret: ${big} file(s) over 2 MB skipped — not graded`);
  return out;
}

// Report lines already echoed to the job log, so the crash path's re-flush echoes only the new ones.
// The log goes first: when the summary write is what throws, the report is already readable.
let echoed = 0;
function flush() {
  for (; echoed < lines.length; echoed++) say(lines[echoed]);
  if (summaryFile) fs.appendFileSync(summaryFile, lines.join('\n') + '\n');
}

// ============================ main ============================
(async () => {
  note('## 🔒 security-baseline — air-gapped SAST · secrets · SCA · supply-chain');
  note('');
  note(`- mode: ${REPORT_MODE ? '**⚠️ REPORT-MODE — NOT enforcing**' : (FAIL_ON_CRITICAL ? '**BLOCK on critical**' : 'report-only')}`);
  note(`- scope: ${DIFF ? `diff (\`${safe(BASE)}\`…HEAD, ${CHANGED ? CHANGED.length : 0} changed file(s))` : 'full tree'}`);
  if (promote.length) note(`- promoted to critical (this caller): \`${promote.join('`, `')}\``);
  if (ignored.length) note(`- ⚠️ ignored \`critical-checks\` (not promotable T1 ids): \`${ignored.join('`, `')}\``);
  // Print the owner set: "why is MY org's action not flagged?" (and its inverse) must be answerable
  // from the report alone, without reading the source of the filter that made the decision.
  if (FIRST_PARTY.size) note(`- first-party owners (exempt from \`gha-unpinned-action\`): \`${[...FIRST_PARTY].map((o) => safe(o, 40)).join('`, `')}\``);
  note('');

  // Each collector with the legs it runs. A collector that throws looked at nothing it had not
  // already returned, so its legs could not look: a crash is never a quiet scanner note.
  const collectors = [
    [collectSemgrep, [LEGS.community, LEGS.custom, LEGS.gha]],
    [collectGitleaks, [LEGS.gitleaks, ...(ENABLE_HISTORY ? [LEGS.gitleaksHistory] : [])]],
    [collectTrufflehog, VERIFIED_SECRETS === 'off' ? [] : [DIFF && BASE ? LEGS.trufflehog : LEGS.trufflehogHistory]],
    [collectOsv, ENABLE_SCA ? [LEGS.osv] : []],
    [collectHadolint, [LEGS.hadolint]],
    [collectArgvSecret, [LEGS.argvSecret]],
  ];
  let findings = [];
  for (const [collect, legs] of collectors) {
    try { findings = findings.concat(collect()); } catch (e) {
      for (const leg of legs) couldNotLook(leg, `${collect.name} crashed: ${scrub(String(e && e.message || e), 120)}`);
    }
  }

  const { graded, crit, warn, info, blocked } = evaluate(findings, { failOnCritical: FAIL_ON_CRITICAL, reportMode: REPORT_MODE, promote });
  // The legs that could not look AND could have found a CRITICAL here: they take the verdict away.
  const blind = faults.filter((f) => canBeCritical(f.leg.checks, promote));
  const faulted = blind.length > 0 && FAIL_ON_CRITICAL && !REPORT_MODE;

  // ---- report, grouped by check, criticals first ----
  const groups = [...groupByCheck(graded)].sort((a, b) => sevRank(baseOf(a[1])) - sevRank(baseOf(b[1])));
  if (graded.length === 0) {
    note(faults.length ? '- no findings from the scanners that looked — the legs that could not are listed below.' : '- ✅ no findings across SAST, secrets, SCA, and CI supply-chain.');
    note('');
  } else {
    for (const [checkId, fs_] of groups) {
      const sev = fs_[0].sev;
      const tier = (CHECKS[checkId] || { tier: 'T1' }).tier;
      note(`### ${ICON[sev] || ICON.warn} \`${safe(checkId, 60)}\` · ${tier} · ${fs_.length} finding(s)`);
      for (const f of fs_.slice(0, 15)) note(`- ${ICON[f.sev] || ICON.warn} ${safe(f.file)}${Number.isFinite(+f.line) && +f.line > 0 ? ':' + (+f.line) : ''} — ${safe(f.msg, 220)}${f.cwe ? ` _(${safe(f.cwe, 40)})_` : ''}`);
      if (fs_.length > 15) note(`- …and ${fs_.length - 15} more`);
      note('');
    }
  }
  // ❌ a leg that could have produced a CRITICAL for this caller; ⚠️ one whose checks only warn here.
  if (faults.length) {
    note(`### ${blind.length ? ICON.critical : ICON.warn} could not look · ${faults.length} scanner leg(s) — a tool fault, not a finding`);
    for (const f of faults) {
      const can = blind.includes(f);
      note(`- ${can ? ICON.critical : ICON.warn} ${safe(f.leg.name, 80)} — ${safe(f.reason, 240)}${can ? '' : ' (its checks only warn for this caller: reported, not a fault)'}`);
    }
    note('');
  }
  if (infra.length) { note('### ℹ️ scanner notes'); infra.forEach((m) => note(`- ${safe(m, 240)}`)); note(''); }

  note(`**critical: ${crit} · warnings: ${warn} · info: ${info}${faults.length ? ` · could not look: ${faults.length}` : ''}**`);
  // Every verdict leaves through here: the report, then one annotation per leg that could not look
  // and could have blocked, then one per CRITICAL — `::error` when this run exits non-zero,
  // `::warning` when it only reports (report-mode, fail-on-critical: false).
  const level = blocked || faulted ? 'error' : 'warning';
  const finish = (code) => {
    flush();
    if (ANNOTATE) {
      const lost = blind.map((f) => faultAnnotation(f.leg.name, f.reason, level));
      for (const a of [...lost, ...annotations(graded, level, Math.max(0, 10 - lost.length))]) say(a);
    }
    process.exit(code);
  };
  const blindly = `${blind.length} scanner leg(s) that could have blocked could not look (${blind.map((f) => f.leg.name).join(', ')})`;
  if (REPORT_MODE && (crit > 0 || blind.length)) {
    if (crit > 0) note(`⚠️ REPORT-MODE — ${crit} critical finding(s) would BLOCK if enforcing. ${safe(env.REPORT_MODE_REASON || '')}`);
    if (blind.length) note(`⚠️ REPORT-MODE — ${blindly}; enforcing, this run would FAULT.`);
    finish(0);
  }
  if (blocked) {
    note(`BLOCKED — ${crit} critical finding(s). Fix the ❌ items, or waive with documented rationale.`);
    if (blind.length) note(`…and ${blindly}, so the list above may be incomplete.`);
    finish(1);
  }
  if (faulted) { note(`FAULT — ${blindly}. No verdict: a tool fault in security-baseline, not a finding about this repository.`); finish(1); }
  if (crit > 0) note(`report-only — ${crit} critical finding(s) would BLOCK under \`fail-on-critical: true\`.`);
  if (blind.length) note(`report-only — ${blindly}; under \`fail-on-critical: true\` this run would FAULT.`);
  if (!crit && !blind.length) note(`PASS — no critical findings.${faults.length ? ` ${faults.length} scanner leg(s) that only warn here could not look (above).` : ''}`);
  finish(0);
})().catch((e) => {
  note(`- ❌ security-baseline crashed: ${safe(String(e && e.stack || e), 400)}`);
  // flush() echoes to the log before it touches the summary, so when the summary sink is what failed,
  // this line still reaches the log — and the exit stays the caller's setting, not an unhandled throw.
  try { flush(); } catch { /* summary sink unwritable; the job log already has the report */ }
  process.exit(FAIL_ON_CRITICAL && !REPORT_MODE ? 1 : 0);
});

function baseOf(arr) { return arr[0] ? arr[0].sev : SEV.WARN; }
