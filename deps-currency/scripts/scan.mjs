// deps-currency CLI — the TIME-axis dependency check. Discovers the FULL committed lockfiles
// (npm/pnpm/composer), runs osv-scanner over each (NOT diff-scoped — that's security-baseline's
// job), parses + floor-filters the advisories via the pure engine, also flags unpinned third-party
// GitHub Actions that consume secrets, renders one report, optionally opens/auto-closes a
// 'dependency advisories' tracking issue (linkcheck's lifecycle), reporting the outcome, and exits
// non-zero ONLY under fail-on-vuln=true: when a >=floor advisory exists, or when osv-scanner could
// not look (engine.mjs osvOutcome) — a FAULT, never a PASS, and never a reason to open or close the
// issue. The report goes to the job log as well as the step summary, and each >=floor advisory is
// annotated (`::error file=<lockfile>,title=…::…`).
//
// EGRESS (honest enumeration — see README §Sovereignty): NO lockfile body leaves the runner.
//   - osv-scanner: sends package COORDINATES (name@version) to osv.dev — never your lockfile body.
//     This is the same documented, opt-out-able egress security-baseline's SCA uses; mirror its
//     honesty. Run on a self-hosted runner with an offline OSV DB to remove it (roadmap).
//   - gh issue ops: GitHub API on github.token — the issue body is your own report.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  parseOsv, osvOutcome, filterByFloor, scanUnpinnedActions, resolveFirstPartyOwners, issueDecision,
  blockDecision, renderReport, normalizeFloor, safe, repoRelative, annotations, faultAnnotation,
} from './engine.mjs';

const env = process.env;
const WORKDIR = path.resolve(env.WORKING_DIRECTORY || '.');
const ECOSYSTEMS = (env.ECOSYSTEMS || 'auto').trim().toLowerCase();
const FLOOR = normalizeFloor(env.SEVERITY_FLOOR || 'HIGH');
const MANAGE_ISSUE = (env.MANAGE_ISSUE || 'true').trim() !== 'false';
const FAIL_ON_VULN = (env.FAIL_ON_VULN || 'false').trim() === 'true';
const OSV_BIN = env.OSV_BIN || 'osv-scanner';
const GH_BIN = env.GH_BIN || 'gh';
const ISSUE_TITLE = env.ISSUE_TITLE || 'deps-currency: dependency advisories';

const WORKSPACE = path.resolve(env.GITHUB_WORKSPACE || '.');   // the repository root, for `file=`

// The report goes to the job LOG always, and to the step summary when there is one. The summary
// alone needs a signed-in browser: `gh run view --log-failed` showed only "exit code 1" and the
// check-run API's `output` was empty, so a headless reader learned THAT the gate blocked, never why
// (security-baseline, 2026-09-23 — ported here in v1.18.0). The log is written through fd 1, never
// by opening /dev/stdout: on Linux that open fails (ENXIO) when stdout is a socket, which is what
// node's child_process hands a child. `/dev/stdout` as the summary (a local idiom) means none.
const summaryFile = env.GITHUB_STEP_SUMMARY && env.GITHUB_STEP_SUMMARY !== '/dev/stdout' ? env.GITHUB_STEP_SUMMARY : '';
const ANNOTATE = env.GITHUB_ACTIONS === 'true';   // runner commands are for the runner, not a local run
const say = (s = '') => { try { fs.writeSync(1, `${s}\n`); } catch { console.log(s); } };
// One block of the report: the job log first, then the step summary — so when the summary write is
// what throws, the block is already readable in the log. Every line of a block starts with our text;
// tool-controlled strings (package names, advisory ids, paths) go through safe().
function emit(text) {
  say(text);
  if (summaryFile) fs.appendFileSync(summaryFile, `${text}\n`);
}
const infra = [];

// `signal` and `error` say a process never finished (a timeout, the output cap): osvOutcome reads
// them before any output. Without them a timed-out osv-scanner read as `status 1`, its findings exit.
function run(bin, args, opts = {}) {
  const t0 = Date.now();
  try {
    const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: opts.timeout || 300000, cwd: opts.cwd, ...opts });
    if (r.error && r.error.code === 'ENOENT') return { missing: true, status: 127, signal: '', error: '', ms: 0, stdout: '', stderr: '' };
    return {
      missing: false, status: r.status == null ? 1 : r.status, signal: r.signal || '', ms: Date.now() - t0,
      error: r.error ? String(r.error.code || r.error.message || r.error) : '', stdout: r.stdout || '', stderr: r.stderr || '',
    };
  } catch (e) { return { missing: false, status: 1, signal: '', error: String((e && e.message) || e), ms: Date.now() - t0, stdout: '', stderr: '' }; }
}
const have = (bin) => !run(bin, ['--version'], { timeout: 15000 }).missing;

// ---------- lockfile discovery ----------
// Each ecosystem maps to its canonical lockfile name(s). 'auto' enables an ecosystem only when its
// lockfile is present in the working dir tree (recursive, but skipping vendored/dep dirs so we read
// the committed top-level lockfiles, not nested copies inside node_modules/vendor).
const LOCK_NAMES = {
  npm: ['package-lock.json', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'yarn.lock', 'bun.lockb', 'bun.lock'],
  composer: ['composer.lock'],
};
const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', '.svn', 'dist', 'build', '.next', '.astro', '.cache']);

function findLockfiles(root, names, { maxDepth = 6 } = {}) {
  const found = [];
  const walk = (dir, depth) => {
    if (depth > maxDepth) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) { if (e.name !== '.github') continue; }
        walk(path.join(dir, e.name), depth + 1);
      } else if (e.isFile() && names.has(e.name)) {
        found.push(path.join(dir, e.name));
      }
    }
  };
  walk(root, 0);
  return found;
}

function resolveEcosystems() {
  const wantNames = new Set();
  const ecosystems = [];
  const requested = ECOSYSTEMS === 'auto'
    ? ['npm', 'composer']
    : ECOSYSTEMS.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const present = [];
  for (const eco of requested) {
    const names = LOCK_NAMES[eco];
    if (!names) { infra.push(`unknown ecosystem '${safe(eco, 24)}' — ignored (known: npm, composer)`); continue; }
    const locks = findLockfiles(WORKDIR, new Set(names));
    if (locks.length) { ecosystems.push(eco); present.push(...locks); for (const n of names) wantNames.add(n); }
    else if (ECOSYSTEMS !== 'auto') infra.push(`ecosystem '${eco}' requested but no lockfile found (${names.join(', ')})`);
  }
  // de-dup + make paths relative-to-workdir for a tidy report
  const rel = [...new Set(present)].map((f) => path.relative(WORKDIR, f) || path.basename(f));
  return { ecosystems: [...new Set(ecosystems)], lockfiles: rel };
}

// ---------- osv-scanner over the FULL tree (one recursive scan covers every lockfile) ----------
// Returns { findings, looked, reason }. `looked: false` is a scan that did not happen — not
// installed, a working directory that is not there, an osv.dev outage, a report that never came —
// and main() reads it as NO VERDICT: never PASS, never a reason to open or close the issue.
function runOsv(lockfiles) {
  if (!have(OSV_BIN)) return { findings: [], looked: false, reason: 'not installed' };
  // A missing cwd fails the spawn with ENOENT, which run() reports as the binary missing.
  if (!fs.existsSync(WORKDIR)) return { findings: [], looked: false, reason: `working-directory ${safe(env.WORKING_DIRECTORY || '.', 80)} does not exist` };
  // `scan source --recursive .` walks the working dir and audits every lockfile it finds — the FULL
  // committed tree, not a diff. We pre-discover lockfiles for the report + ecosystem gating, and so
  // that an exit 128 with a lockfile it did not read is not taken for a tree with nothing to audit;
  // osv itself does the authoritative recursive scan. osv prints real paths, hence realpath.
  let root = WORKDIR;
  try { root = fs.realpathSync(WORKDIR); } catch { /* the lockfile list still decides; only the reason's paths stay long */ }
  const o = osvOutcome(run(OSV_BIN, ['scan', 'source', '--recursive', '--format', 'json', '.'], { cwd: WORKDIR, timeout: 420000 }), { lockfiles, root });
  return { findings: parseOsv({ results: o.results }), looked: o.looked, reason: o.reason || '' };
}

// ---------- unpinned GH actions consuming secrets (over .github/workflows) ----------
function loadWorkflows() {
  const dir = path.join(WORKDIR, '.github', 'workflows');
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const out = [];
  for (const e of entries) {
    if (!e.isFile() || !/\.(ya?ml)$/i.test(e.name)) continue;
    try { out.push({ path: path.join('.github/workflows', e.name), text: fs.readFileSync(path.join(dir, e.name), 'utf8') }); } catch { /* ignore */ }
  }
  return out;
}

// ---------- issue lifecycle (gh CLI; mirrors linkcheck) ----------
// Every outcome is pushed to `infra` and printed after the report as `### ℹ️ issue lifecycle`.
// Why a gh call failed: its stderr, flattened and capped, or its exit status when it printed none. A
// workflow without `issues: write` gets GitHub's 403, "Resource not accessible by integration".
const ghFailure = (r) => safe(r.stderr.trim(), 120) || `exit ${r.status}`;
// The open tracking issue: { num } (null when none is open), or { error } when the lookup failed —
// gh refused, or printed something other than a JSON list.
function findOpenIssue(repo) {
  const r = run(GH_BIN, ['issue', 'list', '-R', repo, '--state', 'open', '--search', `${ISSUE_TITLE} in:title`, '--json', 'number,title'], { timeout: 60000 });
  if (r.status !== 0) return { error: ghFailure(r) };
  let list; try { list = JSON.parse(r.stdout); } catch { /* not JSON — a failed lookup, below */ }
  if (!Array.isArray(list)) return { error: 'gh printed no JSON list' };
  const hit = list.find((i) => i.title === ISSUE_TITLE);
  return { num: hit ? hit.number : null };
}
function manageIssue(decision, body, osvReason = '') {
  const repo = env.GITHUB_REPOSITORY;
  if (!repo) { infra.push('GITHUB_REPOSITORY unset — issue management skipped'); return; }
  if (!have(GH_BIN)) { infra.push('gh CLI not available — issue management skipped'); return; }
  const found = findOpenIssue(repo);
  // A failed lookup leaves the issue as it is, on both paths. A clean sweep cannot close an issue
  // whose number it did not get. A dirty one could still open one, and does not: with an issue
  // already open that is a duplicate, and a lookup that keeps failing would open another on every
  // dirty run, none of which a clean run could find to close. A transient failure costs one run —
  // whose report and annotations still carry every advisory — and the next run looks again.
  // Until v1.19.2 a failed lookup read as "none open": a clean sweep left the issue open without a
  // word, and a dirty one went on to `gh issue create`. linkcheck already stops here: its lookup runs
  // under `bash -eo pipefail`, so a failed `gh issue list` ends the step before it creates or closes.
  // A sweep on hold (osv-scanner could not look) would only have commented on an open issue.
  const untouched = { open: 'nothing opened or updated', close: 'nothing closed', hold: 'nothing commented' }[decision.action];
  if (found.error) { infra.push(`failed to look up the tracking issue: ${found.error} — ${untouched}`); return; }
  const num = found.num;
  const runUrl = `${env.GITHUB_SERVER_URL || 'https://github.com'}/${repo}/actions/runs/${env.GITHUB_RUN_ID || ''}`;
  const stamp = new Date().toISOString().slice(0, 10);
  if (decision.action === 'hold') {   // osv-scanner could not look: no verdict, so neither open nor close
    if (!num) { infra.push('no tracking issue opened — osv-scanner could not look, so this sweep has no verdict'); return; }
    const note = `No verdict as of ${stamp}: osv-scanner could not look — ${safe(osvReason, 200)}. This sweep neither updates nor closes this issue; it stays open until a sweep that looked comes back clean.\n\nRun: ${runUrl}`;
    const r = run(GH_BIN, ['issue', 'comment', String(num), '-R', repo, '--body', note], { timeout: 60000 });
    infra.push(r.status === 0 ? `tracking issue #${num} left open, with a comment — osv-scanner could not look, so this sweep has no verdict` : `tracking issue #${num} left open — osv-scanner could not look; the comment failed: ${ghFailure(r)}`);
    return;
  }
  if (decision.action === 'open') {
    const issueBody = `Scheduled dependency-currency sweep found advisories on **${repo}** (${stamp}).\n\nRun: ${runUrl}\n\nThis issue auto-closes when the next scheduled run is clean.\n\n${body}`;
    if (num) { const r = run(GH_BIN, ['issue', 'comment', String(num), '-R', repo, '--body', issueBody], { timeout: 60000 }); infra.push(r.status === 0 ? `updated tracking issue #${num}` : `failed to update tracking issue #${num}: ${ghFailure(r)}`); }
    else { const r = run(GH_BIN, ['issue', 'create', '-R', repo, '--title', ISSUE_TITLE, '--body', issueBody], { timeout: 60000 }); infra.push(r.status === 0 ? 'opened tracking issue' : `failed to open tracking issue: ${ghFailure(r)}`); }
  } else if (decision.action === 'close') {
    if (num) {
      run(GH_BIN, ['issue', 'comment', String(num), '-R', repo, '--body', `Resolved — the scheduled deps-currency sweep is clean (0 advisories at/above floor **${FLOOR}**) as of ${stamp}.`], { timeout: 60000 });
      const r = run(GH_BIN, ['issue', 'close', String(num), '-R', repo], { timeout: 60000 });
      infra.push(r.status === 0 ? `closed tracking issue #${num} — the sweep is clean` : `failed to close issue #${num}: ${ghFailure(r)}`);
    }
  }
}

// ============================ main ============================
// Defensive crash guard: a scan engine fault must not block a green repo unless we're an enforcing
// caller AND there were no findings to evaluate (we can't know) — so a crash exits 0 in report
// mode, 1 only under fail-on-vuln (conservative for an enforcing caller). Matches the crash
// semantics the five sibling entrypoints already ship via `(async () => {…})().catch(…)`.
//
// ORDERING IS LOAD-BEARING — this MUST stay above the `main()` invocation below. It sat BELOW it
// from the action's first commit until 2026-08-05: the IIFE is evaluated at module load and every
// path through it ends in process.exit(), so the registration was unreachable and the guard had
// never once run. A crash exited 1 unconditionally with a bare stack trace and — because the
// report is appended only at the END of main — wrote NOTHING to the step summary. Statically
// enforced now by .github/scripts/lint-entrypoint-output.mjs (crash-guard ordering rule).
process.on('uncaughtException', (e) => {
  try { emit(`\n- ❌ deps-currency crashed: ${safe(String((e && e.stack) || e), 400)}`); } catch { /* summary sink unwritable; the job log already has the line */ }
  process.exit(FAIL_ON_VULN ? 1 : 0);
});

(function main() {
  const { ecosystems, lockfiles } = resolveEcosystems();
  const osv = runOsv(lockfiles);
  const { findings, looked } = osv;
  if (!looked) infra.push(`osv-scanner could not look — ${osv.reason}`);
  const floorFindings = filterByFloor(findings, FLOOR);
  // FIRST-PARTY owner set for the unpinned-action scan — NOT just the caller's owner. This read
  // `GITHUB_REPOSITORY.split('/')[0]` until the 2026-08 ownership split (callers moved to the org
  // `creme-ypsilon`, `mvalasis/ci-actions` stayed put), after which every one of our OWN
  // `mvalasis/ci-actions/<action>@v1` refs scanned as an unpinned third-party action on every org
  // caller — pinning the tracking issue permanently open (engine.mjs, `resolveFirstPartyOwners`).
  // The action's own owner has TWO independent sources with the same documented meaning, and we
  // read both because neither is documented for the shape we run in (a composite action's own
  // step): ACTION_REPOSITORY is `${{ github.action_repository }}` passed from action.yml, and
  // GITHUB_ACTION_REPOSITORY is the runner's ambient copy — which survives only because action.yml
  // deliberately does NOT write the `GITHUB_` name and shadow it. Either being EMPTY (a local `./`
  // invocation empties both) just drops out, so the set degrades to caller-only rather than
  // exempting everything.
  const firstParty = resolveFirstPartyOwners({
    callerRepo: env.GITHUB_REPOSITORY,          // (a) e.g. creme-ypsilon/lampakia-astro
    actionRepo: env.ACTION_REPOSITORY || env.GITHUB_ACTION_REPOSITORY, // (b) e.g. mvalasis/ci-actions — '' on a local `./` ref
    extraOwners: env.FIRST_PARTY_OWNERS,        // (c) `first-party-owners` input, space/comma separated
  });
  const unpinned = scanUnpinnedActions(loadWorkflows(), firstParty);

  const report = renderReport(floorFindings, unpinned, {
    floor: FLOOR, ecosystems, lockfiles, totalFindings: findings.length, firstPartyOwners: firstParty, looked,
  });

  const lines = [report];
  if (infra.length) { lines.push('', '### ℹ️ scanner notes'); for (const m of infra) lines.push(`- ${safe(m, 240)}`); }

  const decision = issueDecision(floorFindings, unpinned, { looked });
  const blocked = blockDecision(floorFindings, { failOnVuln: FAIL_ON_VULN });
  // A sweep that could not look is a tool FAULT, under the crash guard's rule: exit 1 only under
  // fail-on-vuln, so our failure never blocks a report-mode caller and never passes an enforcing one.
  const faulted = !looked && FAIL_ON_VULN;

  lines.push('');
  lines.push(`**at/above floor: ${looked ? floorFindings.length : 'unknown — osv-scanner could not look'} · unpinned-action advisories: ${unpinned.length}**`);
  if (faulted) lines.push('FAULT — osv-scanner could not look, so the dependency tree was not audited. No verdict: a tool fault in deps-currency, not a finding about this repository.');
  else if (!looked) lines.push('report-only — osv-scanner could not look, so the dependency tree was not audited: no verdict. Under `fail-on-vuln: true` this run would FAULT.');
  else if (blocked) lines.push(`BLOCKED — ${floorFindings.length} dependency advisory(ies) at/above floor **${FLOOR}** with \`fail-on-vuln: true\`. Bump/remove the package(s), or lower the floor / document the exposure.`);
  else if (floorFindings.length > 0) lines.push(`report-only — ${floorFindings.length} advisory(ies) at/above floor would BLOCK under \`fail-on-vuln: true\`.`);
  else lines.push('PASS — no dependency advisories at or above the severity floor.');

  emit(lines.join('\n'));

  if (MANAGE_ISSUE) {
    const mark = infra.length;
    try { manageIssue(decision, report, osv.reason); } catch (e) { /* issue mgmt must never fail the run by itself */ emit(`\n- ℹ️ issue management error (non-fatal): ${safe(String((e && e.message) || e), 160)}`); }
    // manageIssue reports into `infra`, but the scanner notes above were rendered before it ran. Until
    // v1.18.1 its outcome reached neither the log nor the summary, so a caller without `issues: write`
    // got a green run, no tracking issue, and nothing saying the open failed.
    const lifecycle = infra.slice(mark);
    if (lifecycle.length) emit(['', '### ℹ️ issue lifecycle', ...lifecycle.map((m) => `- ${safe(m, 240)}`)].join('\n'));
  }

  // Last in the log: one annotation for a scan that could not look, then one per at/above-floor
  // advisory — `::error` when this run exits 1, `::warning` when it only reports (the default).
  // GitHub keeps 10 per level per step, the fault's included.
  const level = blocked || faulted ? 'error' : 'warning';
  if (ANNOTATE) {
    const located = floorFindings.map((f) => ({ ...f, file: repoRelative(f.source, { workdir: WORKDIR, workspace: WORKSPACE }) }));
    const lost = looked ? [] : [faultAnnotation(osv.reason, level)];
    for (const a of [...lost, ...annotations(located, level, 10 - lost.length)]) say(a);
  }
  process.exit(blocked || faulted ? 1 : 0);
})();
