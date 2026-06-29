// deps-currency CLI — the TIME-axis dependency check. Discovers the FULL committed lockfiles
// (npm/pnpm/composer), runs osv-scanner over each (NOT diff-scoped — that's security-baseline's
// job), parses + floor-filters the advisories via the pure engine, also flags unpinned third-party
// GitHub Actions that consume secrets, renders one report, optionally opens/auto-closes a
// 'dependency advisories' tracking issue (linkcheck's lifecycle), and exits non-zero ONLY when
// fail-on-vuln=true AND a >=floor advisory exists.
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
  parseOsv, filterByFloor, scanUnpinnedActions, issueDecision, blockDecision, renderReport,
  normalizeFloor, safe,
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

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const infra = [];

function run(bin, args, opts = {}) {
  try {
    const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: opts.timeout || 300000, cwd: opts.cwd, ...opts });
    if (r.error && r.error.code === 'ENOENT') return { missing: true, status: 127, stdout: '', stderr: '' };
    return { missing: false, status: r.status == null ? 1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  } catch (e) { return { missing: false, status: 1, stdout: '', stderr: String((e && e.message) || e) }; }
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
function runOsv() {
  if (!have(OSV_BIN)) { infra.push('osv-scanner not installed — dependency advisory scan skipped (install in the action step)'); return { findings: [], ran: false }; }
  // `scan source --recursive .` walks the working dir and audits every lockfile it finds — the FULL
  // committed tree, not a diff. We pre-discover lockfiles only for the report + ecosystem gating;
  // osv itself does the authoritative recursive scan.
  const r = run(OSV_BIN, ['scan', 'source', '--recursive', '--format', 'json', '.'], { cwd: WORKDIR, timeout: 420000 });
  if (r.missing) return { findings: [], ran: false };
  let json; try { json = JSON.parse(r.stdout || '{}'); } catch { infra.push('osv-scanner output was not valid JSON — treated as clean'); return { findings: [], ran: true }; }
  return { findings: parseOsv(json), ran: true };
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
function ghJSON(args) { const r = run(GH_BIN, args, { timeout: 60000 }); if (r.status !== 0) return null; try { return JSON.parse(r.stdout || 'null'); } catch { return null; } }
function findOpenIssue(repo) {
  const list = ghJSON(['issue', 'list', '-R', repo, '--state', 'open', '--search', `${ISSUE_TITLE} in:title`, '--json', 'number,title']);
  if (!Array.isArray(list)) return null;
  const hit = list.find((i) => i.title === ISSUE_TITLE);
  return hit ? hit.number : null;
}
function manageIssue(decision, body) {
  const repo = env.GITHUB_REPOSITORY;
  if (!repo) { infra.push('GITHUB_REPOSITORY unset — issue management skipped'); return; }
  if (!have(GH_BIN)) { infra.push('gh CLI not available — issue management skipped'); return; }
  const num = findOpenIssue(repo);
  const runUrl = `${env.GITHUB_SERVER_URL || 'https://github.com'}/${repo}/actions/runs/${env.GITHUB_RUN_ID || ''}`;
  const stamp = new Date().toISOString().slice(0, 10);
  if (decision.action === 'open') {
    const issueBody = `Scheduled dependency-currency sweep found advisories on **${repo}** (${stamp}).\n\nRun: ${runUrl}\n\nThis issue auto-closes when the next scheduled run is clean.\n\n${body}`;
    if (num) { run(GH_BIN, ['issue', 'comment', String(num), '-R', repo, '--body', issueBody], { timeout: 60000 }); infra.push(`updated tracking issue #${num}`); }
    else { const r = run(GH_BIN, ['issue', 'create', '-R', repo, '--title', ISSUE_TITLE, '--body', issueBody], { timeout: 60000 }); infra.push(r.status === 0 ? 'opened tracking issue' : `failed to open tracking issue: ${safe(r.stderr, 120)}`); }
  } else { // close
    if (num) {
      run(GH_BIN, ['issue', 'comment', String(num), '-R', repo, '--body', `Resolved — the scheduled deps-currency sweep is clean (0 advisories at/above floor **${FLOOR}**) as of ${stamp}.`], { timeout: 60000 });
      const r = run(GH_BIN, ['issue', 'close', String(num), '-R', repo], { timeout: 60000 });
      infra.push(r.status === 0 ? `closed tracking issue #${num} (clean)` : `failed to close issue #${num}`);
    }
  }
}

// ============================ main ============================
(function main() {
  const { ecosystems, lockfiles } = resolveEcosystems();
  const { findings } = runOsv();
  const floorFindings = filterByFloor(findings, FLOOR);
  const unpinned = scanUnpinnedActions(loadWorkflows());

  const report = renderReport(floorFindings, unpinned, {
    floor: FLOOR, ecosystems, lockfiles, totalFindings: findings.length,
  });

  const lines = [report];
  if (infra.length) { lines.push('', '### ℹ️ scanner notes'); for (const m of infra) lines.push(`- ${safe(m, 240)}`); }

  const decision = issueDecision(floorFindings, unpinned);
  const blocked = blockDecision(floorFindings, { failOnVuln: FAIL_ON_VULN });

  lines.push('');
  lines.push(`**at/above floor: ${floorFindings.length} · unpinned-action advisories: ${unpinned.length}**`);
  if (blocked) lines.push(`BLOCKED — ${floorFindings.length} dependency advisory(ies) at/above floor **${FLOOR}** with \`fail-on-vuln: true\`. Bump/remove the package(s), or lower the floor / document the exposure.`);
  else if (floorFindings.length > 0) lines.push(`report-only — ${floorFindings.length} advisory(ies) at/above floor would BLOCK under \`fail-on-vuln: true\`.`);
  else lines.push('PASS — no dependency advisories at or above the severity floor.');

  fs.appendFileSync(summaryFile, lines.join('\n') + '\n');

  if (MANAGE_ISSUE) {
    try { manageIssue(decision, report); } catch (e) { /* issue mgmt must never fail the run by itself */ fs.appendFileSync(summaryFile, `\n- ℹ️ issue management error (non-fatal): ${safe(String((e && e.message) || e), 160)}\n`); }
  }

  process.exit(blocked ? 1 : 0);
})();

// Defensive crash guard: a scan engine fault must not block a green repo unless we're an enforcing
// caller AND there were no findings to evaluate (we can't know) — so a crash exits 0 in report
// mode, 1 only under fail-on-vuln (conservative for an enforcing caller).
process.on('uncaughtException', (e) => {
  try { fs.appendFileSync(summaryFile, `\n- ❌ deps-currency crashed: ${safe(String((e && e.stack) || e), 400)}\n`); } catch { /* ignore */ }
  process.exit(FAIL_ON_VULN ? 1 : 0);
});
