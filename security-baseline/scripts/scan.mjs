// security-baseline CLI — runs the air-gapped scanners, normalizes their output into findings,
// tiers them via the pure engine (tiers.mjs), renders a per-check report to GITHUB_STEP_SUMMARY,
// and exits non-zero only when a CRITICAL (T0, or a per-caller-promoted T1) fires under
// fail-on-critical. Mirrors seo-aeo's check.mjs shape.
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
import { SEV, evaluate, parsePromote, groupByCheck, sevRank, CHECKS, safe, redact } from './tiers.mjs';

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

const BIN = {
  semgrep: env.SEMGREP_BIN || 'semgrep',
  gitleaks: env.GITLEAKS_BIN || 'gitleaks',
  trufflehog: env.TRUFFLEHOG_BIN || 'trufflehog',
  osv: env.OSV_BIN || 'osv-scanner',
  hadolint: env.HADOLINT_BIN || 'hadolint',
};

const summaryFile = env.GITHUB_STEP_SUMMARY || '/dev/stdout';
const lines = [];
const note = (s = '') => lines.push(s);
const ICON = { critical: '❌', warn: '⚠️', info: 'ℹ️', ok: '✅' };
const infra = [];   // tool-availability / degrade notes (not findings)
// safe() + redact() are imported from tiers.mjs (pure, selftest-covered disclosure guards).

function run(bin, args, opts = {}) {
  try {
    const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: opts.timeout || 300000, ...opts });
    if (r.error && r.error.code === 'ENOENT') return { missing: true, status: 127, stdout: '', stderr: '' };
    return { missing: false, status: r.status == null ? 1 : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  } catch (e) { return { missing: false, status: 1, stdout: '', stderr: String(e && e.message || e) }; }
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
  const out = sh(['diff', '--name-only', '--diff-filter=d', `${BASE}...HEAD`]);
  return out ? out.split('\n').map((s) => s.trim()).filter(Boolean) : [];
}
const CHANGED = changedFiles();
const byExt = (files, exts) => (files || []).filter((f) => exts.some((e) => f.toLowerCase().endsWith(e)) && fs.existsSync(f));

// ---------- semgrep ----------
function semgrepRun(configs, targets, { severity } = {}) {
  if (!targets || targets.length === 0) return { ran: false, results: [] };
  const args = ['scan', '--json', '--metrics=off', '--disable-version-check', '--quiet', '--no-git-ignore'];
  if (severity) args.push('--severity', severity);
  for (const c of configs) args.push('--config', c);
  args.push(...targets);
  const r = run(BIN.semgrep, args, { timeout: 420000 });
  if (r.missing) return { ran: false, missing: true, results: [] };
  let json; try { json = JSON.parse(r.stdout || '{}'); } catch { return { ran: true, results: [], parseError: true }; }
  return { ran: true, results: json.results || [] };
}
const sgFinding = (r, checkId) => ({
  checkId, tool: 'semgrep', file: r.path, line: (r.start && r.start.line) || 0,
  cwe: (r.extra && r.extra.metadata && [].concat(r.extra.metadata.cwe || []).join(',')) || '',
  msg: (r.extra && r.extra.message) || r.check_id || '',
});

function collectSemgrep() {
  const out = [];
  // T0 — community ERROR on the diff (or full tree). This IS today's block, preserved.
  if (!have(BIN.semgrep)) { infra.push('semgrep not installed — SAST skipped (install in the action step)'); return out; }
  const sastTargets = DIFF ? byExt(CHANGED, ['.php', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.java']) : ['.'];
  if (sastTargets.length) {
    const community = semgrepRun([SEMGREP_CONFIG], sastTargets, { severity: (env.SAST_SEVERITY || 'ERROR').trim() });
    if (community.ran) for (const r of community.results) out.push(sgFinding(r, 'sast-critical'));
  }
  // T1/T2 — vendored custom rules (php/ts), diff-scoped; emit by metadata.checkId.
  const codeTargets = DIFF ? byExt(CHANGED, ['.php', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.astro']) : ['.'];
  if (codeTargets.length) { // diff: only when code files changed; full: ['.']
    const custom = semgrepRun([path.join(RULES_DIR, 'wp-php.yaml'), path.join(RULES_DIR, 'astro-ts.yaml')], codeTargets);
    if (custom.ran) for (const r of custom.results) {
      const id = r.extra && r.extra.metadata && r.extra.metadata.checkId;
      if (id) out.push(sgFinding(r, id));
    }
  }
  // GitHub Actions supply-chain — always over .github/workflows (small, high value).
  if (fs.existsSync('.github/workflows')) {
    const gha = semgrepRun([path.join(RULES_DIR, 'gha.yaml')], ['.github/workflows']);
    if (gha.ran) for (const r of gha.results) {
      const id = r.extra && r.extra.metadata && r.extra.metadata.checkId;
      if (id) out.push(sgFinding(r, id));
    }
  }
  return out;
}

// ---------- gitleaks (pattern secrets) ----------
function gitleaksRun(extraArgs) {
  const tmp = path.join(os.tmpdir(), `gl-${Math.abs(hashish(extraArgs.join('|')))}.json`);
  const args = ['detect', '--redact', '--no-banner', '--report-format', 'json', '--report-path', tmp, '--exit-code', '0', ...extraArgs];
  const r = run(BIN.gitleaks, args, { timeout: 300000 });
  if (r.missing) return { missing: true, findings: [] };
  let arr = []; try { arr = JSON.parse(fs.readFileSync(tmp, 'utf8') || '[]'); } catch { arr = []; }
  try { fs.unlinkSync(tmp); } catch { /* ignore */ }
  return { missing: false, findings: arr };
}
function collectGitleaks() {
  const out = [];
  if (!have(BIN.gitleaks)) { infra.push('gitleaks not installed — secret scan skipped'); return out; }
  // T0 — diff range (today's block).
  const diffArgs = DIFF && BASE ? ['--log-opts', `${BASE}..HEAD`] : [];
  const diff = gitleaksRun(diffArgs);
  for (const f of diff.findings) out.push({ checkId: 'secret-pattern', tool: 'gitleaks', file: f.File, line: f.StartLine || 0, msg: `${f.RuleID || 'secret'} (${redact(f.Secret)})`, cwe: 'CWE-798' });
  // T2 — full-history baseline (WARN; never blocks). Dedup against the diff hits by file+rule.
  if (ENABLE_HISTORY) {
    const seen = new Set(diff.findings.map((f) => `${f.File}:${f.RuleID}`));
    const hist = gitleaksRun([]);
    for (const f of hist.findings) {
      const k = `${f.File}:${f.RuleID}`; if (seen.has(k)) continue; seen.add(k);
      out.push({ checkId: 'secrets-history', tool: 'gitleaks', file: f.File, line: f.StartLine || 0, msg: `${f.RuleID || 'secret'} in history (${redact(f.Secret)}) — rotate at the provider, then scrub history`, cwe: 'CWE-798' });
    }
  }
  return out;
}

// ---------- trufflehog (verified-live secrets) ----------
function collectTrufflehog() {
  const out = [];
  if (VERIFIED_SECRETS === 'off') { infra.push('verified-secrets:off — live-credential probe disabled (gitleaks pattern floor still blocks)'); return out; }
  if (!have(BIN.trufflehog)) { infra.push('trufflehog not installed — verified-live secret check skipped (gitleaks pattern floor still blocks)'); return out; }
  // CRITICAL `secret-verified` is the DIFF-scoped check: --since-commit bounds it to the NEW
  // commits, so it can only fire on a just-added live key (never pre-existing state). When there
  // is no diff range (scan-scope:full, or an unresolved base), the verified probe widens to full
  // history — a pre-existing live key must NOT block, so those are emitted as WARN `secrets-history`
  // (loud, but a history finding can't be a merge precondition). The raw value of a LIVE secret is
  // NEVER printed (not even redacted) — detector + file:line is enough.
  const scoped = DIFF && !!BASE;
  const args = ['git', 'file://.', '--only-verified', '--no-update', '--json'];
  if (scoped) args.push('--since-commit', BASE);
  const r = run(BIN.trufflehog, args, { timeout: 300000 });
  if (r.missing) return out;
  for (const ln of (r.stdout || '').split('\n')) {
    const t = ln.trim(); if (!t || t[0] !== '{') continue;
    let o; try { o = JSON.parse(t); } catch { continue; }
    if (o.Verified !== true) continue;
    const g = (o.SourceMetadata && o.SourceMetadata.Data && o.SourceMetadata.Data.Git) || {};
    out.push({
      checkId: scoped ? 'secret-verified' : 'secrets-history', tool: 'trufflehog',
      file: g.file || '(history)', line: g.line || 0, cwe: 'CWE-798',
      msg: `🔴 VERIFIED-LIVE ${o.DetectorName || 'secret'} — ROTATE NOW${scoped ? '' : ' (pre-existing in history — WARN, not a block; rotate then scrub history)'}`,
    });
  }
  return out;
}

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
function collectOsv() {
  const out = [];
  if (!ENABLE_SCA) return out;
  if (!have(BIN.osv)) { infra.push('osv-scanner not installed — dependency/SCA audit skipped'); return out; }
  const r = run(BIN.osv, ['scan', 'source', '--recursive', '--format', 'json', '.'], { timeout: 300000 });
  if (r.missing) return out;
  let json; try { json = JSON.parse(r.stdout || '{}'); } catch { return out; }
  for (const res of (json.results || [])) {
    const src = (res.source && res.source.path) || '';
    for (const pkg of (res.packages || [])) {
      const name = (pkg.package && pkg.package.name) || '?';
      const ver = (pkg.package && pkg.package.version) || '?';
      for (const g of (pkg.groups || [])) {
        const score = parseFloat(g.max_severity || '0') || 0;
        const ids = (g.ids || []).slice(0, 3).join(', ');
        out.push({ checkId: scaCheckId(score), tool: 'osv-scanner', file: src, line: 0, msg: `${name}@${ver} — ${ids}${score ? ` (CVSS ${score})` : ' (no CVSS)'} — present-in-tree, reachability unknown`, cwe: 'CWE-1395' });
      }
    }
  }
  return out;
}

// ---------- hadolint (Dockerfile lint — conditional) ----------
function collectHadolint() {
  const out = [];
  const dfChanged = DIFF ? (CHANGED || []).filter((f) => /(^|\/)Dockerfile(\.|$)|\.dockerfile$/i.test(f) && fs.existsSync(f)) : [];
  const targets = DIFF ? dfChanged : (sh(['ls-files']).split('\n').filter((f) => /(^|\/)Dockerfile(\.|$)/i.test(f) && fs.existsSync(f)).slice(0, 20));
  if (targets.length === 0) return out;
  if (!have(BIN.hadolint)) { infra.push('Dockerfile changed but hadolint not installed — IaC lint skipped'); return out; }
  for (const df of targets) {
    const r = run(BIN.hadolint, ['--format', 'json', df], { timeout: 60000 });
    let arr = []; try { arr = JSON.parse(r.stdout || '[]'); } catch { arr = []; }
    for (const h of arr) if (h.level === 'error' || h.level === 'warning') out.push({ checkId: 'dockerfile-lint', tool: 'hadolint', file: df, line: h.line || 0, msg: `${h.code}: ${h.message}`, cwe: 'CWE-1395' });
  }
  return out;
}

function hashish(s) { let h = 0; for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) | 0; } return h; }
function flush() { fs.appendFileSync(summaryFile, lines.join('\n') + '\n'); }

// ============================ main ============================
(async () => {
  note('## 🔒 security-baseline — air-gapped SAST · secrets · SCA · supply-chain');
  note('');
  note(`- mode: ${REPORT_MODE ? '**⚠️ REPORT-MODE — NOT enforcing**' : (FAIL_ON_CRITICAL ? '**BLOCK on critical**' : 'report-only')}`);
  note(`- scope: ${DIFF ? `diff (\`${safe(BASE)}\`…HEAD, ${CHANGED ? CHANGED.length : 0} changed file(s))` : 'full tree'}`);
  if (promote.length) note(`- promoted to critical (this caller): \`${promote.join('`, `')}\``);
  if (ignored.length) note(`- ⚠️ ignored \`critical-checks\` (not promotable T1 ids): \`${ignored.join('`, `')}\``);
  note('');

  let findings = [];
  for (const collect of [collectSemgrep, collectGitleaks, collectTrufflehog, collectOsv, collectHadolint]) {
    try { findings = findings.concat(collect()); } catch (e) { infra.push(`${collect.name}: ${safe(String(e && e.message || e), 120)}`); }
  }

  const { graded, crit, warn, info, blocked } = evaluate(findings, { failOnCritical: FAIL_ON_CRITICAL, reportMode: REPORT_MODE, promote });

  // ---- report, grouped by check, criticals first ----
  const groups = [...groupByCheck(graded)].sort((a, b) => sevRank(baseOf(a[1])) - sevRank(baseOf(b[1])));
  if (graded.length === 0) {
    note('- ✅ no findings across SAST, secrets, SCA, and CI supply-chain.');
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
  if (infra.length) { note('### ℹ️ scanner notes'); infra.forEach((m) => note(`- ${safe(m, 240)}`)); note(''); }

  note(`**critical: ${crit} · warnings: ${warn} · info: ${info}**`);
  if (REPORT_MODE && crit > 0) { note(`⚠️ REPORT-MODE — ${crit} critical finding(s) would BLOCK if enforcing. ${safe(env.REPORT_MODE_REASON || '')}`); flush(); process.exit(0); }
  if (blocked) { note(`BLOCKED — ${crit} critical finding(s). Fix the ❌ items, or waive with documented rationale.`); flush(); process.exit(1); }
  if (crit > 0) note(`report-only — ${crit} critical finding(s) would BLOCK under \`fail-on-critical: true\`.`);
  else note('PASS — no critical findings.');
  flush(); process.exit(0);
})().catch((e) => { note(`- ❌ security-baseline crashed: ${safe(String(e && e.stack || e), 400)}`); flush(); process.exit(FAIL_ON_CRITICAL && !REPORT_MODE ? 1 : 0); });

function baseOf(arr) { return arr[0] ? arr[0].sev : SEV.WARN; }
