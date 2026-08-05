// deps-currency engine — PURE functions, no network, no process exit, no I/O.
// The CLI (scan.mjs) discovers lockfiles, runs osv-scanner over each FULL lockfile, and feeds the
// raw tool output here; selftest.mjs unit-tests this module offline against a saved osv-scanner
// JSON fixture. This is the TIME-axis complement to security-baseline's diff-scoped osv check:
// security-baseline answers "did THIS change introduce a vuln?", deps-currency answers "is the
// committed dependency tree carrying a known-vuln/abandoned dep RIGHT NOW?" on a schedule.
//
// SEVERITY MODEL — osv-scanner v2 emits results[].packages[].groups[] each with a computed
// numeric `max_severity` (CVSS, e.g. "9.2"). We bucket that score into CRITICAL/HIGH/MODERATE/LOW
// and filter against a caller-set severity FLOOR. No CVSS → conservative HIGH (never silently
// dropped). The action is report-mode-first: a finding never blocks unless fail-on-vuln=true AND
// the finding is at/above the floor.

export const SEV = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MODERATE', LOW: 'LOW' };

// Rank: lower number = more severe. Used for floor comparison and report ordering.
export const SEV_RANK = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3 };
const FLOOR_ALIASES = { CRIT: SEV.CRITICAL, CRITICAL: SEV.CRITICAL, HIGH: SEV.HIGH, MED: SEV.MODERATE, MEDIUM: SEV.MODERATE, MODERATE: SEV.MODERATE, MOD: SEV.MODERATE, LOW: SEV.LOW };

export function normalizeFloor(raw) {
  const k = String(raw || 'HIGH').trim().toUpperCase();
  return FLOOR_ALIASES[k] || SEV.HIGH;
}

// CVSS score → bucket. Matches osv-scanner's own thresholds (CRITICAL ≥9, HIGH ≥7, MODERATE ≥4).
// A group with no CVSS (score 0 / absent) is treated as HIGH — "unknown but real" must not slip
// under a HIGH floor, mirroring security-baseline's scaCheckId conservatism.
export function bucketFor(score) {
  const s = Number(score) || 0;
  if (s >= 9.0) return SEV.CRITICAL;
  if (s >= 7.0) return SEV.HIGH;
  if (s >= 4.0) return SEV.MODERATE;
  if (s > 0) return SEV.LOW;
  return SEV.HIGH; // no CVSS → conservative
}

export const atOrAboveFloor = (sev, floor) => SEV_RANK[sev] <= SEV_RANK[normalizeFloor(floor)];

// Parse one osv-scanner v2 JSON document into a flat list of vuln findings, one per group
// (a group is one vuln/alias cluster on one package). Tolerant of partial/empty/garbage input —
// returns [] rather than throwing, so a tool glitch degrades to "clean" not "crash".
//   finding = { ecosystem, source, name, version, ids, score, severity, abandoned }
export function parseOsv(json) {
  const out = [];
  const doc = json && typeof json === 'object' ? json : {};
  for (const res of asArray(doc.results)) {
    const source = (res && res.source && res.source.path) || '';
    for (const pkg of asArray(res && res.packages)) {
      const p = (pkg && pkg.package) || {};
      const name = p.name || '?';
      const version = p.version || '?';
      const ecosystem = p.ecosystem || '';
      for (const g of asArray(pkg && pkg.groups)) {
        const score = parseFloat(g && g.max_severity) || 0;
        const ids = asArray(g && g.ids).slice(0, 4).map(String);
        out.push({
          ecosystem, source, name, version,
          ids: ids.length ? ids : ['(unidentified)'],
          score,
          severity: bucketFor(score),
          // osv-scanner surfaces unmaintained/malicious advisories too; flag if any alias is a
          // GHSA "MAL"/"unmaintained" marker (best-effort — purely additive context in the report).
          abandoned: ids.some((id) => /^MAL-|UNMAINTAINED/i.test(id)),
        });
      }
    }
  }
  return out;
}

// Apply the severity floor → the set of findings that "count" (drive the issue + the optional
// block). Sorted most-severe first, then by package name for a stable report.
export function filterByFloor(findings, floor) {
  return findings
    .filter((f) => atOrAboveFloor(f.severity, floor))
    .sort((a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || a.name.localeCompare(b.name) || a.ids[0].localeCompare(b.ids[0]));
}

// ---------------------------------------------------------------------------
// GitHub-Actions supply-chain: a workflow step that (a) consumes a secret AND
// (b) `uses:` a third-party action pinned to a MUTABLE ref (tag/branch, not a
// 40-hex SHA) can have that ref re-pointed at malicious code that then exfiltrates
// the secret. This is a TIME-axis supply-chain risk (the upstream tag can move
// under you), so it belongs in the scheduled currency sweep. Pure text scan of a
// single workflow YAML body — no YAML lib (zero-dep), heuristic but FP-disciplined:
//   - only flags steps whose `uses:` is a third-party `owner/repo@ref` (skips local
//     `./...`, `docker://`, first-party `actions/*` / `github/*`, AND any owner in the
//     FIRST-PARTY OWNER SET — our own shared actions, e.g. `mvalasis/ci-actions@v1`,
//     are first-party + deliberately floating-tag-pinned by the fleet's versioning
//     policy; flagging them on every caller is pure noise),
//   - only when the ref is NOT a full 40-char hex SHA,
//   - AND only when a secret is referenced anywhere in the same workflow file
//     (`secrets.*` or `${{ secrets… }}`) — the consuming-secrets qualifier.
// Conservative-by-design: file-level secret co-presence (not step-level dataflow),
// so it can over-report within a file but never crosses files. WARN-only signal.
//
// WHY A SET AND NOT ONE OWNER (the 2026-08-02..04 ownership split). This used to take a
// single `selfOwner`, derived from `github.repository` — i.e. "first-party == whoever owns
// the CALLER". That held only while one account owned everything. Then 11 repos moved from
// the personal account `mvalasis` into the org `creme-ypsilon` and `mvalasis/ci-actions`
// did NOT move, so on every org-owned caller each `mvalasis/ci-actions/<action>@v1` ref
// started reading as an unpinned THIRD-PARTY action: lampakia-astro 2 → 6 rows,
// prevedourougr 2 → 5. WARN-tier, so nothing blocked — but `issueDecision` returns 'close'
// only when `unpinnedCount === 0`, so the tracking issues (lampakia-astro#41,
// prevedourougr#28) would have become impossible to EVER close, and a tracking issue that
// can never close is a signal everyone learns to ignore. First-party is now the UNION of
// caller owner ∪ action owner ∪ caller-declared extras (see `resolveFirstPartyOwners`).
// A bare string is still accepted so existing call sites keep working.
const SHA40 = /^[0-9a-f]{40}$/i;
const ownerOf = (slug) => String(slug == null ? '' : slug).split('/')[0].trim();

// Normalize a first-party owner spec — an array, or a space/comma-separated string, so the
// `first-party-owners` action input and a bare single owner both parse through ONE path — into a
// lowercased Set. EMPTY TOKENS ARE DROPPED, and that is load-bearing rather than tidiness:
// `github.action_repository` is EMPTY when the action is invoked by a local `./` ref (which is how
// this repo's own selftest workflows invoke actions), so `ownerOf('')` → `''` genuinely lands in
// the input list on those runs. An `''` left in the set would make `owners.has(ownerLc)` true for
// an owner-less `uses:` — an exemption that matches by accident, which is the exact defect class
// this change exists to fix. Empty in ⇒ nothing exempted, never everything exempted.
export function normalizeOwners(spec) {
  const out = new Set();
  for (const entry of (Array.isArray(spec) ? spec : [spec])) {
    for (const tok of String(entry == null ? '' : entry).split(/[\s,]+/)) {
      const v = tok.trim().toLowerCase();
      if (v) out.add(v);
    }
  }
  return out;
}

// Resolve the first-party owner set per the ownership-split contract — the union of:
//   (a) the CALLER's owner — from `github.repository` (e.g. `creme-ypsilon/lampakia-astro`)
//   (b) the ACTION's own owner — from `github.action_repository` (e.g. `mvalasis/ci-actions`).
//       This is the part that fixes the split. It is EMPTY for a local `./` invocation, and an
//       empty value must contribute NOTHING (never an `''` owner) — the set then correctly
//       degrades to caller-only, which is the right answer when the action IS the caller's repo.
//   (c) any owners named in the optional `first-party-owners` input — the escape hatch for a
//       fleet that later spans a third account, so nobody has to cut an action release for it.
// Returns an ARRAY in caller → action → extras order (deterministic, and it reads that way in the
// report). Pure: the CLI supplies the env, this decides the policy.
export function resolveFirstPartyOwners({ callerRepo = '', actionRepo = '', extraOwners = '' } = {}) {
  return [...normalizeOwners([ownerOf(callerRepo), ownerOf(actionRepo), extraOwners])];
}

export function scanUnpinnedActions(workflowFiles, firstPartyOwners = '') {
  const owners = normalizeOwners(firstPartyOwners);
  const out = [];
  for (const wf of asArray(workflowFiles)) {
    const path = (wf && wf.path) || '';
    const text = (wf && wf.text) || '';
    if (!text) continue;
    const consumesSecret = /\bsecrets\.[A-Za-z_][A-Za-z0-9_]*/.test(text);
    if (!consumesSecret) continue; // only workflows that touch a secret are in scope
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*(?:-\s*)?uses:\s*['"]?([^'"#\s]+)['"]?/);
      if (!m) continue;
      const ref = m[1];
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue; // local / docker — no upstream tag to move
      const at = ref.indexOf('@');
      if (at < 0) continue; // no ref at all (rare) — not our heuristic
      const repo = ref.slice(0, at);
      const pin = ref.slice(at + 1);
      const owner = repo.split('/')[0] || '';
      const ownerLc = owner.toLowerCase();
      if (ownerLc === 'actions' || ownerLc === 'github') continue; // first-party — trusted, GitHub-pinned
      if (owners.has(ownerLc)) continue; // first-party owner — the caller's, the action's own, or a declared extra
      if (SHA40.test(pin)) continue; // immutably pinned — safe
      out.push({ path, line: i + 1, uses: ref, pin });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Issue lifecycle decision (mirrors linkcheck's open-on-fail / close-on-clean). Given the
// floor-filtered vuln findings + the unpinned-action findings, decide whether the tracking issue
// should be OPEN (problems present) or CLOSED (clean). Pure — the CLI does the actual gh calls.
export function issueDecision(floorFindings, unpinned = []) {
  const vulnCount = floorFindings.length;
  const unpinnedCount = unpinned.length;
  const clean = vulnCount === 0 && unpinnedCount === 0;
  return { action: clean ? 'close' : 'open', clean, vulnCount, unpinnedCount };
}

// Block decision: exits non-zero ONLY when fail-on-vuln AND at least one finding at/above floor.
// Unpinned-action findings are WARN-only and NEVER block (a currency advisory, not a gate).
export function blockDecision(floorFindings, { failOnVuln = false } = {}) {
  return failOnVuln === true && floorFindings.length > 0;
}

// ---------------------------------------------------------------------------
// Presentation. `safe` neutralizes tool-controlled strings (package names, advisory ids, file
// paths) before they reach the markdown summary / issue body: strip CR/LF + markdown-structural
// chars + defang URLs + cap length, so a hostile dep name or advisory text can't forge a verdict
// line or inject an image beacon. Mirrors security-baseline's safe().
export const safe = (s, max = 200) => String(s == null ? '' : s)
  .replace(/[\r\n]+/g, ' ')
  .replace(/[`|<>[\]()]/g, '')
  .replace(/:\/\//g, '[:]//')
  .slice(0, max);

const SEV_ICON = { CRITICAL: '🔴', HIGH: '🟠', MODERATE: '🟡', LOW: '⚪' };

// Render the full markdown report (used for BOTH the job summary and the issue body — one source
// of truth). `meta` carries scan context (floor, lockfiles found, ecosystems, totals).
export function renderReport(floorFindings, unpinned, meta = {}) {
  const L = [];
  const p = (s = '') => L.push(s);
  p('## 📦 deps-currency — scheduled dependency advisory sweep');
  p('');
  p(`- floor: **${normalizeFloor(meta.floor)}** · ecosystems: ${meta.ecosystems && meta.ecosystems.length ? meta.ecosystems.map((e) => safe(e, 24)).join(', ') : '(none detected)'}`);
  p(`- lockfiles scanned: ${meta.lockfiles && meta.lockfiles.length ? meta.lockfiles.map((f) => '`' + safe(f, 80) + '`').join(', ') : '(none found)'}`);
  // Print the first-party owner set. The 2026-08 ownership-split defect was invisible in this
  // report — it just showed four extra "unpinned third-party" rows for our OWN actions, with
  // nothing saying which owners the scan had exempted, so the row looked like real debt rather
  // than a mis-derived exemption. Rendered only when the CLI supplies it (older/pure callers of
  // renderReport, incl. the selftest's rendering assertions, are unaffected).
  if (Array.isArray(meta.firstPartyOwners)) p(`- first-party owners (exempt from the unpinned-action scan): ${meta.firstPartyOwners.length ? meta.firstPartyOwners.map((o) => '`' + safe(o, 40) + '`').join(', ') : '(none — every non-`actions`/`github` owner is third-party)'}`);
  if (Number.isFinite(meta.totalFindings)) p(`- advisories in tree: **${meta.totalFindings}** total · **${floorFindings.length}** at/above floor`);
  p('');

  if (floorFindings.length === 0) {
    p('- ✅ no dependency advisories at or above the severity floor.');
  } else {
    p(`### Vulnerable / advisory-flagged dependencies (${floorFindings.length})`);
    p('');
    p('| Sev | Package | Version | Advisory | CVSS | Lockfile |');
    p('|---|---|---|---|---|---|');
    for (const f of floorFindings) {
      const icon = SEV_ICON[f.severity] || '';
      const ab = f.abandoned ? ' _(unmaintained/malicious)_' : '';
      p(`| ${icon} ${f.severity} | ${safe(f.name, 60)}${ab} | ${safe(f.version, 30)} | ${safe(f.ids.join(', '), 60)} | ${f.score ? f.score : 'n/a'} | ${safe(f.source, 60)} |`);
    }
    p('');
    p('_Present-in-tree, reachability unknown — osv-scanner is syntactic (no dataflow). Bump or remove the package; if a fix is unavailable, document the exposure._');
  }
  p('');

  if (unpinned.length) {
    p(`### ⚠️ Unpinned third-party actions consuming secrets (${unpinned.length})`);
    p('');
    p('A mutable tag/branch ref can be re-pointed upstream at malicious code that then exfiltrates the secret. Pin to a full commit SHA.');
    p('');
    for (const u of unpinned.slice(0, 25)) p(`- \`${safe(u.path, 80)}:${u.line}\` → \`${safe(u.uses, 100)}\` (pinned to \`${safe(u.pin, 50)}\`, not a SHA)`);
    if (unpinned.length > 25) p(`- …and ${unpinned.length - 25} more`);
    p('');
  }
  return L.join('\n');
}

function asArray(x) { return Array.isArray(x) ? x : []; }
