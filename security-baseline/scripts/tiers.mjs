// security-baseline tier engine — PURE functions, no network, no process exit, no I/O.
// The CLI (scan.mjs) runs the scanners, normalizes their output into findings, and calls
// evaluate(); selftest.mjs unit-tests this module offline against canned tool output.
//
// SEVERITY MODEL (mirrors seo-aeo's T0/T1/T2, but BLOCK-BY-DEFAULT — security-baseline is the
// fleet's one always-on gate, so unlike seo-aeo it does NOT default to report-only):
//   T0 CRITICAL — always blocks (when fail-on-critical, the default). Tiny core: the two
//     checks that block TODAY (semgrep community ERROR on diff; gitleaks pattern on diff) plus
//     ONE added signal, a verified-live secret (a provider just authenticated it → ~zero FP).
//   T1 promotable-WARN — reports; a caller ELEVATES any id to CRITICAL via `critical-checks`.
//   T2 advisory — reports (WARN/INFO); never promotable (too FP-heavy or purely informational).

export const SEV = { CRIT: 'critical', WARN: 'warn', INFO: 'info', OK: 'ok' };

// checkId → { tier, sev }. The single source of truth for tiering. A finding's checkId (set by
// the tool adapter in scan.mjs) maps here to its DEFAULT severity; promotion can lift a T1 WARN
// to CRITICAL. An unknown checkId defaults to T1 WARN (a new custom rule can never newly-block).
export const CHECKS = {
  // ---- T0: always CRITICAL (the blocking core) ----
  'sast-critical':   { tier: 'T0', sev: SEV.CRIT },  // semgrep community rules @ ERROR, diff scope (today's block)
  'secret-pattern':  { tier: 'T0', sev: SEV.CRIT },  // gitleaks pattern detect, diff scope (today's block)
  'secret-verified': { tier: 'T0', sev: SEV.CRIT },  // trufflehog --only-verified, diff range (ADDED; ~zero FP)

  // ---- T1: promotable WARN (dependency / SCA) ----
  'sca-critical': { tier: 'T1', sev: SEV.WARN },
  'sca-high':     { tier: 'T1', sev: SEV.WARN },

  // ---- T1: promotable WARN (custom WP/PHP rules) ----
  'wp-nonce-missing':   { tier: 'T1', sev: SEV.WARN },
  'wp-cap-missing':     { tier: 'T1', sev: SEV.WARN },
  'wp-sql-unprepared':  { tier: 'T1', sev: SEV.WARN },
  'wp-unserialize':     { tier: 'T1', sev: SEV.WARN },
  'wp-file-include':    { tier: 'T1', sev: SEV.WARN },
  'wp-rest-error-detail': { tier: 'T1', sev: SEV.WARN },
  'wp-weak-crypto':     { tier: 'T1', sev: SEV.WARN },
  'turnstile-test-key': { tier: 'T1', sev: SEV.WARN },

  // ---- T1: promotable WARN (custom Astro/TS/RN rules) ----
  'ts-dangerous-html':    { tier: 'T1', sev: SEV.WARN },
  'ts-eval':              { tier: 'T1', sev: SEV.WARN },
  'ts-child-process':     { tier: 'T1', sev: SEV.WARN },
  'ts-public-secret-leak':{ tier: 'T1', sev: SEV.WARN },
  'ts-ssrf':              { tier: 'T1', sev: SEV.WARN },
  'ts-open-redirect':     { tier: 'T1', sev: SEV.WARN },
  'ts-secret-in-log':     { tier: 'T1', sev: SEV.WARN },
  'rn-insecure-storage':  { tier: 'T1', sev: SEV.WARN },
  'rn-cleartext-http':    { tier: 'T1', sev: SEV.WARN },

  // ---- T1: promotable WARN (GitHub Actions supply-chain) ----
  'gha-unpinned-action':  { tier: 'T1', sev: SEV.WARN },
  'gha-script-injection': { tier: 'T1', sev: SEV.WARN },
  'gha-pr-target':        { tier: 'T1', sev: SEV.WARN },

  // ---- T1: promotable WARN (secrets / supply chain / IaC) ----
  'secret-worktree':   { tier: 'T1', sev: SEV.WARN },  // gitleaks --no-git over .env / wp-config in the tree
  'license-denied':    { tier: 'T1', sev: SEV.WARN },
  'dockerfile-lint':   { tier: 'T1', sev: SEV.WARN },

  // ---- T2: advisory, NEVER promotable ----
  'sca-moderate':      { tier: 'T2', sev: SEV.INFO },
  'sca-low':           { tier: 'T2', sev: SEV.INFO },
  'wp-unescaped-output': { tier: 'T2', sev: SEV.WARN }, // syntactic XSS heuristic — too FP-heavy to promote
  'ts-cors-wildcard':  { tier: 'T2', sev: SEV.WARN },
  'secrets-history':   { tier: 'T2', sev: SEV.WARN },   // full-history secret baseline — clearing needs history rewrite, never a merge precondition
  'lockfile-integrity':{ tier: 'T2', sev: SEV.INFO },
  'iac-misconfig':     { tier: 'T2', sev: SEV.WARN },
};

export const T0_CHECKS = new Set(Object.keys(CHECKS).filter((k) => CHECKS[k].tier === 'T0'));
export const T1_CHECKS = new Set(Object.keys(CHECKS).filter((k) => CHECKS[k].tier === 'T1'));
export const T2_CHECKS = new Set(Object.keys(CHECKS).filter((k) => CHECKS[k].tier === 'T2'));

export const isKnown = (id) => Object.prototype.hasOwnProperty.call(CHECKS, id);
export const isPromotable = (id) => T1_CHECKS.has(id);
export function baseSev(id) { return (CHECKS[id] || { sev: SEV.WARN }).sev; }

// Parse the `critical-checks` input (comma/space separated) → { promote, ignored }.
// Only T1 ids are honored; T0 ids are already critical, T2/unknown ids are reported-and-ignored
// (so a caller can never silently make a T2 advisory or a typo into a blocking gate).
export function parsePromote(raw) {
  const ids = String(raw || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const promote = ids.filter((id) => T1_CHECKS.has(id));
  const ignored = ids.filter((id) => !T1_CHECKS.has(id));
  return { promote: [...new Set(promote)], ignored: [...new Set(ignored)] };
}

// Core evaluation. `findings` is a flat list of { checkId, file, line, msg, tool, cwe } objects
// (NO sev — severity is derived here from checkId + promotion, so a tool can never mis-tier).
// Returns the graded findings + tally + block decision. Pure; no exit, no print.
export function evaluate(findings, opts = {}) {
  const failOnCritical = opts.failOnCritical !== false; // default TRUE (block-by-default)
  const reportMode = opts.reportMode === true;          // escape hatch: report even T0
  const promoteSet = new Set((opts.promote || []).filter((id) => T1_CHECKS.has(id)));

  const graded = findings.map((f) => {
    let sev = baseSev(f.checkId);
    if (sev === SEV.WARN && promoteSet.has(f.checkId)) sev = SEV.CRIT;
    return { ...f, sev, tier: (CHECKS[f.checkId] || { tier: 'T1' }).tier, promoted: sev === SEV.CRIT && baseSev(f.checkId) === SEV.WARN };
  });

  const crit = graded.filter((f) => f.sev === SEV.CRIT).length;
  const warn = graded.filter((f) => f.sev === SEV.WARN).length;
  const info = graded.filter((f) => f.sev === SEV.INFO).length;
  const blocked = crit > 0 && failOnCritical && !reportMode;
  return { graded, crit, warn, info, blocked, reportMode, promoted: [...promoteSet] };
}

// Group graded findings by checkId for a compact report.
export function groupByCheck(graded) {
  const m = new Map();
  for (const f of graded) {
    if (!m.has(f.checkId)) m.set(f.checkId, []);
    m.get(f.checkId).push(f);
  }
  return m;
}

export function sevRank(s) { return { critical: 0, warn: 1, info: 2, ok: 3 }[s] ?? 9; }

// Presentation helpers (pure, selftest-covered). `safe` neutralizes tool-controlled strings
// before they reach the markdown summary (strip CR/LF + markdown-structural chars + cap length)
// so a hostile file path / rule message can't forge a verdict line or inject an image beacon.
// `redact` keeps only first4…last4 of a secret so a raw credential NEVER reaches a (public) job
// summary — the disclosure guard.
export const safe = (s, max = 200) => String(s == null ? '' : s)
  .replace(/[\r\n]+/g, ' ')
  .replace(/[`|<>[\]()]/g, '')   // markdown-structural chars incl parens (no forged links)
  .replace(/:\/\//g, '[:]//')    // defang URLs so a tool-controlled path can't auto-link/beacon
  .slice(0, max);
export const redact = (s) => { const v = String(s == null ? '' : s); return v.length <= 12 ? '****' : `${v.slice(0, 4)}…${v.slice(-4)}`; };

// RESERVED — declared in CHECKS so a FUTURE scanner can emit them with no engine change, but NO
// adapter emits them today (see README §Honest limits). secret-worktree is a *local* pre-push
// concern (a fresh CI checkout has no untracked/gitignored files to scan); license-denied /
// lockfile-integrity / iac-misconfig await a collector. The selftest asserts emitted ∪ reserved
// == all CHECKS, so a new id can never silently become a dead (or unintended-blocking) declaration.
export const RESERVED_CHECKS = new Set(['secret-worktree', 'license-denied', 'lockfile-integrity', 'iac-misconfig']);
