// security-baseline — FIRST-PARTY owner resolution + the `gha-unpinned-action` post-filter.
// PURE apart from one injectable disk read, no network, no process exit: selftest.mjs unit-tests it
// offline, scan.mjs calls it on the raw semgrep results of the gha rule pack.
//
// WHY THE JUDGEMENT LIVES HERE AND NOT IN THE RULE. rules/gha.yaml is a VENDORED SEMGREP rule — a
// static YAML file evaluated by semgrep, with no access to an action input, an env var, or the
// workflow context. It therefore cannot know who "we" are. Baking `mvalasis/ci-actions` into the
// rule would make it correct exactly until ci-actions changes owner — i.e. it would hard-code as a
// constant the very fact that just moved (see below), a mistake this repo has already made once.
// So the rule stays owner-agnostic and flags EVERY mutable-tag ref; ownership is decided at
// runtime, here, where the owners are actually knowable.
//
// WHY THIS IS SUDDENLY LOAD-BEARING. Until 2026-08 every caller and the action lived under the same
// account, so deps-currency's single `selfOwner` test (the CALLER's org) was sufficient. On
// 2026-08-02..04 eleven repos moved from the personal account `mvalasis` into the org
// `creme-ypsilon` while `mvalasis/ci-actions` stayed put. On the six migrated callers the action's
// owner is no longer the caller's owner, so a caller-owner-only test would report all 32 of their
// `mvalasis/ci-actions/<action>@v1` refs as unpinned third-party actions — pure noise, and exactly
// the false-positive class deps-currency already learned to suppress. FIRST-PARTY is therefore the
// UNION of: the caller's owner, the ACTION's own owner, and any owners the caller names via the
// `first-party-owners` input.
import fs from 'node:fs';

const asArray = (v) => (Array.isArray(v) ? v : v ? [v] : []);

// Split a space/comma separated owner list. Lowercased (GitHub owners are case-insensitive), and
// empties dropped — an `''` in the owner set would be catastrophic, see ownerOf().
export function parseOwners(raw) {
  return String(raw == null ? '' : raw).split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
}

// Owner of an `owner/repo` slug, lowercased; '' for anything that is not a slug.
// The '' case is NOT hypothetical: the runner leaves `github.action_repository` EMPTY when the
// action is invoked by a local `./` ref — which is precisely how this repo's own
// security-baseline-selftest.yml smoke job invokes it (`uses: ./security-baseline`). An empty owner
// must never reach the owner set: it would compare equal to every ref whose owner failed to parse
// and suppress the entire check silently, turning a supply-chain gate into a no-op.
export const ownerOf = (slug) => String(slug == null ? '' : slug).split('/')[0].trim().toLowerCase();

// The first-party owner set per the ownership contract. Empties are filtered LAST, so a missing
// action_repository (local ./ ref) contributes nothing instead of poisoning the set.
export function firstPartyOwners({ repository = '', actionRepository = '', extra = '' } = {}) {
  return new Set([ownerOf(repository), ownerOf(actionRepository), ...parseOwners(extra)].filter(Boolean));
}

// A workflow `uses:` scalar, with or without the list dash and with or without quotes — the same
// shape deps-currency's scanner uses, kept deliberately identical so the two agree on what a ref is.
const USES_LINE = /^\s*(?:-\s*)?uses:\s*['"]?([^'"#\s]+)['"]?/;
// A BARE ref, for when the recovered text is the scalar alone rather than the whole line (semgrep's
// `extra.lines` shape is not contractual). Deliberately strict — at least two path segments and an
// `@ref` — so ordinary text can never be mistaken for a ref and quietly suppressed.
const BARE_REF = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+@[^\s'"#]+$/;

export function refFromText(text) {
  const t = String(text == null ? '' : text).split(/\r?\n/)[0] || '';
  const m = t.match(USES_LINE);
  if (m) return m[1];
  const bare = t.trim();
  return BARE_REF.test(bare) ? bare : '';
}

// Read one 1-indexed line of a file. Deliberately uncached: `.github/workflows` is a handful of
// small files and findings are few, and a module-level memo is hidden state that would let the
// offline selftest (which injects its own reader) drift away from the real path.
export function readLineFromDisk(file, line) {
  return fs.readFileSync(file, 'utf8').split(/\r?\n/)[line - 1] || '';
}

// Recover the `uses:` ref a finding points at. Primary source is the file on disk at the finding's
// line (deterministic, always the full line); `extra.lines` is the fallback for when the file
// cannot be read. Returns '' when neither yields a ref.
export function recoverRef(r, readLine = readLineFromDisk) {
  const file = (r && r.path) || '';
  const line = (r && r.start && r.start.line) || 0;
  if (file && line > 0) {
    let text = '';
    try { text = readLine(file, line) || ''; } catch { text = ''; }
    const ref = refFromText(text);
    if (ref) return ref;
  }
  return refFromText((r && r.extra && r.extra.lines) || '');
}

// Drop `gha-unpinned-action` findings whose `uses:` ref belongs to a first-party owner.
//
// FAIL TOWARD REPORTING, ALWAYS. Anything this filter cannot positively identify as first-party
// noise passes through untouched: other rule ids, an unrecoverable ref, a ref whose owner will not
// parse, an empty owner set. A spurious warning is a nuisance; a silently dropped supply-chain
// finding defeats the only reason the rule exists — so every uncertain branch KEEPS the finding.
export function filterFirstPartyGha(results, owners, readLine = readLineFromDisk) {
  const set = owners instanceof Set ? owners : new Set(parseOwners(asArray(owners).join(' ')));
  const all = asArray(results);
  if (set.size === 0) return all.slice();   // nothing is first-party → nothing may be dropped
  return all.filter((r) => {
    const id = r && r.extra && r.extra.metadata && r.extra.metadata.checkId;
    if (id !== 'gha-unpinned-action') return true;           // not ours to judge
    const ref = recoverRef(r, readLine);
    if (!ref) return true;                                   // unrecoverable → report it
    const at = ref.indexOf('@');
    const owner = ownerOf(at >= 0 ? ref.slice(0, at) : ref);
    if (!owner) return true;                                 // unparseable owner → report it
    return !set.has(owner);
  });
}
