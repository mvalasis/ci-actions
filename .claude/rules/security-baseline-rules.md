---
paths:
  - "security-baseline/**"
---
# security-baseline rule-authoring conventions

Severity model, recap: **T0** (tiny, always blocks) is fixed. **T1** is WARN by default and
promotable per-caller, additively, via the `critical-checks` input — default empty means a new
T1 rule never newly-blocks anyone. **T2** is advisory and never promotable. A new detection rule
starts life in `rules/*.yaml` at `severity: WARNING` with a stable `metadata.checkId` — raising a
rule's blocking posture is the caller's `critical-checks` choice, never a change to the rule
file's own `severity:`.

**When a new rule approximates an existing promotable rule with a heuristic or taint-mode
match, give it a SEPARATE `checkId`.** An exact-match rule (e.g. an accessor reaching a sink
directly) and a broader heuristic sibling that catches the same vulnerability class through
indirection (propagation through an intermediate variable, a normalizer, a DEBUG-labeled
container, a redirect target) are FP-shaped very differently. Sharing one `checkId` means a
caller who has verified the precise rule clean and promoted it to CRITICAL would newly-block on
the heuristic's false positives the moment it ships. Ship the heuristic family under its own id
instead, so the precise rule's promotion and the heuristic's stay independent.

**FP-discipline conventions for a new rule — baked in from experience, don't regress them:**
- **WP/PHP:** exclude committed `wp-admin/`, `wp-includes/`, `vendor/`, `*.phar` (WP repos vendor
  all of core). Require request-derived data to reach the sink directly — proximity alone is not
  enough. Treat a capability/nonce guard (`current_user_can`, `check_admin_referer`) as present in
  **any** position — a bare statement, inside an `if`, inside a `||` — never require one specific
  shape.
- **Astro/TS:** match only request/props-derived or otherwise non-constant operands — a
  fixed-origin `fetch`, a `JSON.stringify` of static data, a constant-constructed store must never
  fire. Constrain a receiver-sensitive match (e.g. `child_process`) to its actual receiver so an
  unrelated same-named method elsewhere doesn't false-fire. A `PUBLIC_*`/`EXPO_PUBLIC_*` name is
  public by convention — flag one only when it ALSO carries a genuinely-secret suffix
  (`SECRET`/`PRIVATE`/`API_?KEY`/`TOKEN`/`PASSWORD`), never a bare `_KEY` (a site key is meant to
  ship to the client). The accepted, documented exception under that pattern is the one named in
  `rules/astro-ts.yaml` (stays WARN, never auto-promoted).
- **A DEBUG-labeled heuristic beats a plain-key one.** Matching an array key named
  `detail|debug|trace|stack|sql|query|exception|backtrace|db_error|sql_error|error_detail` carries
  far less noise than also matching bare `error`/`message` keys — those are usually the intended
  client-facing string. Don't widen a heuristic to plain `error`/`message`.
- **Reach through an intermediate variable needs taint mode, not a structural grep.** Whenever a
  sink can be reached via a normalizer or an intermediate variable (`array_merge`, a wrapper
  function), write the rule in semgrep's taint mode. A structural rule both misses the indirection
  and, if widened to catch it structurally, over-fires on an unrelated function that merely also
  contains a logger and a clean response.
- **GHA supply-chain:** an action ref can carry subdirectory segments — `owner/repo/path@ref` is
  ONE action, not two path components. Match the whole `owner/repo` prefix, not just up to the
  first `@`, or a legitimate three-segment ref (and a mutable-tag risk hiding inside one) is
  invisible to the rule.

**First-party ownership is decided at runtime, never hard-coded.** A `uses:` ref is first-party
when its owner is in the union of: the caller's own owner (`github.repository`), this action's
own owner (`github.action_repository`), or an owner named in the caller's own allow-list input.
Hard-coding an owner literal becomes a lie the day that owner changes. Treat every uncertain
branch — an unparseable ref, an unparseable owner, an empty owner (a local `./` invocation leaves
`github.action_repository` empty) — as **keep the finding**, never as **drop it**: a spurious WARN
is a nuisance, a silently dropped supply-chain finding defeats the rule.
