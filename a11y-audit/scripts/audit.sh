#!/usr/bin/env bash
# a11y-audit: WCAG audit of live URLs via pa11y-ci (axe + HTML_CodeSniffer).
# Report-mode by default; FAIL_ON_VIOLATIONS=true makes it BLOCK.
# VERIFY_TOKEN (optional) → X-Verify-Source header, to clear a WAF/CF bot-challenge.
set -uo pipefail

# ---- crash guard — armed before EVERY other statement ---------------------
# A fault in this SCRIPT or in pa11y-ci is a fault in the GATE, not WCAG debt on
# the caller's page. It is reported as such and exits under the caller's own
# `fail-on-violations` setting, so our bug never newly-BLOCKS a report-mode
# caller — the report-mode-first rule the JS entrypoints already follow.
#
# WHY `trap … EXIT` AND NOT `trap … ERR`. Measured, not assumed:
#   * `set -u` (line 5) aborts the shell on an unbound variable with status 1
#     even though errexit is off — and it does NOT fire the ERR trap, only EXIT.
#     An unbound variable is the single most likely fault in this script, so an
#     ERR trap would miss precisely the class it was written for.
#   * With errexit off, ERR fires on every non-zero command while the script
#     carries on regardless — including the deliberate `grep -q` probes below —
#     so an ERR trap would also report crashes that never happened.
# EXIT fires exactly once, on every path, and can rewrite the status. It is the
# only hook that is both complete and non-spurious here.
#
# ORDER AND ENV-IMMUNITY, both the hard way. The first draft of this guard sat
# below the config block and read the script's own `$FAIL_ON_VIOLATIONS` — and a
# behavioural test injecting an unbound variable into that block walked straight
# past it: an abort ABOVE the `trap` line never reaches the handler, and a handler
# that dereferences a not-yet-assigned variable would re-abort inside itself under
# `set -u`. So the guard is armed on the first executable line, and every value it
# needs is read as `${VAR:-default}` from the ENVIRONMENT, never from a script
# variable that may not be assigned yet. That is the same rule, for the same
# reason, as render-check.mjs reading `process.env` instead of its TDZ consts.
#
# The sentinel separates a deliberate verdict from an abort: every intentional
# exit goes through `finish`, which sets it. Anything reaching the trap without it
# aborted early.
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
# `|| true`: the crash reporter runs THROUGH note, so note must never be the thing
# that fails while reporting that something failed (an unwritable summary sink is
# itself one of the faults worth reporting). The stderr mirror in report_fault is
# what guarantees the diagnostic survives that case.
note() { printf '%s\n' "$*" >>"$summary" 2>/dev/null || true; }

verdict_reached=0
finish() { verdict_reached=1; exit "$1"; }

report_fault() {   # $1 = one-line reason
  note ""
  note "- ❌ **a11y-audit crashed** — the GATE faulted. This is not a verdict on the page."
  note "  - $1"
  if [ "${FAIL_ON_VIOLATIONS:-false}" = "true" ]; then
    note "  - \`fail-on-violations: true\` → exiting **1** (conservative for an enforcing caller)."
  else
    note "  - \`fail-on-violations: false\` → exiting **0** — a tool fault must not newly-block a report-mode caller."
  fi
  # Mirror to stderr: if the summary sink is what broke, this is the only copy.
  printf 'a11y-audit crashed: %s\n' "$1" >&2
}

# Report a tool fault and exit under the caller's enforcement setting.
crash() {
  report_fault "$1"
  if [ "${FAIL_ON_VIOLATIONS:-false}" = "true" ]; then finish 1; else finish 0; fi
}

on_exit() {
  rc=$?
  # A verdict was reached — pass its status through untouched.
  if [ "$verdict_reached" -eq 1 ]; then exit "$rc"; fi
  report_fault "unexpected exit $rc before any verdict was reached (unbound variable under \`set -u\`, an errexit abort, or a fatal signal)"
  if [ "${FAIL_ON_VIOLATIONS:-false}" = "true" ]; then exit 1; fi
  exit 0
}
trap on_exit EXIT

STANDARD="${STANDARD:-WCAG2AA}"
RUNNER="${RUNNER:-axe htmlcs}"
FAIL_ON_VIOLATIONS="${FAIL_ON_VIOLATIONS:-false}"
MAX_URLS="${MAX_URLS:-25}"

# Header for sitemap fetch (pa11y gets it via the config below).
# NOTE: this curl has NO -L, so a 3xx on the sitemap is not followed and the
# token can never be replayed to a redirect target (curl re-sends a custom -H
# across a cross-host redirect — it strips only Cookie/Authorization). Keep it
# that way: do NOT add -L here, or the token would leak to the redirect host.
hdr=()
[ -n "${VERIFY_TOKEN:-}" ] && hdr=(-H "X-Verify-Source: $VERIFY_TOKEN")

# Build the URL list (sitemap expansion + explicit urls).
urls=""
if [ -n "${SITEMAP_URL:-}" ]; then
  urls=$(curl -fsS --max-time 30 "${hdr[@]}" "$SITEMAP_URL" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed 's#</\?loc>##g')
fi
if [ -n "${URLS:-}" ]; then
  urls=$(printf '%s\n%s\n' "$urls" "$URLS")
fi
urls=$(printf '%s\n' "$urls" | tr ' ' '\n' | sed '/^$/d' | sort -u | head -n "$MAX_URLS")

note "## ♿ a11y-audit"
if [ -z "$urls" ]; then note "- no URLs to audit — skipped"; finish 0; fi
count=$(printf '%s\n' "$urls" | wc -l | tr -d ' ')
note "- standard: \`$STANDARD\` · runners: \`$RUNNER\` · URLs: $count"

# Generate the pa11y-ci config (JSON).
runners_json=$(printf '"%s",' $RUNNER | sed 's/,$//')
urls_json=$(printf '%s\n' "$urls" | sed 's#.*#"&"#' | paste -sd, -)
# headers: a dummy `_lscache_vary` cookie makes LiteSpeed "Guest Mode" SKIP its
# first-visit JS reload — the client only reloads when that cookie is absent, and
# on a cookie-less CI runner the reload navigates mid-audit and throws "Execution
# context was destroyed", failing the gate on a compliant page (wait alone loses
# the race; the cookie removes the reload deterministically). Harmless without
# Guest Mode. X-Verify-Source is added when a token is set (WAF/CF bypass).
#
# TOKEN SCOPE (verified against pa11y@9.1.1 / pa11y-ci@4.1.1): these go into
# pa11y-ci's `defaults.headers`, which pa11y applies via first-request-only
# Puppeteer request interception — NOT page.setExtraHTTPHeaders. Its handler
# overrides headers only while an `interceptionHandled` flag is false, then sets
# it true (lib/pa11y.js: "We only want to make changes to the first request …
# which is the request for the page we're testing"). So X-Verify-Source rides
# ONLY the navigation request to each audited URL — never a cross-origin
# subresource (fonts/CDNs/analytics) and never a cross-origin redirect target
# (the 3xx target is a later request → empty overrides → no token). The token is
# therefore confined to the first-party origins you point this action at. This
# no-broadcast property depends on pa11y NOT switching to setExtraHTTPHeaders, so
# the `pa11y-ci@4` pin (see action.yml install step) is a SECURITY control —
# re-audit token scope on any pa11y-ci major bump. (`_lscache_vary=1` is a public
# literal, not a secret; only X-Verify-Source is sensitive.)
hdr_pairs='"Cookie": "_lscache_vary=1"'
[ -n "${VERIFY_TOKEN:-}" ] && hdr_pairs="$hdr_pairs, \"X-Verify-Source\": \"$VERIFY_TOKEN\""
headers_json="\"headers\": { $hdr_pairs }, "
# levelCapWhenNeedsReview: cap axe "incomplete" (needsFurtherReview) findings
# to a warning. axe emits these when it CAN'T determine pass/fail automatically
# (e.g. text over a position:fixed overlay, gradients, bg images) — they are
# judgment items, not confirmed violations, so a hard gate must not BLOCK on
# them (DISCIPLINES.md: mechanical → gate, judgment → advisory). Confirmed
# axe violations + htmlcs errors still report as errors and block.
# wait: a short settle so any post-load entrance animation finishes first.
cat > /tmp/pa11y-ci.json <<EOF
{ "defaults": { ${headers_json}"standard": "$STANDARD", "runners": [$runners_json], "timeout": 60000,
    "wait": 3000,
    "levelCapWhenNeedsReview": "warning",
    "chromeLaunchConfig": { "args": ["--no-sandbox", "--disable-dev-shm-usage"] } },
  "urls": [ $urls_json ] }
EOF

# Run pa11y-ci, capturing the log so we can tell a flaky *run* error apart from a
# URL that ran and reported violations. pa11y-ci prints one structured summary
# line per URL: "> <url> - Failed to run" for a run error, "> <url> - N errors"
# for a real violation. We key off those reporter lines (not free text) so the
# audited page's own HTML — which is echoed in the error detail and could contain
# strings like "Failed to run" — can never spoof the decision.
# NO_COLOR + ANSI strip: pa11y-ci's reporter (kleur) emits colour when a CI sets
# FORCE_COLOR even on a non-TTY pipe; the ">"-anchored greps below would then
# match nothing and silently disable the retry. Force plain output and strip any
# stray escapes so summary-line detection is deterministic across colour envs.
# Capture pa11y-ci's real exit via PIPESTATUS[0] (the pipe ends in sed|tee).
run_audit() { NO_COLOR=1 pa11y-ci --config /tmp/pa11y-ci.json 2>&1 | sed $'s/\x1b\\[[0-9;]*m//g' | tee /tmp/pa11y-out.txt; return "${PIPESTATUS[0]}"; }

# A genuine WCAG violation is always a "> <url> - N errors" line; a transient
# failure is a "> <url> - Failed to run" line. Anchor to the reporter's per-URL
# summary shape (leading ">") so error-detail lines (which start with " • " or
# whitespace, never ">") can't match even when the page HTML echoes these words.
ran_errline='^[[:space:]]*>[[:space:]].*-[[:space:]]Failed to run[[:space:]]*$'
viol_errline='^[[:space:]]*>[[:space:]].*-[[:space:]][0-9]+[[:space:]]error'

set +e
run_audit
rc=$?
# Retry ONCE only when the failure was purely a flaky run error AND no URL
# reported real violations. The "no violations" guard is the safety invariant:
# if any "- N errors" line is present, we never retry, so a passing re-run can
# never clear a real WCAG failure (which would be worse than the flake itself).
# A persistent run error (both attempts fail) still falls through non-zero, so
# enforce mode blocks.
if [ "$rc" -ne 0 ] \
   && grep -qE "$ran_errline" /tmp/pa11y-out.txt \
   && ! grep -qE "$viol_errline" /tmp/pa11y-out.txt; then
  note "- ⚠️ transient run error only (no WCAG violations) — retrying once"
  run_audit
  rc=$?
fi
# NB this ENABLES errexit rather than restoring it — line 5 sets `-uo pipefail`,
# never `-e` — so the verdict block below runs under errexit that the rest of the
# script does not. Left as-is (it is not this change's bug, and it only tightens
# the tail), but it is no longer silent: an abort it triggers now lands in the
# EXIT trap and is reported as a tool fault instead of vanishing into a bare
# non-zero exit.
set -e

if [ "$rc" -eq 0 ]; then
  note "- ✅ no WCAG $STANDARD errors"
  finish 0
fi

# A non-zero rc is NOT automatically "WCAG errors found". pa11y-ci exits non-zero
# for a fault too — a missing binary (127), an unwritable /tmp config, a Chromium
# that will not launch — and until now every one of those was reported to the
# operator as accessibility debt and BLOCKED an enforcing caller under a verdict
# the tool never actually reached. The per-URL reporter lines are the evidence
# that a verdict exists; without one there is nothing to report but the fault.
# (Anchored on the leading ">" reporter shape, same as the retry logic above, so
# the audited page's own HTML can never spoof its way into looking like one.)
have_viol=0
if grep -qE "$viol_errline" /tmp/pa11y-out.txt 2>/dev/null; then have_viol=1; fi
have_runerr=0
if grep -qE "$ran_errline" /tmp/pa11y-out.txt 2>/dev/null; then have_runerr=1; fi

if [ "$have_viol" -eq 0 ]; then
  if [ "$have_runerr" -eq 1 ]; then
    crash "pa11y-ci could not load the target page(s) — every URL reported \`Failed to run\`, twice (site unreachable from the runner, or Chromium failed to start). No page was audited."
  else
    crash "pa11y-ci exited $rc without reporting a per-URL result (missing binary, unwritable config, or a Chromium launch failure). No page was audited."
  fi
fi

# From here a real WCAG verdict exists.
if [ "$FAIL_ON_VIOLATIONS" = "true" ]; then
  note "- ❌ WCAG errors found (see log) — BLOCKING"
  finish 1
fi
note "- ⚠️ WCAG errors found (see log) — report-only; set \`fail-on-violations: true\` to block once clean"
finish 0
