#!/usr/bin/env bash
# selftest-nosem.sh — the semgrep behaviour `sast-suppressed` rests on, measured on the real semgrep (v1.32.0).
#
#   bash security-baseline/scripts/selftest-nosem.sh        (needs semgrep on PATH, or $SEMGREP_BIN)
#
# scan.mjs runs every semgrep leg with --disable-nosem and emits a result whose `extra.is_ignored` is
# true as `sast-suppressed` (T1 WARN, promotable): a `// nosemgrep` comment on the scanned line no
# longer removes the finding, it names it. That reading is the pinned semgrep's, not this repo's — a
# semgrep that dropped the flag, or stopped marking the results it would have removed, would report
# every nosemgrep'd finding under its own id, or remove it again as every leg did before v1.32.0 —
# and selftest.mjs stubs semgrep, so only the real one can say it still holds. A one-rule config and
# a two-line file, scanned twice:
#   with --disable-nosem      2 results: line 1 (the nosemgrep'd one) is_ignored true, line 2 not
#   without it, the control   1 result, line 2: the comment removed line 1
# Exit 0 = every assertion held; a failure prints one ::error per assertion and semgrep's stderr.
set -uo pipefail
SG="${SEMGREP_BIN:-semgrep}"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/selftest-nosem.XXXXXX")" || { echo "::error title=security-baseline self-test::selftest-nosem: cannot create a work dir"; exit 1; }
trap 'rm -rf "$work"' EXIT
fail=0
# check DESCRIPTION COMMAND...: one assertion (a compound test goes through eval).
check() {
	local d="$1"
	shift
	if "$@"; then echo "  ✅ $d"; else fail=1; echo "::error title=security-baseline self-test::selftest-nosem: $d"; fi
}

cat >"$work/rule.yaml" <<'EOF'
rules:
  - id: selftest-sink
    languages: [javascript]
    severity: ERROR
    message: selftest sink
    pattern: dangerous($X)
EOF
printf 'dangerous(a); // nosemgrep\ndangerous(b);\n' >"$work/a.js"

# scan NAME [FLAG...]: one run, spelled as scan.mjs spells its legs; the JSON lands in $work/NAME.json,
# semgrep's stderr in $work/NAME.err.
scan() {
	local name="$1"
	shift
	"$SG" scan --json --metrics=off --disable-version-check --quiet --no-git-ignore "$@" \
		--config "$work/rule.yaml" "$work/a.js" >"$work/$name.json" 2>"$work/$name.err"
}
# results NAME: how many results the run reported; `unreadable` when it printed no JSON.
results() {
	python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("results", [])))' \
		"$work/$1.json" 2>/dev/null || echo unreadable
}
# ignored NAME LINE: the `extra.is_ignored` of the result on LINE — true, false, unset (a result with no
# such field), absent (no result on that line), or how many results share the line.
ignored() {
	python3 -I - "$work/$1.json" "$2" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print(f"unreadable ({type(e).__name__})"); sys.exit(0)
hits = [r for r in d.get("results", []) if isinstance(r, dict) and r.get("start", {}).get("line") == int(sys.argv[2])]
if len(hits) != 1:
    print("absent" if not hits else f"{len(hits)} results on the line"); sys.exit(0)
v = hits[0].get("extra", {}).get("is_ignored", "unset")
print("true" if v is True else "false" if v is False else "unset" if v == "unset" else repr(v))
EOF
}

echo "== semgrep $("$SG" --version 2>/dev/null | tail -1): a nosemgrep comment with and without --disable-nosem"
scan with --disable-nosem
rc=$?
check "with --disable-nosem: semgrep looked (exit 0; got $rc)" [ "$rc" = 0 ]
check "with --disable-nosem: both lines are reported ($(results with) results)" [ "$(results with)" = 2 ]
check "with --disable-nosem: line 1, under the nosemgrep comment, is reported with extra.is_ignored true (got $(ignored with 1))" \
	[ "$(ignored with 1)" = true ]
check "with --disable-nosem: line 2, uncommented, is reported and not is_ignored (got $(ignored with 2))" \
	eval '[ "$(ignored with 2)" = false ] || [ "$(ignored with 2)" = unset ]'
scan without
rc=$?
check "control, no flag: semgrep looked (exit 0; got $rc)" [ "$rc" = 0 ]
check "control, no flag: the comment removed line 1 — $(results without) result(s), line 1 $(ignored without 1)" \
	eval '[ "$(results without)" = 1 ] && [ "$(ignored without 1)" = absent ]'
check "control, no flag: line 2 is still reported (got $(ignored without 2))" [ "$(ignored without 2)" != absent ]

if [ "$fail" != 0 ]; then
	for f in with without; do
		[ -s "$work/$f.err" ] && { echo "  -- semgrep's stderr, the '$f' run:"; sed 's/^/     /' "$work/$f.err"; }
	done
	echo "❌ selftest-nosem failed"
else
	echo "✅ selftest-nosem: a nosemgrep'd finding under --disable-nosem is reported and flagged; removed without the flag"
fi
exit "$fail"
