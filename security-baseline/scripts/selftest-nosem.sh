#!/usr/bin/env bash
# selftest-nosem.sh — the semgrep behaviour `sast-suppressed` rests on, measured on the real semgrep (v1.32.0).
#
#   bash security-baseline/scripts/selftest-nosem.sh        (needs semgrep on PATH, or $SEMGREP_BIN)
#
# scan.mjs runs every semgrep leg with --disable-nosem, under which semgrep KEEPS a finding a `nosemgrep`
# comment covers, and tells which one it kept by scanning the files that say `nosem` once more without
# the flag: a result that control run lacks is the suppression, emitted as `sast-suppressed` (T1 WARN,
# promotable) — a `// nosemgrep` comment on the scanned line no longer removes the finding, it names it.
# Both halves are the pinned semgrep's, not this repo's: a semgrep that dropped the flag would remove the
# finding as every leg did before v1.32.0, one that stopped honouring the comment would report it under
# its own id — and selftest.mjs stubs semgrep, so only the real one can say they still hold. (1.178.0
# marks nothing in its JSON — no `extra.is_ignored` on either result — which is why the control run
# exists; printed below, never asserted.) A one-rule config and a two-line file, scanned twice:
#   with --disable-nosem      2 results: line 1 (the nosemgrep'd one) kept beside line 2
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
# reported NAME LINE: whether the run reported the result on LINE — yes, absent, or how many results share
# the line. What scan.mjs's control run reads: a line the flagged run reported and the control did not.
reported() {
	python3 -I - "$work/$1.json" "$2" <<'EOF'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print(f"unreadable ({type(e).__name__})"); sys.exit(0)
hits = [r for r in d.get("results", []) if isinstance(r, dict) and r.get("start", {}).get("line") == int(sys.argv[2])]
print("yes" if len(hits) == 1 else "absent" if not hits else f"{len(hits)} results on the line")
EOF
}
# ignored NAME LINE: the `extra.is_ignored` of the result on LINE — true, false, unset (a result with no
# such field), absent (no result on that line), or how many results share the line. A NOTE, never an
# assertion: 1.178.0 writes no such field, and scan.mjs reads none — a later semgrep that writes one
# changes nothing here.
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
check "with --disable-nosem: line 1, under the nosemgrep comment, is kept (got $(reported with 1))" [ "$(reported with 1)" = yes ]
check "with --disable-nosem: line 2, uncommented, is reported (got $(reported with 2))" [ "$(reported with 2)" = yes ]
echo "  ℹ️  with --disable-nosem: extra.is_ignored is $(ignored with 1) on line 1 and $(ignored with 2) on line 2 — scan.mjs reads neither; the control run below tells them apart"
scan without
rc=$?
check "control, no flag: semgrep looked (exit 0; got $rc)" [ "$rc" = 0 ]
check "control, no flag: the comment removed line 1 — $(results without) result(s), line 1 $(reported without 1)" \
	eval '[ "$(results without)" = 1 ] && [ "$(reported without 1)" = absent ]'
check "control, no flag: line 2 is still reported (got $(reported without 2))" [ "$(reported without 2)" = yes ]

if [ "$fail" != 0 ]; then
	for f in with without; do
		[ -s "$work/$f.err" ] && { echo "  -- semgrep's stderr, the '$f' run:"; sed 's/^/     /' "$work/$f.err"; }
	done
	echo "❌ selftest-nosem failed"
else
	echo "✅ selftest-nosem: a nosemgrep'd finding is kept under --disable-nosem and removed without the flag — what scan.mjs's control run reads"
fi
exit "$fail"
