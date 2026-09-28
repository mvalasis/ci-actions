#!/usr/bin/env bash
#
# selftest-install.sh — a11y-audit installed and run for real (v1.22.0): the half selftest.sh stubs.
#
#   bash a11y-audit/scripts/selftest-install.sh
#
# Needs Linux x86_64 (the Chrome pin is the linux64 build) and the network (the npm registry,
# Google's bucket): required on CI (a11y-audit-selftest.yml), skipped with a note elsewhere.
# Everything lands in one private dir, removed on exit, with the fixture servers.
#
# (I) install.sh, as the action runs it: pa11y-ci and every package the lock names, at the lock's
#     versions, with no lifecycle script run (puppeteer's postinstall would have downloaded a browser
#     into PUPPETEER_CACHE_DIR), alone in the bin dir it hands audit.sh; its Chrome is the pinned
#     build, and the pin is the build puppeteer-core in the lock launches; the action's own dir stays
#     as it was.
# (R) install-pinned.sh refuses Chrome for Testing under the digest of another asset (the same
#     build's mac-arm64 zip, published beside it): exit 1, nothing extracted, no temp dir left.
# (T) the real audit.sh, pa11y-ci and Chrome at two loopback origins (selftest-fixtures.mjs). The
#     verify-token rides the sitemap fetch and each audited navigation, and nothing else: no
#     subresource or fetch on either origin, no redirect target (selftest-fixtures.mjs check). The
#     canary reaches neither the log nor the summary. Violations are reported in report mode and
#     BLOCK in enforce mode; a clean page passes; none of them is reported as a crash.
# Exit 0 = every assertion held.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
installer="$root/security-baseline/scripts/install-pinned.sh"
lock="$root/a11y-audit/package-lock.json"
pin_version="$(awk '$1 == "chrome-for-testing" { print $2 }' "$root/security-baseline/tool-pins.txt")"
# The digest of chrome-mac-arm64.zip for the same build: well-formed, published, and wrong for linux64.
other_asset='20f0155e9d75a31d32d168691110cd8fbc4d66f75dc6d7a53c004cbea60290b9'

fail=0
n=0
ok() { n=$((n + 1)); echo "ok   $1"; }
bad() { n=$((n + 1)); fail=1; echo "::error title=a11y-audit selftest-install::$1"; }
# check DESCRIPTION COMMAND...: one assertion.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
indent() { sed 's/^/     | /'; }

if [ "$(uname -sm)" != "Linux x86_64" ]; then
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		bad "the real install needs Linux x86_64; this runner is $(uname -sm)"
		exit 1
	fi
	echo "skip: the real install needs Linux x86_64 (the Chrome pin is linux64); have $(uname -sm). CI runs it."
	exit 0
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/selftest-install.XXXXXX")" || {
	echo "::error::cannot create a work dir"
	exit 1
}
server=''
cleanup() {
	if [ -n "$server" ]; then kill "$server" 2>/dev/null; fi
	rm -rf "$work"
}
trap cleanup EXIT

echo "== (I) install.sh, as the action runs it"
before="$(ls -A "$root/a11y-audit")"
mkdir -p "$work/runner-temp"
: >"$work/github-output"
out="$(env -u PIN_VERSION -u PIN_SHA256 RUNNER_TEMP="$work/runner-temp" GITHUB_OUTPUT="$work/github-output" \
	PUPPETEER_CACHE_DIR="$work/puppeteer-cache" bash "$here/install.sh" 2>&1)"
rc=$?
printf '%s\n' "$out" | indent
check "install.sh exits 0" [ "$rc" = 0 ]
bin="$(sed -n 's/^bin=//p' "$work/github-output")"
chrome="$(sed -n 's/^chrome=//p' "$work/github-output")"
tools="${bin%/bin}"
check "its outputs name a bin dir and a Chrome inside one private dir under RUNNER_TEMP" \
	eval 'case "$bin" in "$work/runner-temp/a11y-audit-tools."*/bin) [ "$chrome" = "$tools/browser/chrome-linux64/chrome" ] ;; *) false ;; esac'
check "that dir is mode 0700" [ "$(stat -c %a "$tools" 2>/dev/null)" = 700 ]
check "the bin dir holds pa11y-ci and nothing else" [ "$(ls -A "$bin" 2>/dev/null)" = pa11y-ci ]
tree="$(node -e '
	const fs = require("fs"), path = require("path");
	const [lock, dir] = process.argv.slice(1);
	const bad = []; let n = 0;
	for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(lock, "utf8")).packages)) {
		if (!k) continue;
		n++;
		let got = "(missing)";
		try { got = JSON.parse(fs.readFileSync(path.join(dir, k, "package.json"), "utf8")).version; } catch {}
		if (got !== v.version) bad.push(`${k} ${got} (lock: ${v.version})`);
	}
	console.log(bad.length ? bad.join("; ") : `all ${n}`);' "$lock" "$tools" 2>&1)"
check "every package in the lock is installed, at the lock's version ($tree)" eval 'has "$tree" "all "'
lockv="$(node -p 'require(process.argv[1]).packages["node_modules/pa11y-ci"].version' "$lock")"
check "pa11y-ci on that PATH is the lock's $lockv" [ "$(PATH="$bin:$PATH" pa11y-ci --version 2>/dev/null)" = "$lockv" ]
check "no lifecycle script ran: puppeteer's postinstall downloaded no browser into PUPPETEER_CACHE_DIR" [ ! -e "$work/puppeteer-cache" ]
check "Chrome for Testing is the pinned build ($pin_version)" \
	[ "$("$chrome" --version 2>/dev/null | sed 's/[[:space:]]*$//')" = "Google Chrome for Testing $pin_version" ]
want="$(node -p 'require(process.argv[1]).PUPPETEER_REVISIONS.chrome' "$tools/node_modules/puppeteer-core/lib/cjs/puppeteer/revisions.js" 2>&1)"
check "the pin is the build puppeteer-core in the lock launches ($want)" [ "$want" = "$pin_version" ]
check "the action's own dir is as it was (nothing installed beside action.yml)" [ "$(ls -A "$root/a11y-audit")" = "$before" ]

echo "== (R) Chrome for Testing under the digest of another asset"
mkdir -p "$work/wrong/tmp"
out="$(env -u PIN_VERSION PIN_SHA256="$other_asset" INSTALL_DIR="$work/wrong/browser" RUNNER_TEMP="$work/wrong/tmp" \
	bash "$installer" chrome-for-testing 2>&1)"
rc=$?
printf '%s\n' "$out" | indent
check "exit 1, SHA-256 mismatch, nothing extracted, no temp dir left" \
	eval '[ "$rc" = 1 ] && has "$out" "SHA-256 mismatch, refusing to install it" && [ ! -e "$work/wrong/browser" ] && [ -z "$(ls -A "$work/wrong/tmp")" ]'

echo "== (T) the real audit.sh, pa11y-ci and Chrome, at two loopback origins"
node "$here/selftest-fixtures.mjs" serve "$work/requests.log" "$work/ports.json" &
server=$!
disown "$server" # killed by cleanup; without disown bash reports it as "Terminated"
for _ in $(seq 1 50); do
	[ -s "$work/ports.json" ] && break
	sleep 0.2
done
A="http://127.0.0.1:$(node -p 'require(process.argv[1]).A' "$work/ports.json" 2>/dev/null)"
B="http://127.0.0.1:$(node -p 'require(process.argv[1]).B' "$work/ports.json" 2>/dev/null)"
check "the fixture servers listen" eval '[ -s "$work/ports.json" ] && curl -fsS -o /dev/null "$A/page" && curl -fsS -o /dev/null "$B/landing"'
canary="a11y-canary-$$-$RANDOM$RANDOM"
major="${pin_version%%.*}"

# run_real NAME FAIL_ON_VIOLATIONS [VAR=VALUE...]: audit.sh as the action's Audit step runs it, the
# request log emptied first. Sets rc, and $log / $summary to its output and step summary.
run_real() {
	local name="$1" fov="$2"
	shift 2
	log="$work/$name.log" summary="$work/$name.summary.md"
	: >"$work/requests.log"
	: >"$summary"
	env -u VERIFY_TOKEN -u URLS -u SITEMAP_URL PATH="$bin:$PATH" PUPPETEER_EXECUTABLE_PATH="$chrome" \
		GITHUB_STEP_SUMMARY="$summary" FAIL_ON_VIOLATIONS="$fov" "$@" bash "$here/audit.sh" >"$log" 2>&1
	rc=$?
	echo "  -- $name: audit.sh, fail-on-violations $fov → exit $rc"
	indent <"$log"
	echo "     | -- step summary:"
	indent <"$summary"
}
not_crashed() { ! grep -q 'a11y-audit crashed' "$summary"; }

run_real report false VERIFY_TOKEN="$canary" SITEMAP_URL="$A/sitemap.xml" URLS="$A/redirect $A/violation"
check "report mode, violations on one page: exit 0" [ "$rc" = 0 ]
check "…pa11y-ci reported each URL: the sitemap's page, the redirect's landing, the violations" \
	eval 'grep -qF "> $A/page - 0 errors" "$log" && grep -qF "> $B/landing - 0 errors" "$log" && grep -qE "> $A/violation - [1-9][0-9]* errors" "$log"'
check "…the summary reports WCAG errors, report-only" eval 'grep -q "WCAG errors found" "$summary" && grep -q "report-only" "$summary"'
check "…not a crash" not_crashed
check "…and the canary is in neither the log nor the summary" eval '! grep -qF "$canary" "$log" "$summary"'
check "the verify-token rode the sitemap fetch and each audited navigation, and nothing else" \
	node "$here/selftest-fixtures.mjs" check "$work/requests.log" "$canary" /sitemap.xml,/page,/redirect,/violation --chrome-major "$major"

run_real enforce-clean true URLS="$A/page"
check "enforce mode, a clean page: exit 0, no WCAG errors, not a crash" \
	eval '[ "$rc" = 0 ] && grep -q "no WCAG" "$summary" && not_crashed'
check "…and with no verify-token set, no request carried one" eval '! grep -q "\"token\":\"" "$work/requests.log" && [ -s "$work/requests.log" ]'

run_real enforce-violation true URLS="$A/violation"
check "enforce mode, violations: exit 1, BLOCKING, not a crash" \
	eval '[ "$rc" = 1 ] && grep -q "BLOCKING" "$summary" && not_crashed'

echo "== $n assertions, $([ "$fail" = 0 ] && echo 'all held' || echo 'FAILED')"
exit "$fail"
