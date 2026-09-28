#!/usr/bin/env bash
#
# selftest-pins.sh — install-pinned.sh and the pins it reads, tested (v1.21.0).
#
#   bash security-baseline/scripts/selftest-pins.sh [--offline]
#
# (O) offline: every pin in tool-pins.txt is well-formed and equals its `<tool>-version` default
#     in security-baseline/action.yml (osv-scanner's in deps-currency/action.yml too); semgrep's
#     default equals the lock's; every `*-sha256` input defaults to empty, so a moved version can
#     never borrow the pinned digest; the lock pins every package `==` with hashes and allows
#     wheels only; and no action.yml or workflow downloads a release binary, pip-installs, pipes
#     curl into a shell or tar, or npm-installs a package at anything but an exact version, outside
#     the installer.
# (N) the real release assets: each binary's pin installs; the digest of another asset, a version
#     moved without a digest (nothing downloaded: a curl stub on PATH logs every call, and a
#     control proves the stub is the curl the installer runs), a malformed digest or version, a
#     failed download and an unknown tool each exit 1 with their own message and install nothing,
#     and a binary already in place stays as it was; a moved version with its right digest, and
#     the pin in GitHub's `sha256:<HEX>` spelling, install. No temp dir outlives a run.
# (S) semgrep, on Linux x86_64 with python3 >= 3.10 (required on CI, skipped with a note on a
#     laptop): a version moved without a digest is refused before any venv exists; the digest of
#     another wheel is refused by pip and links nothing; the lock installs a semgrep that runs;
#     the pinned version with its right digest (the override path) installs.
#
# Each installer run gets its own INSTALL_DIR and RUNNER_TEMP under one private dir, so nothing
# lands on the runner's PATH and nothing here sees an install another step made. The installer's
# own `::error` lines are printed indented, so they are not raised as annotations of this run.
# Exit 0 = every assertion held.

set -uo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
sb="$root/security-baseline"
installer="$sb/scripts/install-pinned.sh"
pins="$sb/tool-pins.txt"
lock="$sb/semgrep-requirements.txt"
tools='gitleaks trufflehog osv-scanner hadolint'
offline=0
[ "${1:-}" = --offline ] && offline=1

fail=0
n=0
ok() { n=$((n + 1)); echo "ok   $1"; }
bad() { n=$((n + 1)); fail=1; echo "::error title=selftest-pins::$1"; }
# check DESCRIPTION COMMAND...: one assertion.
check() {
	local d="$1"
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}
has() { case "$1" in *"$2"*) return 0 ;; esac; return 1; }
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# default_of FILE INPUT: an action.yml input's `default:`, quotes stripped.
default_of() {
	awk -v k="  $2:" '
		index($0, k) == 1 && length($0) == length(k) { f = 1; next }
		f && /^  [A-Za-z]/ { exit }
		f && /^    default:/ { sub(/^    default:[ \t]*/, ""); gsub(/["\047]/, ""); print; exit }' "$1"
}
pin_version() { awk -v t="$1" '$1 == t { print $2 }' "$pins"; }
pin_sha() { awk -v t="$1" '$1 == t { print $3 }' "$pins"; }

echo "== (O) the pins agree with every action.yml, and nothing installs around them"
for t in $tools; do
	check "tool-pins.txt: exactly one pin for $t" [ "$(awk -v t="$t" '$1 == t' "$pins" | wc -l | tr -d ' ')" = 1 ]
	check "tool-pins.txt: $t's digest is 64 lowercase hex digits" eval '[[ "$(pin_sha '"$t"')" =~ ^[0-9a-f]{64}$ ]]'
done
check "tool-pins.txt: pins these four tools and nothing else" \
	[ "$(awk '!/^#/ && NF { print $1 }' "$pins" | sort | tr '\n' ' ')" = "gitleaks hadolint osv-scanner trufflehog " ]
for pair in gitleaks:gitleaks trufflehog:trufflehog osv:osv-scanner hadolint:hadolint; do
	input="${pair%%:*}-version" t="${pair#*:}"
	check "security-baseline/action.yml: $input defaults to $t's pin ($(pin_version "$t"))" \
		[ "$(default_of "$sb/action.yml" "$input")" = "$(pin_version "$t")" ]
done
check "deps-currency/action.yml: osv-version defaults to osv-scanner's pin" \
	[ "$(default_of "$root/deps-currency/action.yml" osv-version)" = "$(pin_version osv-scanner)" ]
lock_version="$(sed -n 's/^semgrep==\([^ ;\\]*\).*/\1/p' "$lock")"
check "the lock pins semgrep exactly once" [ "$(grep -c '^semgrep==' "$lock")" = 1 ]
check "security-baseline/action.yml: semgrep-version defaults to the lock's semgrep ($lock_version)" \
	[ "$(default_of "$sb/action.yml" semgrep-version)" = "$lock_version" ]
for input in semgrep-sha256 gitleaks-sha256 trufflehog-sha256 osv-sha256 hadolint-sha256; do
	check "security-baseline/action.yml: $input defaults to empty (the pin applies only to the pinned version)" \
		eval '[ -z "$(default_of "$sb/action.yml" '"$input"')" ] && grep -q "^  '"$input"':$" "$sb/action.yml"'
done
check "deps-currency/action.yml: osv-sha256 defaults to empty" \
	eval '[ -z "$(default_of "$root/deps-currency/action.yml" osv-sha256)" ] && grep -q "^  osv-sha256:$" "$root/deps-currency/action.yml"'
check "the lock allows wheels only (--only-binary :all:)" grep -qx -- '--only-binary :all:' "$lock"
lock_problems="$(awk '
	function done_req() { if (name != "" && hashes == 0) print name ": no --hash"; name = ""; hashes = 0 }
	/^[[:space:]]*#/ || /^[[:space:]]*$/ || /^--/ { next }
	/^[A-Za-z0-9]/ {
		done_req(); name = $1
		if ($1 !~ /^[A-Za-z0-9][A-Za-z0-9._-]*==[^=]+$/) print $1 ": not pinned with =="
		reqs++
	}
	{ hashes += gsub(/--hash=sha256:[0-9a-f]{64}/, "&") }
	END { done_req(); if (reqs < 2) print "fewer than two requirements: " reqs }' "$lock")"
check "the lock pins every package == and hashes each${lock_problems:+ ($lock_problems)}" [ -z "$lock_problems" ]
surfaces=("$root"/*/action.yml "$root"/.github/workflows/*.yml)
around="$(grep -nE 'releases/download|pip3? install([^a-z]|$)|curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh|curl[^|]*\|[[:space:]]*tar|wget ' "${surfaces[@]}" | sed "s|^$root/||")"
check "no action.yml or workflow downloads a release, pip-installs or pipes curl into sh/tar outside install-pinned.sh${around:+: $around}" [ -z "$around" ]
floating="$(grep -nE 'npm (i|install) (-g|--global)' "${surfaces[@]}" | grep -vE '@[0-9]+\.[0-9]+\.[0-9]+([^0-9A-Za-z.-]|$)' | sed "s|^$root/||")"
check "every global npm install names an exact version${floating:+: $floating}" [ -z "$floating" ]
check "a11y-audit installs an exact pa11y-ci" grep -qE 'npm install -g pa11y-ci@[0-9]+\.[0-9]+\.[0-9]+$' "$root/a11y-audit/action.yml"

if [ "$offline" = 1 ]; then
	echo "== $n assertions (offline only)"
	exit "$fail"
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/selftest-pins.XXXXXX")" || { echo "::error::cannot create a work dir"; exit 1; }
trap 'rm -rf "$work"' EXIT

# inst NAME TOOL [VAR=VALUE...]: run the installer for TOOL with its own INSTALL_DIR
# ($work/NAME/bin) and RUNNER_TEMP ($work/NAME/tmp); sets $rc and $out, and $bin.
inst() {
	local name="$1" tool="$2"
	shift 2
	bin="$work/$name/bin"
	mkdir -p "$bin" "$work/$name/tmp"
	out="$(env -u PIN_VERSION -u PIN_SHA256 INSTALL_DIR="$bin" RUNNER_TEMP="$work/$name/tmp" "$@" bash "$installer" "$tool" 2>&1)"
	rc=$?
	local a shown=''
	for a in "$@"; do case "$a" in PATH=*) shown="$shown PATH=<curl stub first>" ;; *) shown="$shown $a" ;; esac; done
	echo "  -- $name: install-pinned.sh $tool$shown → exit $rc"
	printf '%s\n' "$out" | sed 's/^/     | /'
}

# Real digests of OTHER assets: well-formed, published, and wrong for what is downloaded.
gitleaks_8300='79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e' # gitleaks_8.30.0_linux_x64.tar.gz
semgrep_mac='ba18dbf4f293ed20834b69aae62b9352a089f2c9308e66f6eb43d67ca780e633'   # semgrep 1.178.0, macosx_10_14_x86_64 wheel
semgrep_linux='b7c4a4ba5cad1a6b0e76f7143c164b3f2853b9d0f902f2db2f64006257c941f2' # semgrep 1.178.0, manylinux_2_34_x86_64 wheel

echo "== (N) the release binaries, against the real assets"
for t in $tools; do
	inst "pin-$t" "$t"
	check "$t: the pin installs (exit 0, executable, verified against tool-pins.txt)" \
		eval '[ "$rc" = 0 ] && [ -x "$bin/'"$t"'" ] && has "$out" "verified against the pin in tool-pins.txt"'
done
# The installed file is the program, not the archive it came in (gitleaks and trufflehog ship as
# tar.gz): all four are Linux ELF executables, whatever machine this runs on.
for t in $tools; do
	check "$t: what was installed is an ELF executable, not an archive" \
		[ "$(head -c 4 "$work/pin-$t/bin/$t" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = 7f454c46 ]
done
for t in osv-scanner hadolint; do
	check "$t: what was installed is the pinned file itself" [ "$(sha256_of "$work/pin-$t/bin/$t" 2>/dev/null)" = "$(pin_sha "$t")" ]
done

inst wrong-digest gitleaks PIN_SHA256="$gitleaks_8300"
check "gitleaks 8.30.1 with 8.30.0's digest: exit 1, SHA-256 mismatch, nothing installed" \
	eval '[ "$rc" = 1 ] && has "$out" "SHA-256 mismatch, refusing to install it" && has "$out" "expected $gitleaks_8300 (gitleaks-sha256)" && [ ! -e "$bin/gitleaks" ]'
inst wrong-digest-raw osv-scanner PIN_SHA256="$(pin_sha hadolint)"
check "osv-scanner with hadolint's digest: exit 1, SHA-256 mismatch, nothing installed" \
	eval '[ "$rc" = 1 ] && has "$out" "SHA-256 mismatch" && [ ! -e "$bin/osv-scanner" ]'
mkdir -p "$work/keeps/bin" && printf 'previous\n' >"$work/keeps/bin/gitleaks"
inst keeps gitleaks PIN_SHA256="$gitleaks_8300"
check "a mismatch leaves the binary already in place as it was" \
	eval '[ "$rc" = 1 ] && [ "$(cat "$bin/gitleaks")" = previous ]'

mkdir -p "$work/stub"
printf '#!/bin/sh\necho "curl $*" >>"%s/curl.log"\nexit 22\n' "$work" >"$work/stub/curl"
chmod +x "$work/stub/curl"
inst stub-control gitleaks PATH="$work/stub:$PATH"
check "control: with the curl stub first on PATH the installer's download is the stub's (logged, exit 1, download failed)" \
	eval '[ "$rc" = 1 ] && has "$out" "download failed" && grep -q "gitleaks_8.30.1_linux_x64.tar.gz" "$work/curl.log"'
: >"$work/curl.log"
inst moved-no-digest gitleaks PIN_VERSION=8.30.0 PATH="$work/stub:$PATH"
check "gitleaks-version moved to 8.30.0 without gitleaks-sha256: exit 1, named, nothing downloaded" \
	eval '[ "$rc" = 1 ] && has "$out" "gitleaks 8.30.0 is not the pinned 8.30.1, and no gitleaks-sha256 was given" && [ ! -s "$work/curl.log" ] && [ ! -e "$bin/gitleaks" ]'
inst moved-with-digest gitleaks PIN_VERSION=8.30.0 PIN_SHA256="$gitleaks_8300"
check "gitleaks-version 8.30.0 with its own digest: installs, verified against gitleaks-sha256" \
	eval '[ "$rc" = 0 ] && [ -x "$bin/gitleaks" ] && has "$out" "gitleaks 8.30.0: sha256 $gitleaks_8300 verified against gitleaks-sha256"'
inst github-spelling hadolint PIN_SHA256="sha256:$(pin_sha hadolint | tr 'a-f' 'A-F')"
check "the pinned digest spelled sha256:<UPPERCASE> (GitHub's API form) is accepted" \
	eval '[ "$rc" = 0 ] && [ -x "$bin/hadolint" ]'
inst bad-digest trufflehog PIN_SHA256=abc123
check "a digest that is not 64 hex digits: exit 1, named" \
	eval '[ "$rc" = 1 ] && has "$out" "trufflehog-sha256 is not a SHA-256" && [ ! -e "$bin/trufflehog" ]'
inst bad-version osv-scanner PIN_VERSION='v2.4.0/../../../evil' PIN_SHA256="$(pin_sha osv-scanner)"
check "a version that is not a version (a path): exit 1, named" \
	eval '[ "$rc" = 1 ] && has "$out" "osv-version is not a version" && [ ! -e "$bin/osv-scanner" ]'
inst bad-version-dots hadolint PIN_VERSION='2..12' PIN_SHA256="$(pin_sha hadolint)"
check "a version holding '..': exit 1" eval '[ "$rc" = 1 ] && has "$out" "is not a version"'
inst no-release gitleaks PIN_VERSION=0.0.0 PIN_SHA256="$gitleaks_8300"
check "a release that does not exist: exit 1, download failed (not a digest mismatch), nothing installed" \
	eval '[ "$rc" = 1 ] && has "$out" "download failed" && ! has "$out" "mismatch" && [ ! -e "$bin/gitleaks" ]'
inst unknown notatool
check "an unknown tool: exit 1, named" eval '[ "$rc" = 1 ] && has "$out" "unknown tool '\''notatool'\''"'
check "no installer temp dir outlives its run" eval '[ -z "$(find "$work" -path "*/tmp/install-pinned.*" -print -quit)" ]'

echo "== (S) semgrep, from the hashed lock"
if [ "$(uname -sm)" != "Linux x86_64" ] || ! python3 -c 'import sys, venv; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		bad "semgrep legs need Linux x86_64 and python3 >= 3.10 with venv; this runner has $(uname -sm), $(python3 --version 2>&1)"
	else
		echo "skip semgrep legs: need Linux x86_64 and python3 >= 3.10 (have $(uname -sm), $(python3 --version 2>&1)); CI runs them"
	fi
else
	inst sg-moved-no-digest semgrep PIN_VERSION=1.177.0
	check "semgrep-version moved without semgrep-sha256: exit 1, named, before any venv exists" \
		eval '[ "$rc" = 1 ] && has "$out" "semgrep 1.177.0 is not the pinned $lock_version, and no semgrep-sha256 was given" && [ -z "$(ls "$work/sg-moved-no-digest/tmp")" ]'
	inst sg-wrong-digest semgrep PIN_SHA256="$semgrep_mac"
	check "semgrep with another wheel's digest: pip refuses, exit 1, nothing linked, no venv left" \
		eval '[ "$rc" = 1 ] && has "$out" "pip refused to install it from semgrep-sha256" && has "$out" "THESE PACKAGES DO NOT MATCH THE HASHES" && [ ! -e "$bin/semgrep" ] && [ ! -e "$work/sg-wrong-digest/tmp/semgrep-$lock_version-venv" ]'
	inst sg-pin semgrep
	check "semgrep: the lock installs, and the linked semgrep runs as $lock_version" \
		eval '[ "$rc" = 0 ] && has "$out" "verified against the hashed lock" && [ "$(SEMGREP_SEND_METRICS=off "$bin/semgrep" --version 2>/dev/null)" = "$lock_version" ]'
	inst sg-override semgrep PIN_VERSION="$lock_version" PIN_SHA256="$semgrep_linux"
	check "semgrep $lock_version with its manylinux x86_64 digest (the override path): installs" \
		eval '[ "$rc" = 0 ] && has "$out" "verified against semgrep-sha256" && [ -L "$bin/semgrep" ]'
fi

echo "== $n assertions, $([ "$fail" = 0 ] && echo 'all held' || echo 'FAILED')"
exit "$fail"
