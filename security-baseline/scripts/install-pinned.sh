#!/usr/bin/env bash
#
# install-pinned.sh — install one pinned third-party tool, verified before it is installed.
#
#   install-pinned.sh <tool>
#     tool         gitleaks | trufflehog | osv-scanner | hadolint   (release binaries, ../tool-pins.txt)
#                  chrome-for-testing                             (a zip, ../tool-pins.txt; a11y-audit)
#                  semgrep                                        (pip, ../semgrep-requirements.txt)
#     PIN_VERSION  the caller's <tool>-version input; '' = the pinned version
#     PIN_SHA256   the caller's <tool>-sha256 input; '' = the pinned digest. REQUIRED when
#                  PIN_VERSION is not the pinned version: a caller who moves a pin names the digest
#                  of what they moved it to, or nothing is installed.
#     INSTALL_DIR  where the tool lands (default /usr/local/bin; sudo only when it is not writable).
#                  chrome-for-testing is a directory: it lands as $INSTALL_DIR/chrome-linux64/, its
#                  executable chrome-linux64/chrome, and INSTALL_DIR must be writable (no sudo).
#                  No action input moves it: a11y-audit installs the pin, the build puppeteer-core in
#                  a11y-audit/package-lock.json launches.
#
# Until v1.21.0 the release binaries were pinned by release TAG only (`curl | tar`, trufflehog's
# without -f) and semgrep was whatever `pip install semgrep` resolved on the day: a replaced
# release asset, or a compromised maintainer account, ran on every caller's runner. Now:
#   - a release binary is downloaded to a private temp dir and installed only when its SHA-256
#     equals the pin (tool-pins.txt), or the caller's own digest when one is given;
#   - semgrep and every dependency it pulls are installed from a hashed lock with pip
#     --require-hashes --only-binary :all:, into a fresh virtualenv, so no package is taken from
#     what the runner already had and nothing is built from source. A caller moving semgrep's
#     version swaps only semgrep's line for `semgrep==<version> --hash=sha256:<their digest>`;
#     its dependencies stay the lock's, and a version they do not satisfy fails the step.
# Any mismatch, missing digest, malformed input or failed download fails the step with
# ::error, before anything is installed. There is no report-mode path around it: a binary
# that does not hash to its pin is never run.
#
# lint-allow-no-crash-guard: a failed download or digest check must fail the step in every mode — installing and running an unverified binary is never the fallback — and each error names the tool, the version and the pin, so the failure is the supply chain's, never read as a finding about the caller's code. There is no report-mode input to consult here.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tool="${1:-}"
version="${PIN_VERSION:-}"
want="${PIN_SHA256:-}"
dir="${INSTALL_DIR:-/usr/local/bin}"
# The action inputs that feed PIN_VERSION / PIN_SHA256, named in every message: osv-scanner's
# are osv-version and osv-sha256.
input="$tool"
[ "$tool" = osv-scanner ] && input=osv

die() {
	echo "::error title=${tool:-install-pinned} install::$*"
	exit 1
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# A digest is 64 hex digits; GitHub's API prints it as `sha256:<hex>`, so that prefix is accepted.
if [ -n "$want" ]; then
	want="$(printf '%s' "${want#sha256:}" | tr 'A-F' 'a-f')"
	[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$tool: ${input}-sha256 is not a SHA-256 (64 hex digits): '${PIN_SHA256}'"
fi
# The version is spliced into a URL (or a requirement): digits, letters, '.', '_', '+', '-' only.
if [ -n "$version" ] && { ! [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || [[ "$version" == *..* ]]; }; then
	die "$tool: ${input}-version is not a version: '$version'"
fi

base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
tmp="$(mktemp -d "$base/install-pinned.XXXXXX")" || die "$tool: cannot create a temp dir under $base"
trap 'rm -rf "$tmp"' EXIT

# place SRC NAME: put SRC (a file, or the venv's entry point for semgrep) in INSTALL_DIR as NAME.
place() {
	local src="$1" name="$2" how=(install -m 0755)
	[ "$tool" = semgrep ] && how=(ln -sf)
	mkdir -p "$dir" 2>/dev/null || sudo mkdir -p "$dir" || return 1
	if [ -w "$dir" ]; then "${how[@]}" "$src" "$dir/$name"; else sudo "${how[@]}" "$src" "$dir/$name"; fi
}

if [ "$tool" = semgrep ]; then
	lock="$here/../semgrep-requirements.txt"
	[ -f "$lock" ] || die "semgrep: the lock $lock is missing"
	[ "$(grep -c '^semgrep==' "$lock")" = 1 ] || die "semgrep: $lock must pin semgrep exactly once"
	pinned="$(sed -n 's/^semgrep==\([^ ;\\]*\).*/\1/p' "$lock")"
	version="${version:-$pinned}"
	req="$lock" why="the hashed lock semgrep-requirements.txt"
	if [ -n "$want" ]; then
		# The lock with semgrep's entry (its line and every --hash continuation) swapped for the
		# caller's version and digest; every other package keeps its pinned version and hashes.
		awk -v v="$version" -v h="$want" '
			skip && /^[[:space:]]+--hash=/ { next }
			{ skip = 0 }
			/^semgrep==/ { print "semgrep==" v " --hash=sha256:" h; skip = 1; next }
			{ print }' "$lock" >"$tmp/semgrep-requirements.txt" || die "semgrep: cannot write the requirements for $version"
		req="$tmp/semgrep-requirements.txt" why="semgrep-sha256, beside the lock's hashed dependencies"
	elif [ "$version" != "$pinned" ]; then
		die "semgrep $version is not the pinned $pinned, and no semgrep-sha256 was given. A caller overriding semgrep-version must also set semgrep-sha256: the SHA-256 of the wheel pip installs on this runner (curl -s https://pypi.org/pypi/semgrep/$version/json | jq -r '.urls[] | select(.filename | test(\"manylinux.*x86_64\")) | .digests.sha256')."
	fi
	venv="$base/semgrep-$version-venv"
	rm -rf "$venv"
	python3 -m venv "$venv" || die "semgrep: python3 -m venv failed (is python3-venv installed?)"
	if ! "$venv/bin/python" -m pip install --quiet --disable-pip-version-check --no-input \
		--require-hashes --only-binary :all: -r "$req"; then
		rm -rf "$venv"
		die "semgrep $version: pip refused to install it from $why (a hash mismatch, a dependency the lock does not hold, or a failed download; pip's reason is above). Nothing was installed."
	fi
	place "$venv/bin/semgrep" semgrep || die "semgrep: cannot link $venv/bin/semgrep into $dir"
	echo "semgrep $version: every package verified against $why → $dir/semgrep"
	exit 0
fi

pins="$here/../tool-pins.txt"
case "$tool" in
gitleaks | trufflehog | osv-scanner | hadolint | chrome-for-testing) ;;
*) die "unknown tool '$tool' (gitleaks, trufflehog, osv-scanner, hadolint, chrome-for-testing, semgrep)" ;;
esac
[ -f "$pins" ] || die "$tool: the pin file $pins is missing"
pin="$(awk -v t="$tool" '$1 == t { print $2, $3; n++ } END { exit n == 1 ? 0 : 1 }' "$pins")" ||
	die "$tool: $pins must hold exactly one pin for it"
read -r pinned pinned_sha <<<"$pin"
[[ "$pinned_sha" =~ ^[0-9a-f]{64}$ ]] || die "$tool: its pin in $pins is not a SHA-256: '$pinned_sha'"
version="${version:-$pinned}"
if [ -n "$want" ]; then
	why="${input}-sha256"
elif [ "$version" = "$pinned" ]; then
	want="$pinned_sha" why="the pin in tool-pins.txt"
else
	die "$tool $version is not the pinned $pinned, and no ${input}-sha256 was given. A caller overriding ${input}-version must also set ${input}-sha256 to the SHA-256 of the release asset it downloads (gh api repos/<owner>/<repo>/releases/tags/<tag> --jq '.assets[] | {name, digest}'). Nothing was downloaded."
fi

member=''
case "$tool" in
gitleaks)
	url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
	member=gitleaks
	;;
trufflehog)
	url="https://github.com/trufflesecurity/trufflehog/releases/download/v${version}/trufflehog_${version}_linux_amd64.tar.gz"
	member=trufflehog
	;;
osv-scanner)
	# osv-scanner v2.x names its asset without the version; the release tag carries it.
	url="https://github.com/google/osv-scanner/releases/download/${version}/osv-scanner_linux_amd64"
	;;
hadolint)
	url="https://github.com/hadolint/hadolint/releases/download/v${version}/hadolint-Linux-x86_64"
	;;
chrome-for-testing)
	# The URL puppeteer's own browser download uses for this build (@puppeteer/browsers). Chrome for
	# Testing publishes no checksum or signature, so the pin is a digest hashed at pin time and
	# cross-checked against the bucket's own metadata (tool-pins.txt says how).
	url="https://storage.googleapis.com/chrome-for-testing-public/${version}/linux64/chrome-linux64.zip"
	;;
esac

# -f: an HTTP error fails here instead of saving the error page as the "binary" (the v1.4.2
# osv-scanner defect); it would fail the digest check anyway, but the message would mislead.
curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' -o "$tmp/asset" "$url" ||
	die "$tool $version: download failed: $url. Nothing was installed."
got="$(sha256_of "$tmp/asset")"
[ "$got" = "$want" ] ||
	die "$tool $version: SHA-256 mismatch, refusing to install it. Downloaded $got, expected $want ($why), from $url. Nothing was installed."
if [ "$tool" = chrome-for-testing ]; then
	# Extracted from the verified file only, into this run's temp dir, and moved into place whole:
	# a failure anywhere before the move leaves INSTALL_DIR as it was.
	command -v unzip >/dev/null 2>&1 || die "$tool $version: unzip is not installed, so the verified archive cannot be extracted. Nothing was installed."
	unzip -q "$tmp/asset" -d "$tmp/x" || die "$tool $version: unzip failed on the verified archive $url. Nothing was installed."
	[ -x "$tmp/x/chrome-linux64/chrome" ] || die "$tool $version: chrome-linux64/chrome is not in the verified archive $url. Nothing was installed."
	{ mkdir -p "$dir" && [ -w "$dir" ] && rm -rf "$dir/chrome-linux64" && mv "$tmp/x/chrome-linux64" "$dir/chrome-linux64"; } ||
		die "$tool $version: cannot install it into $dir (it must be writable)"
	echo "$tool $version: sha256 $got verified against $why → $dir/chrome-linux64/chrome"
	exit 0
fi
src="$tmp/asset"
if [ -n "$member" ]; then
	tar -xzf "$tmp/asset" -C "$tmp" "$member" || die "$tool $version: $member is not in the verified archive $url"
	src="$tmp/$member"
fi
place "$src" "$tool" || die "$tool $version: cannot install it into $dir"
echo "$tool $version: sha256 $got verified against $why → $dir/$tool"
