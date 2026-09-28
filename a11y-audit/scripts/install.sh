#!/usr/bin/env bash
#
# install.sh — pa11y-ci and the Chrome it drives, each verified before it runs (v1.22.0).
#
#   bash a11y-audit/scripts/install.sh
#
# Into a private dir under $RUNNER_TEMP (mktemp -d, 0700; the runner empties RUNNER_TEMP after the
# job), never into the action's own dir or onto the job's PATH:
#   - pa11y-ci and every package it pulls, from the lockfile beside action.yml. `npm ci` installs
#     exactly the versions the lock names and checks each tarball against the lock's sha512
#     integrity. --ignore-scripts: no lifecycle script runs, so puppeteer's postinstall does not
#     download a browser of its own (it is the only install script in the lock);
#   - Chrome for Testing, the build puppeteer-core in the lock launches, through
#     security-baseline/scripts/install-pinned.sh: downloaded to a temp dir, and extracted only when
#     its zip hashes to the pin in security-baseline/tool-pins.txt.
# Step outputs (GITHUB_OUTPUT): `bin`, a dir holding pa11y-ci and nothing else, for audit.sh's PATH;
# `chrome`, the executable, for PUPPETEER_EXECUTABLE_PATH.
#
# Until v1.22.0 the step was `npm install -g pa11y-ci@4.1.1` (v1.21.0; the floating `@4` before):
# the top package was pinned, but its dependencies resolved within their ranges on every caller run,
# and puppeteer's postinstall downloaded the Chrome its version named, checked by nothing.
#
# lint-allow-no-crash-guard: an install that cannot be verified fails the step in every mode. A lock or digest mismatch is a supply-chain signal to be seen, the audit step never runs after it, and every message names the install, so it is never read as a verdict on the page.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
action="$(cd "$here/.." && pwd)"
installer="$action/../security-baseline/scripts/install-pinned.sh"

die() {
	echo "::error title=a11y-audit install::$*"
	exit 1
}

# The Chrome pin is the linux64 build, the only one Chrome for Testing publishes for Linux.
[ "$(uname -sm)" = "Linux x86_64" ] || die "a11y-audit runs on Linux x86_64 runners (ubuntu-latest); this one is $(uname -sm). Nothing was installed."
[ -f "$installer" ] || die "security-baseline/scripts/install-pinned.sh is missing beside a11y-audit ($installer). Nothing was installed."
base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
dir="$(mktemp -d "$base/a11y-audit-tools.XXXXXX")" || die "cannot create a private dir under $base. Nothing was installed."
cp "$action/package.json" "$action/package-lock.json" "$dir/" ||
	die "cannot copy the vendored package.json and package-lock.json into $dir. Nothing was installed."
(cd "$dir" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund) ||
	die "npm ci refused the vendored lock (a tarball that does not match its integrity hash, a lock that disagrees with package.json, or a registry that did not answer; npm's reason is above). Nothing was audited."
[ -x "$dir/node_modules/.bin/pa11y-ci" ] || die "npm ci left no node_modules/.bin/pa11y-ci in $dir"
# node_modules/.bin also links extract-zip, semver, js-yaml and more: none is for audit.sh's PATH.
{ mkdir -p "$dir/bin" && ln -s "$dir/node_modules/.bin/pa11y-ci" "$dir/bin/pa11y-ci"; } ||
	die "cannot link pa11y-ci into $dir/bin"

# Without PIN_VERSION / PIN_SHA256: a job-level env of those names must not move the pin.
env -u PIN_VERSION -u PIN_SHA256 INSTALL_DIR="$dir/browser" bash "$installer" chrome-for-testing || exit 1
chrome="$dir/browser/chrome-linux64/chrome"
[ -x "$chrome" ] || die "no Chrome for Testing at $chrome after its install"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	printf 'bin=%s\nchrome=%s\n' "$dir/bin" "$chrome" >>"$GITHUB_OUTPUT" || die "cannot write the step outputs to GITHUB_OUTPUT"
fi
echo "pa11y-ci $(node -p 'require(process.argv[1]).version' "$dir/node_modules/pa11y-ci/package.json"), every package verified against the vendored lock → $dir/bin/pa11y-ci"
