#!/usr/bin/env bash
# A pull_request checkout, scanned by scan.mjs with the REAL trufflehog (v1.19.6).
# The selftest workflow's other real-scanner runs are pushes: a sha for a base (event.before), a
# checkout on a branch. A pull_request run is neither. actions/checkout leaves it DETACHED on
# GitHub's test merge with no local branch, and its base arrives as a ref NAME (origin/<base_ref>),
# which trufflehog resolves in its own clone of the checkout, where that name does not exist: every
# PR run scanned nothing until v1.19.0 and FAULTed from v1.19.0 to v1.19.5. And trufflehog walks
# `git log` newest commit date first and stops at the base, so a walk from the test merge never
# reached a PR commit dated before the base branch's tip.
# This builds that shape, a PR one commit off main dated before main's tip, and fails unless the
# walk reaches the PR's commit and none of main's. --only-verified is swapped for an offline pass
# that prints unverified results, so a planted token (minted per run, never live) shows what was
# walked; it pins the walk on every trufflehog-version bump. Needs git, node, openssl, trufflehog
# (or $REAL_TRUFFLEHOG) and gitleaks (or $GITLEAKS_BIN); semgrep has nothing in scope here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sb-pr-shape.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fail() { echo "::error title=security-baseline self-test::$1"; exit 1; }
g() { git -c user.name=selftest -c user.email=selftest@example.invalid -c commit.gpgsign=false -c init.defaultBranch=main "$@"; }
commit() { # <iso date> <file> <line> <message>
  printf '%s\n' "$3" > "$2"
  g add "$2"
  GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" g commit -qm "$4"
}
# Token-shaped values are minted per run: a literal one committed here would trip this repo's scan.
tok() { printf 'ghp_%s' "$(openssl rand -hex 18)"; }

cd "$work"
g init -q up
(
  cd up
  commit 2026-09-01T10:00:00Z README.md base 'where the PR leaves main'
  g checkout -qb feature
  commit 2026-09-01T11:00:00Z pr.txt "pr_token = \"$(tok)\"" 'the PR, dated before main tip'
  g checkout -q main
  commit 2026-09-01T12:00:00Z main.txt "main_token = \"$(tok)\"" 'main moves on'
)
# What actions/checkout does on a pull_request: every branch as origin/*, GitHub's test merge
# checked out detached, no local branch.
g init -q pr
cd pr
g fetch -q --no-tags ../up '+refs/heads/*:refs/remotes/origin/*'
g checkout -q --detach refs/remotes/origin/main
GIT_COMMITTER_DATE=2026-09-01T13:00:00Z g merge -q --no-ff --no-edit refs/remotes/origin/feature
g update-ref refs/remotes/pull/1/merge HEAD
g checkout -q --detach refs/remotes/pull/1/merge
[ -z "$(git for-each-ref refs/heads)" ] || fail 'the PR-shaped checkout has a local branch, so it is not the shape under test'

hits="$work/trufflehog-hits.jsonl"
wrap="$work/trufflehog-offline"
cat > "$wrap" <<'SH'
#!/usr/bin/env bash
a=()
for x in "$@"; do
  if [[ $x == --only-verified ]]; then a+=(--no-verification --results=unverified); else a+=("$x"); fi
done
"${REAL_TRUFFLEHOG:-trufflehog}" "${a[@]}" | tee -a "$HITS"
exit "${PIPESTATUS[0]}"
SH
chmod +x "$wrap"
out="$work/report.log"
# GITHUB_ACTIONS empty: gitleaks flags the planted tokens too, and they are worth no annotation.
HITS="$hits" TRUFFLEHOG_BIN="$wrap" GITHUB_ACTIONS='' GITHUB_STEP_SUMMARY='' \
  SCAN_SCOPE=diff VERIFIED_SECRETS=on FAIL_ON_CRITICAL=false ENABLE_SECRETS_HISTORY=false ENABLE_SCA=false \
  SEMGREP_SEND_METRICS=off BASE_REF='' GITHUB_BASE_REF=main GITHUB_EVENT_BEFORE='' PR_HEAD_SHA="$(git rev-parse HEAD^2)" \
  node "$here/scan.mjs" | tee "$out" || true
! grep -Eq 'could not look|security-baseline crashed' "$out" || fail 'a scanner leg could not look on a pull_request checkout; see the report above'
grep -q '"file":"pr.txt"' "$hits" || fail "trufflehog did not walk the PR's commit (pr.txt), so a PR behind its base would pass unscanned"
! grep -q '"file":"main.txt"' "$hits" || fail "trufflehog walked a main commit the PR does not hold (main.txt), which is pre-existing state"
echo "✅ pull_request checkout: trufflehog walked the PR's commit and none of main's"
