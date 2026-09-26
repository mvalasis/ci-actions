#!/usr/bin/env bash
# The shapes the selftest workflow's own runs never produce, scanned by scan.mjs with the REAL
# trufflehog (v1.19.6, v1.19.7) and gitleaks (v1.19.8). The workflow's other real-scanner runs are pushes of this repo's
# linear history: a sha for a base (event.before), a checkout on a branch.
# 1. A pull_request checkout. actions/checkout leaves it DETACHED on GitHub's test merge with no local
#    branch, and its base arrives as a ref NAME (origin/<base_ref>), which trufflehog resolves in its
#    own clone of the checkout, where that name does not exist: every PR run scanned nothing until
#    v1.19.0 and FAULTed from v1.19.0 to v1.19.5. And trufflehog walks `git log` newest commit date
#    first and stops at the base, so a walk from the test merge never reached a PR commit dated
#    before the base branch's tip. Here: a PR one commit off main, dated before main's tip.
# 2. A PR that merged its base in, with one commit dated before the base commit it merged. One walk
#    from the PR head stops at that base commit first (v1.19.6); v1.19.7 walks from every segment tip.
# 3. A push of a merge commit whose merged branch holds a commit dated before event.before.
# 4. A push of an octopus merge: three branches at once, each dated before event.before.
# Each fails unless the walk reaches every commit of the range and none of the base's.
# 5. gitleaks' range past a clock skew (v1.19.8), as a push and as a pull_request: main's seven commits
#    after the fork are dated before it, so `git log <base>..HEAD` lists the fork, which main holds,
#    and the REAL gitleaks reads its key. It fails unless the PR's key is secret-pattern and the
#    fork's secrets-history, never secret-pattern; its controls fail when git or gitleaks stop
#    reading the fork into the range, since the shape would then test nothing.
# --only-verified is swapped for an offline pass that prints unverified results, so planted tokens
# (minted per run, never live) show what was walked; it pins the walk on every trufflehog-version
# bump, and shape 5 pins gitleaks' range on every gitleaks-version bump. Needs git, node, openssl,
# trufflehog (or $REAL_TRUFFLEHOG) and gitleaks (or $GITLEAKS_BIN); semgrep has nothing in scope here.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sb-pr-shape.XXXXXX")"
trap 'rm -rf "$work"' EXIT
# Every failed check is reported, and the script exits 1 at the end: one shape failing hides no other.
fail() { echo "::error title=security-baseline self-test::$1"; echo "$1" >> "$work/failed"; }
fails() { if [ -f "$work/failed" ]; then wc -l < "$work/failed" | tr -d ' '; else echo 0; fi; }
passed() { [ "$(fails)" -ne "$1" ] || echo "✅ $2"; }   # <failures before the shape> <what it showed>
g() { git -c user.name=selftest -c user.email=selftest@example.invalid -c commit.gpgsign=false -c init.defaultBranch=main "$@"; }
commit() { # <iso date> <file> <line> <message>
  printf '%s\n' "$3" > "$2"
  g add "$2"
  GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" g commit -qm "$4"
}
# Token-shaped values are minted per run: a literal one committed here would trip this repo's scan.
tok() { printf 'ghp_%s' "$(openssl rand -hex 18)"; }
# What actions/checkout does on a pull_request: every branch as origin/*, GitHub's test merge of
# feature into main checked out detached, no local branch.
pr_checkout() { # <upstream> <checkout> <test merge's iso date>
  g init -q "$2"
  (
    cd "$2"
    g fetch -q --no-tags "$1" '+refs/heads/*:refs/remotes/origin/*'
    g checkout -q --detach refs/remotes/origin/main
    GIT_COMMITTER_DATE="$3" g merge -q --no-ff --no-edit refs/remotes/origin/feature
    g update-ref refs/remotes/pull/1/merge HEAD
    g checkout -q --detach refs/remotes/pull/1/merge
    [ -z "$(git for-each-ref refs/heads)" ] || fail 'the PR-shaped checkout has a local branch, so it is not the shape under test'
  )
}

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
# scan <checkout> <name> <env…>: scan.mjs over the checkout; every trufflehog result lands in $work/<name>.hits.
# GITHUB_ACTIONS empty: gitleaks flags the planted tokens too, and they are worth no annotation.
scan() {
  local dir="$1" name="$2"
  shift 2
  : > "$work/$name.hits"
  (cd "$dir" && env HITS="$work/$name.hits" TRUFFLEHOG_BIN="$wrap" GITHUB_ACTIONS='' GITHUB_STEP_SUMMARY='' \
    SCAN_SCOPE=diff VERIFIED_SECRETS=on FAIL_ON_CRITICAL=false ENABLE_SECRETS_HISTORY=false ENABLE_SCA=false \
    SEMGREP_SEND_METRICS=off "$@" node "$here/scan.mjs") | tee "$work/$name.log" || true
  ! grep -Eq 'could not look|security-baseline crashed' "$work/$name.log" || fail "$name: a scanner leg could not look; see the report above"
}
hit() { grep -q "\"file\":\"$2\"" "$work/$1.hits"; }

cd "$work"
# ---- 1. a pull_request checkout, the PR one commit off main and dated before main's tip ----
n=$(fails)
g init -q up
(
  cd up
  commit 2026-09-01T10:00:00Z README.md base 'where the PR leaves main'
  g checkout -qb feature
  commit 2026-09-01T11:00:00Z pr.txt "pr_token = \"$(tok)\"" 'the PR, dated before main tip'
  g checkout -q main
  commit 2026-09-01T12:00:00Z main.txt "main_token = \"$(tok)\"" 'main moves on'
)
pr_checkout "$work/up" "$work/pr" 2026-09-01T13:00:00Z
scan "$work/pr" pr BASE_REF='' GITHUB_BASE_REF=main GITHUB_EVENT_BEFORE='' PR_HEAD_SHA="$(git -C "$work/pr" rev-parse HEAD^2)"
hit pr pr.txt || fail "trufflehog did not walk the PR's commit (pr.txt), so a PR behind its base would pass unscanned"
! hit pr main.txt || fail "trufflehog walked a main commit the PR does not hold (main.txt), which is pre-existing state"
passed "$n" "pull_request checkout: trufflehog walked the PR's commit and none of main's"

# ---- 2. a PR that merged its base in: one PR commit older than the base commit it merged ----
n=$(fails)
g init -q up2
(
  cd up2
  commit 2026-09-02T10:00:00Z fork.txt "fork_token = \"$(tok)\"" 'where the PR leaves main'
  g checkout -qb feature
  commit 2026-09-02T10:30:00Z pr-old.txt "old_token = \"$(tok)\"" 'the PR, dated before the base commit it merges'
  commit 2026-09-02T12:30:00Z pr-mid.txt "mid_token = \"$(tok)\"" 'the PR, dated after it'
  g checkout -q main
  commit 2026-09-02T12:00:00Z base-merged.txt "base_token = \"$(tok)\"" 'main moves on; the PR merges this in'
  g checkout -q feature
  GIT_AUTHOR_DATE=2026-09-02T13:00:00Z GIT_COMMITTER_DATE=2026-09-02T13:00:00Z g merge -q --no-ff --no-edit main
  commit 2026-09-02T14:00:00Z pr-new.txt "new_token = \"$(tok)\"" 'the PR goes on'
  g checkout -q main
  commit 2026-09-02T15:00:00Z main-after.txt "after_token = \"$(tok)\"" 'main moves on again'
)
pr_checkout "$work/up2" "$work/pr2" 2026-09-02T16:00:00Z
scan "$work/pr2" pr2 BASE_REF='' GITHUB_BASE_REF=main GITHUB_EVENT_BEFORE='' PR_HEAD_SHA="$(git -C "$work/pr2" rev-parse HEAD^2)"
for f in pr-old.txt pr-mid.txt pr-new.txt; do
  hit pr2 "$f" || fail "a PR that merged its base in: trufflehog did not walk $f, a commit of the PR"
done
for f in base-merged.txt main-after.txt fork.txt; do
  ! hit pr2 "$f" || fail "a PR that merged its base in: trufflehog walked $f, a base commit, which is pre-existing state"
done
grep -q 'walked from 2 segment tips' "$work/pr2.log" || fail 'a PR that merged its base in: the report does not say it took two walks'
passed "$n" "a PR that merged its base in: trufflehog walked all three of the PR's commits and none of main's"

# ---- 3. a push: a branch merged onto main with a merge commit, its commit older than event.before ----
n=$(fails)
g init -q push
(
  cd push
  commit 2026-09-03T10:00:00Z fork.txt "fork_token = \"$(tok)\"" 'where the branch leaves main'
  g checkout -qb topic
  commit 2026-09-03T11:00:00Z topic.txt "topic_token = \"$(tok)\"" 'the branch, dated before event.before'
  g checkout -q main
  commit 2026-09-03T12:00:00Z before.txt "before_token = \"$(tok)\"" 'event.before: main tip before the push'
  GIT_AUTHOR_DATE=2026-09-03T13:00:00Z GIT_COMMITTER_DATE=2026-09-03T13:00:00Z g merge -q --no-ff --no-edit topic
)
scan "$work/push" push BASE_REF='' GITHUB_BASE_REF='' GITHUB_EVENT_BEFORE="$(git -C "$work/push" rev-parse HEAD^1)" PR_HEAD_SHA=''
hit push topic.txt || fail "a push of a merge: trufflehog did not walk topic.txt, the merged branch's commit"
for f in before.txt fork.txt; do
  ! hit push "$f" || fail "a push of a merge: trufflehog walked $f, which main held before the push"
done
passed "$n" "a push of a merge: trufflehog walked the merged branch's commit and none of main's"

# ---- 4. a push of an octopus merge: three branches at once, each dated before event.before ----
n=$(fails)
g init -q octo
(
  cd octo
  commit 2026-09-04T10:00:00Z fork.txt "fork_token = \"$(tok)\"" 'where the branches leave main'
  g checkout -qb a
  commit 2026-09-04T10:10:00Z a.txt "a_token = \"$(tok)\"" 'branch a, dated before event.before'
  g checkout -q main && g checkout -qb b
  commit 2026-09-04T10:20:00Z b.txt "b_token = \"$(tok)\"" 'branch b, dated before event.before'
  g checkout -q main && g checkout -qb c
  commit 2026-09-04T10:30:00Z c.txt "c_token = \"$(tok)\"" 'branch c, dated before event.before'
  g checkout -q main
  commit 2026-09-04T12:00:00Z before.txt "before_token = \"$(tok)\"" 'event.before: main tip before the push'
  GIT_AUTHOR_DATE=2026-09-04T13:00:00Z GIT_COMMITTER_DATE=2026-09-04T13:00:00Z g merge -q --no-ff --no-edit a b c
)
scan "$work/octo" octo BASE_REF='' GITHUB_BASE_REF='' GITHUB_EVENT_BEFORE="$(git -C "$work/octo" rev-parse HEAD^1)" PR_HEAD_SHA=''
for f in a.txt b.txt c.txt; do
  hit octo "$f" || fail "a push of an octopus merge: trufflehog did not walk $f, a merged branch's commit"
done
for f in before.txt fork.txt; do
  ! hit octo "$f" || fail "a push of an octopus merge: trufflehog walked $f, which main held before the push"
done
passed "$n" "a push of an octopus merge: trufflehog walked all three branches and none of main's"

# ---- 5. gitleaks' range past a clock skew: main's seven commits after the fork dated before it ----
n=$(fails)
g init -q skew
(
  cd skew
  commit 2026-09-08T09:00:00Z root.txt root "main's root"
  commit 2026-09-08T10:00:00Z fork.txt "fork_token = \"$(tok)\"" 'where the PR leaves main: a key that predates the PR'
  g checkout -qb feature
  commit 2026-09-08T11:00:00Z pr.txt "pr_token = \"$(tok)\"" "the PR's own key"
  g checkout -q main
  for i in 1 2 3 4 5 6 7; do commit "2026-09-08T08:0$((8 - i)):00Z" "x$i.txt" "x$i" 'main moves on, dated before its parent'; done
  g checkout -q feature
  GIT_AUTHOR_DATE=2026-09-08T12:00:00Z GIT_COMMITTER_DATE=2026-09-08T12:00:00Z g merge -q --no-ff --no-edit main
)
x7=$(git -C "$work/skew" rev-parse main)
fork=$(git -C "$work/skew" rev-parse main~7)
# Lists are read whole before grep sees them: under pipefail, a `grep -q` that stops reading early can
# fail the pipeline it matched in.
listed() { local l; l=$(git -C "$1" rev-list "$2"); grep -qx "$3" <<< "$l"; }   # <repo> <range> <commit>
git -C "$work/skew" merge-base --is-ancestor "$fork" "$x7" && listed "$work/skew" "$x7..HEAD" "$fork" \
  || fail "gitleaks' range past a clock skew: git's rev-list no longer lists the fork, which main holds, so this shape tests nothing"
"${GITLEAKS_BIN:-gitleaks}" detect --redact --no-banner --report-format json --report-path "$work/skew-range.json" --exit-code 0 \
  --source "$work/skew" --log-opts "$x7..HEAD" > /dev/null 2>&1 || true
node -e 'const a = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8") || "[]"); process.exit(a.some((f) => f.File === "fork.txt") ? 0 : 1)' "$work/skew-range.json" \
  || fail "gitleaks' range past a clock skew: gitleaks no longer reads the fork's key from <base>..HEAD, so this shape tests nothing"
# group <log> <check id>: that check's findings in the report.
group() { awk -v id="\`$2\`" 'index($0, "### ") == 1 { p = index($0, id) > 0; next } p' "$work/$1.log"; }
graded() { # <log> <shape>
  local sp sh
  sp=$(group "$1" secret-pattern)
  sh=$(group "$1" secrets-history)
  grep -q '^- ❌ pr\.txt:1 — ' <<< "$sp" || fail "$2: the PR's key is not secret-pattern"
  ! grep -q 'fork\.txt' <<< "$sp" || fail "$2: the fork's key, which the base holds, is secret-pattern: pre-existing state would block"
  grep -q '^- ⚠️ fork\.txt:1 — ' <<< "$sh" || fail "$2: the fork's key is not secrets-history"
  grep -q '^- gitleaks: its range listed a commit the base already holds' "$work/$1.log" || fail "$2: the report does not say why the fork's key is history"
}
scan "$work/skew" skew-push BASE_REF='' GITHUB_BASE_REF='' GITHUB_EVENT_BEFORE="$x7" PR_HEAD_SHA=''
graded skew-push "gitleaks' range past a clock skew, on a push"
pr_checkout "$work/skew" "$work/skew-pr" 2026-09-08T13:00:00Z
listed "$work/skew-pr" refs/remotes/origin/main..HEAD "$fork" \
  || fail "gitleaks' range past a clock skew: the pull_request checkout's range does not list the fork, so that shape tests nothing"
scan "$work/skew-pr" skew-pr BASE_REF='' GITHUB_BASE_REF=main GITHUB_EVENT_BEFORE='' PR_HEAD_SHA="$(git -C "$work/skew-pr" rev-parse HEAD^2)"
graded skew-pr "gitleaks' range past a clock skew, on a pull_request"
passed "$n" "gitleaks' range past a clock skew: the fork's key, which main holds, warns as history; the PR's is secret-pattern, on a push and a pull_request"
[ "$(fails)" -eq 0 ] || { echo "❌ $(fails) check(s) failed"; exit 1; }
