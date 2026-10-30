#!/usr/bin/env bash
# Offline: real git and ssh-keygen, throwaway keys, every verdict of verify.sh. Exit 0 = pass.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V="$HERE/verify.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fails=0
ok() { echo "  ✅ $1"; }
bad() { echo "  ❌ $1"; fails=$((fails + 1)); }
expect() { # <name> <exit> <needle> <env assignment…>
  local name="$1" want="$2" needle="$3" out rc
  shift 3
  out="$(cd "$T/repo" && env "$@" bash "$V" 2>&1)"; rc=$?
  if [ "$rc" = "$want" ] && grep -qF -- "$needle" <<<"$out"; then ok "$name"; else bad "$name: rc $rc, $out"; fi
}

export HOME="$T/home" GIT_CONFIG_NOSYSTEM=1
mkdir -p "$HOME" "$T/repo"
ssh-keygen -q -t ed25519 -N '' -C listed -f "$T/listed"
ssh-keygen -q -t ed25519 -N '' -C other -f "$T/other"
LIST="ops@test namespaces=\"git\" $(cut -d' ' -f1,2 "$T/listed.pub")"
cd "$T/repo" || exit 1
git init -q .
git config user.name t; git config user.email t@t; git config gpg.format ssh; git config commit.gpgsign false
c() { git -c user.signingkey="$1" commit -q --allow-empty ${1:+-S} -m "$2"; git rev-parse HEAD; }
# A commit object with one extra header line in front of the blank line that ends the headers.
with_header() { # <sha> <header lines>
  { git cat-file commit "$1" | sed '/^$/q' | sed '$d'; printf '%s\n' "$2"; git cat-file commit "$1" | sed '1,/^$/d' | { echo; cat; }; } | git hash-object -t commit -w --stdin
}

echo '# verify-signature'
SIGNED="$(c "$T/listed" signed)"
UNLISTED="$(c "$T/other" unlisted)"
UNSIGNED="$(c '' unsigned)"
PGP="$(with_header "$UNSIGNED" "gpgsig -----BEGIN PGP SIGNATURE-----
 AAAA
 -----END PGP SIGNATURE-----")"
ODD="$(with_header "$UNSIGNED" 'gpgsig -----BEGIN SIGNED MESSAGE-----')"

expect 'a commit a listed key signed passes, naming the signer' 0 'is signed by ops@test' ALLOWED_SIGNERS="$LIST" HEAD_SHA="$SIGNED"
expect 'blank lines around the list are ignored' 0 'is signed by ops@test' ALLOWED_SIGNERS="
$LIST

" HEAD_SHA="$SIGNED"
expect 'a key that is not listed is refused' 1 'does not verify against the listed keys' ALLOWED_SIGNERS="$LIST" HEAD_SHA="$UNLISTED"
expect 'an unsigned commit is refused' 1 'is not signed' ALLOWED_SIGNERS="$LIST" HEAD_SHA="$UNSIGNED"
expect 'a GPG-signed commit (a merge GitHub made) is refused' 1 'is GPG-signed' ALLOWED_SIGNERS="$LIST" HEAD_SHA="$PGP"
expect 'a signature of any other kind is refused' 1 'of a kind this gate does not accept' ALLOWED_SIGNERS="$LIST" HEAD_SHA="$ODD"
expect 'an empty list fails closed' 2 'allowed-signers is empty' ALLOWED_SIGNERS='   ' HEAD_SHA="$SIGNED"
expect 'an unset list fails closed' 2 'allowed-signers is empty' HEAD_SHA="$SIGNED"
expect 'no sha fails closed' 2 'no commit to verify' ALLOWED_SIGNERS="$LIST" HEAD_SHA=
expect 'a sha this checkout lacks fails closed' 2 'is not a commit in this checkout' ALLOWED_SIGNERS="$LIST" HEAD_SHA=1111111111111111111111111111111111111111

mkdir "$T/noskg"
for t in git sed grep mktemp rm tail bash env cat; do ln -s "$(command -v "$t")" "$T/noskg/$t"; done
expect 'a runner with no ssh-keygen fails closed' 2 'cannot verify SSH signatures' PATH="$T/noskg" ALLOWED_SIGNERS="$LIST" HEAD_SHA="$SIGNED"

mkdir "$T/nomktemp"
printf '#!/bin/sh\nexit 1\n' > "$T/nomktemp/mktemp"; chmod +x "$T/nomktemp/mktemp"
expect 'a mktemp that fails fails closed' 2 'mktemp failed' PATH="$T/nomktemp:$PATH" ALLOWED_SIGNERS="$LIST" HEAD_SHA="$SIGNED"

# The crash guard itself: a script that dies under it must still refuse.
sed 's/^umask 077$/exit 7/' "$V" > "$T/crash.sh"
out="$(cd "$T/repo" && ALLOWED_SIGNERS="$LIST" HEAD_SHA="$SIGNED" bash "$T/crash.sh" 2>&1)"; rc=$?
if [ "$rc" = 2 ] && grep -qF 'stopped before a verdict, rc 7' <<<"$out"; then ok 'a crash mid-script refuses, exit 2'; else bad "crash guard: rc $rc, $out"; fi

mkdir "$T/tmpdir"
expect 'a passing run' 0 'is signed' TMPDIR="$T/tmpdir" ALLOWED_SIGNERS="$LIST" HEAD_SHA="$SIGNED"
expect 'a refused run' 1 'is not signed' TMPDIR="$T/tmpdir" ALLOWED_SIGNERS="$LIST" HEAD_SHA="$UNSIGNED"
if [ -z "$(ls -A "$T/tmpdir")" ]; then ok '…neither leaves the list on disk'; else bad 'a list file was left behind'; fi

# The real action.yml wires the input and the sha under these names.
A="$HERE/../action.yml"
if grep -qF 'ALLOWED_SIGNERS: ${{ inputs.allowed-signers }}' "$A" && grep -qF 'HEAD_SHA: ${{ github.sha }}' "$A"; then ok 'action.yml passes the input and the sha'; else bad 'action.yml wiring'; fi

if [ "$fails" -eq 0 ]; then echo '✅ all verify-signature self-tests passed'; else echo "❌ $fails self-test(s) failed"; exit 1; fi
