#!/usr/bin/env bash
# verify-signature: the commit must carry an SSH signature by a key in ALLOWED_SIGNERS. Ported from
# luxairportlu's scripts/deploy-verify-signature.sh (7654db4). Needs no token, network or key.
# Env: ALLOWED_SIGNERS (ssh-keygen's allowed-signers format; the principal only names the signer in
# the log, git matches the key), HEAD_SHA (the commit).
# Exit 0 = signed by a listed key; 1 = unsigned, GPG-signed (a merge GitHub made: the web button,
# `gh pr merge`, Dependabot) or SSH-signed by a key not listed; 2 = it could not verify: an empty list,
# no such commit, a runner too old, or its own crash. Every path but the first refuses the deploy.
finished=0
list=""
on_exit() {
  rc=$?
  [ -n "$list" ] && rm -f "$list"
  if [ "$finished" != 1 ]; then
    echo "::error title=Commit signature::verify-signature stopped before a verdict, rc $rc; nothing may deploy"
    exit 2
  fi
  exit "$rc"
}
trap on_exit EXIT
set -uo pipefail

refuse() { # <exit> <message>
  echo "::error title=Commit signature::$2"
  finished=1
  exit "$1"
}

sha="${HEAD_SHA:-}"
[ -n "$sha" ] || refuse 2 "no commit to verify; nothing may deploy"
signers="$(sed '/^[[:space:]]*$/d' <<<"${ALLOWED_SIGNERS:-}")"
[ -n "$signers" ] || refuse 2 "allowed-signers is empty: no key may sign a deploy, so nothing may deploy"
git cat-file -e "$sha^{commit}" 2>/dev/null || refuse 2 "$sha is not a commit in this checkout; nothing may deploy"

umask 077
list="$(mktemp)" || { list=""; refuse 2 "mktemp failed; nothing may deploy"; }
printf '%s\n' "$signers" > "$list" || refuse 2 "could not write the list; nothing may deploy"

# What the commit carries, read off the object itself. Only an SSH signature is ever verified.
header="$(git cat-file commit "$sha" | sed '/^$/q')"
if ! grep -q '^gpgsig' <<<"$header"; then
  kind=none
elif grep -qE '^gpgsig(-sha256)? -----BEGIN SSH SIGNATURE-----' <<<"$header"; then
  kind=ssh
elif grep -qE '^gpgsig(-sha256)? -----BEGIN PGP SIGNATURE-----' <<<"$header"; then
  kind=pgp
else
  kind=other
fi

g=(git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen -c "gpg.ssh.allowedSignersFile=$list" -c gpg.minTrustLevel=fully)
out=""
if [ "$kind" = ssh ]; then
  if out="$("${g[@]}" verify-commit "$sha" 2>&1)"; then
    who="$("${g[@]}" log -1 --format='%GS' "$sha" 2>/dev/null)"
    echo "ok  $sha is signed by ${who:-a listed key}"
    finished=1
    exit 0
  fi
  if grep -qE 'is needed for ssh signature verification|openssh version|gpg\.format|allowedSignersFile needs to be configured|cannot run ssh-keygen|No such file' <<<"$out"; then
    refuse 2 "this runner cannot verify SSH signatures (git 2.34+ and OpenSSH 8.2+ are needed): $(tail -n 1 <<<"$out"); nothing may deploy"
  fi
fi

case "$kind" in
  none) refuse 1 "$sha is not signed. A deploy's tip must be a commit an operator signed with a listed key: commit.gpgsign true and gpg.format ssh" ;;
  pgp) refuse 1 "$sha is GPG-signed, which is what GitHub does to a merge it makes (the web button, gh pr merge, Dependabot). Merge locally with --no-ff" ;;
  ssh) refuse 1 "$sha carries an SSH signature that does not verify against the listed keys. A key is added by a signed commit to the workflow's allowed-signers" ;;
  *) refuse 1 "$sha carries a signature of a kind this gate does not accept; only an SSH signature by a listed key deploys" ;;
esac
