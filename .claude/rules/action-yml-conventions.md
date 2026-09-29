---
paths:
  - "**/action.yml"
  - "**/action.yaml"
---
# action.yml conventions

**Never shadow a `GITHUB_`-prefixed ambient runner variable in a composite step's own `env:`.**
The runner already exports variables such as `GITHUB_ACTION_REPOSITORY` ambiently into every step
of a composite action. Writing `env: { GITHUB_ACTION_REPOSITORY: ${{ github.action_repository }} }`
does not "pass it through" — it SHADOWS the ambient copy with the context value, and the context
value is EMPTY when the action is invoked by a local `./` ref (exactly how this repo's own
selftest workflows invoke every action). Two independent sources collapse into one, and the one
that survives is the empty one.

**Rule:** pass the context value under a NON-`GITHUB_`-prefixed name, and read both in the
script, context value first: `env: { ACTION_REPOSITORY: ${{ github.action_repository }} }`, then
`env.ACTION_REPOSITORY || env.GITHUB_ACTION_REPOSITORY` in the script. Applies to any `GITHUB_*`
context/env pairing a composite action's own `env:` block might be tempted to "restate", not just
this one (`GITHUB_REPOSITORY` is the identical shape).

Not obvious enough to skip a regression test for: two scripts independently wrote this exact bug
the same day. A unit assertion that injects env directly cannot see it — it never exercises the
`action.yml` → script wiring at all. Pin it with one end-to-end run of the real entrypoint through
the real `action.yml`, asserting both that the non-prefixed name IS read and that the
`GITHUB_`-prefixed one is NOT written by this action's own `env:`.
