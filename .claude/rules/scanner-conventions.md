---
paths:
  - "*/scripts/*.mjs"
  - "*/scripts/*.py"
  - "*/scripts/*.sh"
---
# Scanner entrypoint conventions

A fault in an entrypoint's own tooling is a fault in the gate, never a finding about the
caller's site. Report it as a fault and exit `FAIL_ON_<X> ? 1 : 0` — a bug here must never
newly-block a report-mode caller, and must never be laundered into a verdict about their code.

**Arm a crash guard before any statement that can fault**, and read the enforcement setting
from the environment, never from program state:

| language | guard | why the env read matters |
| --- | --- | --- |
| `.mjs` | `process.on('uncaughtException'/'unhandledRejection', …)` hoisted above the main invocation | a crash during const init leaves module consts in the temporal dead zone — reading one inside the handler throws `ReferenceError`, which loses the diagnostic and the exit code together (node then exits 7) |
| `.py` | `try/except` around `main()` under `if __name__` | `SystemExit` is not an `Exception`, so a deliberate verdict exit is never relabelled a crash |
| `.sh` | `trap … EXIT` on the first executable line, paired with a sentinel a deliberate exit sets | never `trap … ERR`: `set -u` aborts *without* firing `ERR`, and with errexit off `ERR` fires on non-fault commands too |

**Exempting an entrypoint from the guard is judged by misattribution, not by the exit code.**
An entrypoint with no report-mode input can still skip the guard when its own wrapper already
reports a failure for what it is; conversely, guard an entrypoint even with no report-mode input
the moment a bare wrapper failure would misattribute the fault to the caller (e.g. open an issue
blaming their site for a crawl that never ran). Mark a deliberate exemption with
`lint-allow-no-crash-guard: <reason>` (`#` in `.py`/`.sh`, `//` in `.mjs`) on the entrypoint — a
reason is required, and a bare pragma does not count.

**One level down: a scanner that could not look is not a PASS.** A crash guard only covers the
entrypoint itself dying. Anything that shells out to a scanner must also read that scanner's exit
status and report shape — "it printed nothing" and "it found nothing" look identical to a JSON
parser. Classify every run as *looked* or *could-not-look*, and grade a could-not-look leg as a
fault under the same `FAIL_ON_<X> ? 1 : 0` rule whenever that leg could have produced a blocking
finding (a WARN-only leg that could not look is listed, never treated as a fault).

**Known limit, not papered over:** for bash the crash-guard check matches any `trap … EXIT`, so a
pure cleanup trap reads as a guard. A behavioural self-test that actually crashes the real
entrypoint — not a static check — is what proves the guard fires. Mutation-test every new
self-test assertion: revert the fix (or neuter the condition) and confirm the assertion goes red;
one that survives its own bug reintroduced is worthless.

Mechanized (rules 2–3 of five) in `.github/scripts/lint-entrypoint-output.mjs`, scoped to the
scripts an `action.yml` actually executes.
