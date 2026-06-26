# security-baseline

Air-gapped security gate — **semgrep** SAST (community rules, telemetry OFF) +
**gitleaks** secret scan. Nothing leaves the runner, so it is sovereignty-safe (no
US-SaaS egress) on GitHub-hosted or self-hosted EU runners alike.

Blocks the build on semgrep findings at/above the severity threshold, or any
gitleaks-detected secret.

## Caller

```yaml
# .github/workflows/security-baseline.yml
name: security-baseline
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # diff scope needs git history
      - uses: mvalasis/ci-actions/security-baseline@v1
        with:
          scan-scope: diff        # changed files vs base-ref
          semgrep-severity: ERROR # block on ERROR only (lowest noise)
```

## Inputs

| input | default | notes |
|---|---|---|
| `semgrep-config` | `p/security-audit` | registry id or local path; **vendor a local rules file for a full air-gap** |
| `semgrep-severity` | `ERROR` | minimum severity that BLOCKS |
| `scan-scope` | `diff` | `diff` (vs `base-ref`) or `full` (whole tree) |
| `base-ref` | _(auto)_ | PR base, else `HEAD~1` |
| `fail-on-secrets` | `true` | gitleaks gate |
| `gitleaks-version` | `8.18.4` | pinned release |
| `semgrep-version` | _(latest)_ | pin for reproducibility |

## Sovereignty

- `semgrep` runs with `--metrics=off` + `--disable-version-check` → no telemetry, no
  update pings. Public-registry rule fetch downloads *rule definitions* only (never your
  code); vendor a local rules file to remove even that.
- `gitleaks` is a self-contained binary — zero network, zero egress.
- Result: the gate works identically on an EU self-hosted runner with no behaviour change.
