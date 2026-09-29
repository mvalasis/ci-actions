---
paths:
  - "*/scripts/*.mjs"
  - "*/scripts/*.py"
  - "*/scripts/*.sh"
  - "**/action.yml"
---
# Verify-token scoping conventions

Any action that attaches a caller-supplied bearer/verify token (the WAF-bypass header,
`X-Verify-Source`, from `VERIFY_TOKEN`/`VERIFY_HOMEPAGE_TOKEN`) to outbound requests has two
independent leak classes to close. Check both for any new script that sends the token.

## Class 1 — which host receives it

`curl -L`, `fetch`/undici, and Chromium all forward an arbitrary custom `X-*` request header
across a cross-origin redirect — they strip only `Cookie`/`Authorization` on a cross-host hop.
So gating the token by the *start* URL's host is not enough: a page that 3xx-redirects off-host
leaks it.

**Fix pattern:** never pass `-L` / `redirect: follow`. Follow redirects hop-by-hop and attach the
token only when the *current* hop's host is in an allowed-host set, re-evaluated at every hop —
seed the set from the caller's declared host plus every URL host actually being crawled, so a
same-host or subdomain child still gets the token while a cross-host one never does. Current
implementations: `seo-aeo/scripts/check.mjs` (`headersFor`/`followFetch`),
`linkcheck/scripts/linkcheck.py` (`_token_args`/`_hop`/`_follow`/`is_internal`) and
`linkcheck/scripts/sitemap-urls.py` (`is_allowed`/`_seed_allowed`) — `linkcheck/action.yml` passes
`LINKCHECK_HOST` through to the sitemap step too, so both scripts share one gate.

**`a11y-audit` is a deliberate, narrower exemption from this class** — do not re-plumb its pa11y
redirects into the hop-by-hop pattern above. `pa11y-ci`/`pa11y` apply configured headers via
*first-request-only* Puppeteer request interception (an `interceptionHandled` flag), never
`setExtraHTTPHeaders`, so the header rides only the navigation request to each audited URL — never
a same- or third-party subresource, never a redirect target. This property belongs to the PINNED
`pa11y`/`pa11y-ci` versions, not to this action's own code: re-verify token scope on any
`pa11y-ci` major bump. It is measured, not just read from source — a real-install self-test
(`a11y-audit/scripts/selftest-install.sh` + `selftest-fixtures.mjs`) installs the pinned
`pa11y`/`pa11y-ci`/Chrome for Testing from the committed lock and checks the token against two
live loopback origins on every change to the lock. `verify-homepage/scripts/render-check.mjs`,
`contract-check/scripts/check.mjs` and `form-protection/scripts/check.mjs` set the header
in-process (no redirect-follow of their own to worry about) and are not this class either.

## Class 2 — where the token sits on the runner

Host scoping says nothing about exposure on the runner itself: a token in a child process's argv
is readable by `ps` (`/proc/<pid>/cmdline`) from every other process on the runner, and is
recorded verbatim by any argv-logging wrapper on `PATH`; an exported variable reaches every child
(the browser, npm deps); a file written under the default umask is world-readable.

**Rule:** curl gets the header from `-H @file`, the file mode 600 inside a private mode-0700
directory (`mktemp -d`) removed on every exit path, including a crash — inside the crash guard's
own cleanup, not after it; a child process runs with the variable name **not** exported
(`export -n`) so it cannot inherit it. `security-baseline/scripts/argv-secret.mjs` also runs as
one of the entrypoint lint's rules (`.github/scripts/lint-entrypoint-output.mjs`) over this repo's
own action scripts, so a new script that spells a header value from a `TOKEN`/`SECRET`/`KEY`/
`PASS`-named variable straight into argv fails the lint before it fails anything else. A name that
only looks secret takes `# lint-allow-argv-secret: <why this is not a secret>` (`//` in `.mjs`) on
the flagged line or the line above.

## Regression guards

Host scoping: an offline self-test stands up two loopback servers on different hostnames and
asserts the token never reaches the external one across a redirect chain (including a redirect
loop and a compressed response). Runner scoping: a self-test puts an argv-logging stub first on
`PATH` over every call the entrypoint makes, and asserts cleanup runs on both the normal and the
crashing exit path.
