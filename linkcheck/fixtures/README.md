# linkcheck fixtures

A tiny static site served on `127.0.0.1:8099` by the **issue-lifecycle** job in
`.github/workflows/linkcheck-selftest.yml`. It exists so the real composite action can be
run end-to-end with **GitHub's own `if:` evaluator** deciding the issue steps — the one
thing `scripts/selftest.py` structurally cannot do, and the gap that let this action spend
weeks closing its own broken-links issue on every run that found broken links.

## The four verdict branches, one fixture each

| pass | sitemap | host | crawler | verdict | the action must |
|---|---|---|---|---|---|
| broken | `sitemap_index.xml` → `broken.html` | `127.0.0.1` | rc 1 | `broken` | OPEN the issue |
| fault | `sitemap_index_clean.xml` | *(empty)* | rc 2 | `fault` | do NOTHING |
| unset | `no-such-sitemap.xml` | `127.0.0.1` | never runs | *(null)* | do NOTHING |
| clean | `sitemap_index_clean.xml` → `clean.html` | `127.0.0.1` | rc 0 | `clean` | CLOSE the issue |

**`unset` is the load-bearing one.** The 2026-09-04 incident was an *unwritten* output
compared to a numeric literal (`outputs.rc == '0'` is TRUE when `rc` is null, because both
coerce to numbers). A partial relapse that restores the numeric conditions while keeping
the `set +e` guard passes broken/fault/clean and fails **only** here. Deleting this pass
re-opens the hole while leaving the job green — don't.

The bogus sitemap makes `sitemap-urls.py` yield zero URLs, so `action.yml`'s
`[ "$N" -gt 0 ]` aborts the composite **before** the crawl step, which is what makes
`steps.crawl.outputs.verdict` genuinely null. Its oracle is the **absence** of
`linkcheck-verdict.txt` (the crawl step deletes that file on entry and writes it on exit).

## Two rules when editing these fixtures

1. **Never serve a WAF fingerprint** — `x-amzn-waf-action`, `cf-mitigated`, `cf-chl-bypass`
   or `x-cache: error from cloudfront`. Those route a URL to the REVIEW queue, which makes
   `linkcheck.py` write `linkcheck-review.txt`, which the composite uploads as an artifact
   under a **fixed name**. `upload-artifact@v4` rejects a duplicate name within one run, so
   two passes producing review output would 409 the job. Python's `http.server` emits no
   such headers, which is why this is safe today and fragile if you change it.
2. **Keep it offline.** Every URL must be `127.0.0.1:8099`. One external link would make a
   CI gate depend on somebody else's uptime — the failure mode this whole action reports on.
