# form-protection

Bot-gate-enforced-end-to-end CI gate. Fetches the listed form pages from the
live site (JS-disabled, the way a bot sees them), finds every form carrying a
bot widget (`.cf-turnstile`, `.g-recaptcha`, `.h-captcha`, `[data-sitekey]`),
and asserts the protection is REAL on both ends:

| id | sev | what it catches |
|---|---|---|
| `sitekey-real` | **CRITICAL** | `data-sitekey` missing/empty or a known **test/placeholder key** (Turnstile `1x`/`2x`/`3x` force-keys + the `0x000…0` placeholder, reCAPTCHA `6LeIxAcT…` universal test pair, hCaptcha `10000000-ffff-…` test keys; extend via `test-sitekeys`). A test key passes every client — the widget is decorative. |
| `server-rejects` | **CRITICAL** | the resolved submit endpoint **accepts** (2xx) a tokenless POST or a junk-token POST — the server never calls siteverify (skip-verify). With `expect=` set, a reject **without** the bot-gate's signature is also CRITICAL: the reject came from field validation, so the gate never fired. |
| `endpoint-unknown` | WARN | widget form with no `<form action>` and no `form-endpoints` match — probe skipped, add a mapping. |
| `no-gated-form` | WARN | a wired page has no widget form and no map match — widget removed / selector drift / wrong URL. |
| `probe-inconclusive` | WARN | endpoint answered 3xx (PRG ambiguity) or 5xx — verification unconfirmed. |
| `widget-not-static` | INFO | mapped surface whose widget is client-rendered; static sitekey check skipped (an inline-script `sitekey`/`turnstileSiteKey = "…"` literal is still classified when present). |

This is the conversation-independent form of the §Security "bot-protection
enforced END-TO-END" check in `~/.claude/DISCIPLINES.md` — built because the
incident class it hunts actually shipped (EPN 2026-06: test sitekey AND a
skip-verifying server, both invisible in a client-side click-test).

## Why the probe is read-safe

The POST probes send a **minimal body** — no realistic form fields, only the
(absent or junk) token field. A correctly-gated endpoint rejects before any
side-effect. A *broken* endpoint falls through to its own field validation and
rejects the empty payload — so the probe still cannot create a record, send
mail, or place an order. That fall-through is also why `expect=` matters: it
distinguishes the bot-gate's reject signature from a later layer's, catching
skip-verify servers that hide behind a field-validation 400.

## Inputs

Mirrors `seo-aeo`: `urls` / `sitemap-url`, `fail-on-critical` (default
`false` — report-first), `max-urls`, `verify-token` (host-scoped
`X-Verify-Source`). Plus:

- **`submit-probe`** (default `true`) — set `false` only where a live POST has
  no safe rejection path at all; you lose the entire server-side half.
- **`form-endpoints`** — for JS-driven forms whose submit URL isn't in the
  `<form action>`. One entry per line:

  ```
  <css-selector> => <endpoint> [mode=json] [token=<field>] [expect=<substring>]
  ```

  The selector matches the form element **or anything inside it** (a widget
  container id works). `mode=json` posts a JSON body (default: urlencoded).
  `token` names the token field for the junk-token probe (defaults:
  `cf-turnstile-response`/`g-recaptcha-response`/`h-captcha-response` by widget
  type in form mode, `turnstileToken` in json mode). `expect` is the bot-gate's
  reject-body signature. Lines starting with `#` that carry no `=>` are comments.
- **`test-sitekeys`** — extra values to treat as test keys; trailing `*` = prefix.

## Wired callers

- **epn-astro** — `/contact/` + `/employers/` (static `data-sitekey`, forms POST
  `/api/contact`, reject = `403 {"ok":false,"error":"turnstile_failed"}`).
- **lampakia-astro** — `/checkout/` (client-rendered widget, JSON endpoint
  `/api/checkout/create-order`, `token=turnstileToken expect=turnstile_failed`).

## Honest limits

Distinguishes *present-vs-absent* enforcement, not a weak secret from a strong
one. A client-rendered widget's sitekey is only checked when an inline-script
literal exposes it. Without `expect=`, a non-2xx from ANY layer reads as a
reject — set the signature wherever you know it. Endpoints that only accept
authenticated/stateful POSTs may need `submit-probe: false` + a manual note.

## Self-test

`node scripts/selftest.mjs` — engine fixtures (sitekey classification, map
parsing, epn/lampakia-shaped pages, verdict table) plus a local `node:http`
server e2e that runs the real CLI subprocess against fixture pages and
reject/accept/wrong-layer endpoints, asserting summaries AND exit codes.
No external network. CI: `.github/workflows/form-protection-selftest.yml`
(+ a live report-mode smoke against epn.one).
