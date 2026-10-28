# Guarded CAPTCHA challenges (`src/brocode/challenges.py`)

Bounded replacement for the unsafe legacy automatic solver. Scope is
deliberately narrow: **reCAPTCHA v2 on an exact in-scope host, single
attempt, explicit per-action approval** — everything else fails closed.

## What it does

- `classify_challenge(state, page_url, allowed_domains)` — pure classification
  of a `DETECT_JS`-shaped snapshot (no page access here; detection JS stays in
  the worker's isolated world). Out-of-scope pages, hard blocks, unready
  widgets, and non-`recaptcha-v2` kinds return explicit error codes, never a
  silent fallback.
- `SolverProvider` + `validate_provider_url` — one configured HTTPS provider
  on an explicitly allowlisted host. HTTP, arbitrary hosts, embedded
  credentials, and non-default ports are rejected before approval.
- `build_solve_permission` — per-action `ApprovalRequest` with the external-
  solver disclosure ("page URL and sitekey leave the egress boundary; cost
  unknown") and fingerprints/lengths only. Sitekeys, tokens, and credentials
  never appear in approvals, events, or logs (`repr` is redacted; tests
  assert this).
- `revalidate_binding` — page/frame/widget fingerprint comparison for the two
  mandatory rechecks: after approval and after the solver wait. Any change
  aborts with `PAGE_CHANGED_DURING_APPROVAL` / `WIDGET_CHANGED_DURING_APPROVAL`.
- `decide_token_delivery` — currently **always unsupported**
  (`CAPTCHA_TOKEN_BINDING_UNAVAILABLE`). The legacy injector traverses
  `data-callback` attributes and the `___grecaptcha_cfg` object graph with
  suppressed exceptions, so it cannot prove exactly one widget callback
  fired. Any solver token is discarded; success is never claimed.
- `human_fallback_guidance` — the supported fallback: genuine caller input
  with the live browser open (`ask_caller` while live, or a new scoped task
  after reconciliation once terminated). No pretended auto-solve, no tile
  driving.
- `guarded_solve` — orchestrates the above over injected boundaries only
  (`approve`, `reobserve`, `SolverClient` protocol). No browser, network,
  environment, archive, or state access; no import of `INJECT_JS_TEMPLATE`
  or `solve_if_present`.

## What it explicitly does not do (non-goals)

- No token injection, callback traversal, retries, tile driving, or bypass.
- No worker/policy/controller edits (this change owns only `challenges.py`,
  `tests/test_challenges.py`, and this doc).
- No `NoCaptchaAIClient` calls, no `INJECT_JS`, no `solve_if_present`.

## Turnstile provider client

`infra.captcha.NoCaptchaAIClient.solve_turnstile` now implements the documented
TurnstileTaskProxyLess create/poll API. It uses one creation attempt, a bounded
wall-clock wait, sanitized errors, an exact HTTPS provider endpoint, denied
redirects, and bounded responses. Cancellation or timeout may leave a billable
remote task; it does not retry. The returned token is private and must never be
logged. Synthetic tests cover the API contract; no paid/live solver test has been
performed. The underlying blocking HTTP request may finish after cancellation,
but redirects and automatic creation retries remain disabled.

This provider method is NOT connected to worker challenge dispatch. It does not
solve the Indeed challenge end to end. A managed Cloudflare challenge may need
more context than a standalone Turnstile token, and no such compatibility is
claimed. Legacy injection remains disabled.

## Provider authentication checks

`NoCaptchaAIClient.validate` uses authenticated GET `/balance` with the `apikey`
header. POST `/getBalance` is unsuitable for credential validation because it can
return a zero balance for an invalid key. Validation shares the exact endpoint,
redirect denial, disabled environment proxies, and response size limit used by
the task transport. Errors are sanitized; a success requires a numeric balance.
Zero balance is reported separately from a rejected key.

The opt-in checks in [Indeed prerequisites](indeed-prerequisites.md) exercise the
installed relay and this authentication request without opening a browser or
creating a paid solver task. A valid key does not prove challenge compatibility
or browser token delivery.

## Worker integration needed for an actual solve (not implemented here)

1. Keep `audit_captcha` / `solve_captcha` dispatch disabled
   (`CAPTCHA_AUTOMATION_DISABLED`) until a reviewer approves a design.
2. To enable solving later, the worker — not this module — must provide:
   - isolated-world detection feeding `classify_challenge`;
   - `policy.authorize("solve_captcha", …)` with the disclosure approval from
     `build_solve_permission`, in `confirm` mode with an operation key;
   - revalidation via `revalidate_binding` after approval and after the
     solver wait, plus `policy.check_scope` on every fresh URL;
   - an **atomic exact-widget delivery primitive** (single bound callback
     through the isolated context, verified single-effect) to replace the
     `decide_token_delivery` fail-closed branch — without it, delivery stays
     `CAPTCHA_TOKEN_BINDING_UNAVAILABLE` and any token is discarded;
   - uncertainty latching (`UNCERTAIN_MUTATION`) on any dispatch-side
     ambiguity; never retry a possibly-executed step without reconciliation.
3. The existing `infra.captcha.NoCaptchaAIClient` provider calls may be
   reused behind a `SolverClient` adapter, but its `INJECT_JS` /
   `solve_if_present` path must stay unused.
4. Run `brocode doctor` before any live browser work; never change host
   traffic, egress, or proxy settings for a challenge.
