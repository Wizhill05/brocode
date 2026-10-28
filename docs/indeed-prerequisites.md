# Test Indeed Easy Apply prerequisites

The current procedure is `playbooks/indeed-easy-apply/PLAYBOOK.md`. It remains a
draft. The older historical `indeed-apply` seed has been removed.
The runtime now reads source procedures from the project's `playbooks/` directory;
private drafts still come from the configured state directory.

## Automated checks

Run the standard suite with `uv run --locked pytest -q`.

`tests/test_egress_connections.py` uses real loopback TCP connections to exercise
CONNECT tunneling, ordinary HTTP forwarding, proxy credential stripping,
rejection and truncated responses, malformed status lines, cancellation, and
fragmented health responses. These checks never contact a public host.

`tests/test_relay.py` checks process ownership, isolated state, exit identity,
route equality, host isolation, and failure when an online exit cannot carry
traffic. `tests/test_captcha.py` checks provider request/poll behavior,
authentication, redirects, cancellation, response bounds, and sanitized errors.
The provider responses in this suite are synthetic. Additional cases exercise
idle/processing polling, timeout and cancellation during polling after task
creation without duplicate creates, input rejection before dispatch, POST payloads,
malformed/oversized responses, relay refusal/timeouts without fallback, IPv6
CONNECT formatting, and rejection of host Tailscale sockets. Final regression
run: **456 passed, 6 skipped**; scoped Ruff checks passed. Opt-in live checks are
separate and failed as detailed below.

Worker tests also check that CAPTCHA solving and website uploads remain blocked,
and question-channel tests cover answers, denial, timeout, and cancellation.
These tests do not establish live client or website compatibility.

## Installed relay and provider

Run doctor for the intended provider before opening any browser. The default
configuration may select WARP; a WARP pass does not validate the required relay.
For the relay installed on port 1089, use these process-local overrides:

```sh
BROCODE_EGRESS_MODE=tailscale-relay \
BROCODE_PROXY_URL=http://127.0.0.1:1089 \
uv run --locked brocode doctor

BROCODE_LIVE_PREREQUISITES=1 \
BROCODE_EGRESS_MODE=tailscale-relay \
BROCODE_PROXY_URL=http://127.0.0.1:1089 \
uv run --locked pytest -q tests/test_live_prerequisites.py
```

Use the actual explicitly configured relay proxy address if it differs. The
checks do not switch services, enroll a node, or modify host routes. They save
sanitized reports under the absolute state directory in
`acceptance/indeed-prerequisites-<timestamp>/`. Credentials, tokens, provider
response bodies, and public IPs are excluded from those reports.

The relay check runs shared preflight against the installed services. The
independent route-path check probes the relay upstream, Brocode browser proxy,
and ordinary host route even when shared preflight stops at an earlier
failure. It records bounded timings and reachability without saving IPs, and
leaves route equality/isolation unverified if a path fails. Synthetic checks in
`tests/test_prerequisite_checks.py` cover independent failures, route mismatch,
host isolation, unsafe upstream rejection, and report sanitization.

The solver check authenticates the configured key with GET `/balance` and checks
for usable balance. It opens no browser, creates no paid task, and sends no
applicant data. All three tests are skipped unless explicitly enabled.

## Current live result, 2026-10-17, 11:44 UTC

The explicit relay doctor and opt-in tests were rerun against the installed
services, not just mocks. Relay daemon ownership, private socket/state, online
exit status, and selected identity passed inspection. Live traffic did not:

- Relay upstream (`127.0.0.1:8080`): HTTPS trace timed out after about 10 seconds.
- Brocode browser proxy (`127.0.0.1:1089`): same HTTPS trace timed out after about
  10 seconds, independently of the upstream test.
- Ordinary host route: same HTTPS trace succeeded in about 35 ms.
- Socket-scoped discovery and WireGuard TSMP pings to the selected exit: neither
  received a successful reply within its three-second timeout.

This localizes the observed failure to the relay route rather than general host
internet access; it does not establish whether the exit host, intervening
connectivity, or remote policy is responsible. An online control-plane status is
not proof of working data-plane traffic. Route equality and host/browser IP
isolation remain unverified. No services, routes, proxy settings, or profile state
were changed during this retest, and no browser was opened.

The provider was reachable but rejected the configured key through authenticated
GET `/balance`. Balance and paid solving therefore remain unverified. No paid
solve was attempted. The three opt-in acceptance tests failed as expected on these
blockers; they were not skipped or reclassified as passing.

Sanitized private evidence for this retest is under
`var/acceptance/indeed-prerequisites-20261017T114441.628326Z/`:
`relay.json`, `relay-route-paths.json`, `relay-peer-reachability.json`, and
`captcha-authentication.json`. No provider bodies, credentials, or IPs are saved
in these reports.

Automatic CAPTCHA dispatch and website upload dispatch are disabled in the
runtime. A successful standalone Turnstile token would not prove that Indeed's
managed Cloudflare challenge cleared. End-to-end Easy Apply remains unverified.
Repair exit connectivity and provide a valid solver credential through private
configuration before repeating these checks. Browser token delivery and upload
support still need implementation and separate acceptance tests.

All browser acceptance must use the shared Runtime after doctor passes, with
exact domain scope and meaningful verification. Navigation can have side effects,
redirects may contact another host before detection, and arbitrary websites do
not provide exactly-once writes. Infrastructure checks never authorize a job
application or replace per-action permission.
