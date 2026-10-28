# Controller tools (bounded)

Registered, allowlisted helpers for the **controlling assistant** (not a webpage,
not the browser LLM) to request premade runtime helpers for browser-only relay
status and human challenge/input handling.

## Tools

| Name | Arguments | Result |
| --- | --- | --- |
| `egress_status` | None | Offline egress mode/proxy inspection; no live probes |
| `capabilities` | None | Enabled tools plus explicitly disabled helpers |
| `challenge_summary` | `{"run_id": "<id>"}` | Read-only human-challenge/input state for one run |

All tools are read-only, return structured output, and reuse existing APIs
(`infra.egress.EGRESS_MODES` for mode support, `infra.preflight.parse_proxy`,
`store.get`). `egress_status` accepts every mode in shared `EGRESS_MODES`
(`tailscale`, `warp`, `tailscale-relay`); it does not hardcode the set.

## Use

```sh
brocode tools list
brocode tools run egress_status
brocode tools run capabilities
brocode tools run challenge_summary --args '{"run_id": "<run_id>"}'
```

Over MCP: `controller_list` with no arguments, and
`controller_run` with `name` plus an optional `args` object. Unknown names,
path-like run IDs, and non-object args are rejected as tool errors.

## Explicitly disabled

Automatic CAPTCHA solving, CAPTCHA injectors and policy bypass, arbitrary
scripts/paths/shell/eval, network and route changes, approval escalation,
browser launches, unregistered uploads, secrets/state/archive reads, and
dependency upgrades. Human challenges fail closed and there is currently no
live captcha handoff: a terminated challenge cannot be resumed from here;
`challenge_summary` only reports. In-flight clarifying questions are a
separate, supported path (the worker's bounded `ask_caller` tool via the
owning channel: Python `question_handler`, or ACP form elicitation when the
connected client advertises it); restarting or resuming a terminal run is
still unsupported.

## Limitations (honest)

- `egress_status` is **offline**: it validates the configured mode and proxy
  shape and best-effort checks the local listener. It does not prove the
  selected route IP. Run `brocode doctor` for live route/IP verification.
- Full **pause/resume is not implemented**. Reconcile uncertain writes against
  site records with evidence (`brocode reconcile`) before anything else; only
  then consider a new scoped task. Never retry a possibly-executed submission
  without reconciliation.
- A `challenge_summary` report is not proof of browser success; read
  `status`, `verification`, and `error_code`, and treat interrupted
  submissions as uncertain.
- Tests use synthetic fixtures and injected diagnostics; they perform no live
  network access and open no browser.
