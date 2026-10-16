# Brocode

A goal-driven browser specialist for humans and other agents. Python + browser-use, with a CLI, a guarded Python API, **Agent Client Protocol (ACP)**, and MCP. Callers describe an outcome, exact domain scope, and verification checks—not selectors or executable website scripts.

All interfaces share one runtime for preflight, permissions, profile ownership, durable results, and procedural memory.

## Setup

Requirements: Python 3.11+, uv, Google Chrome, a responsive X display (Xvfb is supported), and an explicitly configured browser egress route. The supplied infrastructure targets Linux.

```sh
cd /absolute/path/to/brocode
uv sync --locked
cp .env.example .env
# Edit .env with your model credentials and infrastructure configuration.
uv run --locked brocode --help
```

Set `OPENAI_BASE_URL=https://api.openai.com/v1`, `VISION_MODEL=gpt-4.1`, and your own `OPENAI_API_KEY`, or configure a compatible vision-capable model service. These are configuration examples, not live compatibility certifications. Environment variables override the project-root `.env`; configuration does not depend on caller cwd. Set an absolute `BROCODE_ROOT` when the project/configuration root differs from the package location.

Keep `.env`, the persistent Chrome profile, and runtime output private. State defaults to the project’s absolute `var/`; `BROCODE_STATE_DIR` and `CHROME_USER_DATA_DIR` accept absolute paths. Authentication is needed only for sites that require it; do not share or clear another running browser’s profile.

### Browser infrastructure

The **browser egress proxy is separate from the model API endpoint**. Chrome uses `BROCODE_PROXY_URL`, an HTTP loopback listener served by `brocode.infra.egress`. Do not set a host-wide proxy or silently substitute another provider.

Choose one mode explicitly in both `.env` and the service command:

- `warp`: forwards through a separately configured loopback WARP proxy. The supplied `deploy/brocode-egress.service` selects this mode.
- `tailscale`: binds outbound connections to an operator-selected source address. It requires source-scoped policy routing through table 52, an online selected exit node, and independent host/browser isolation checks. Pass your local IPv4 source address with `--source-ip`; Tailscale mode rejects a missing source. WARP mode needs no source address.

Adapt the paths and options in `deploy/` before installing the `brocode-egress` and `brocode-display` user services. The display template uses Xvfb on `:99`; align it with `BROCODE_DISPLAY` (or `DISPLAY`, which takes precedence). See [infrastructure details](docs/architecture-plan.md#browser-egress-and-preflight).

```sh
/absolute/path/to/brocode/.venv/bin/brocode doctor
```

Fix every failed check before browser execution or debugging. Shared runtime preflight also gates every browser task. Doctor inspects configuration, routing, Chrome, display, and profile ownership; it does not repair routes or remove locks.

For stale singleton locks, `brocode repair-profile-lock` previews eligibility without removing links; review it before explicitly adding `--apply`. Repair requires a proven-dead local owner and no process using the profile; unknown/live owners or incomplete inspection are rejected. It removes only validated singleton symlinks, records private audit evidence on apply, and never launches/kills Chrome or clears cookies. Keep unrelated Chrome launches stopped during repair: rechecks narrow but cannot eliminate races with independent processes.

## Run a goal

```sh
/absolute/path/to/brocode/.venv/bin/brocode run \
  "Read https://example.com and report its title" \
  --domain example.com --verify-title "Example Domain" --no-record
```

Default `observe` policy denies interaction. It is **not universally read-only**: navigation and scrolling can have side effects. Exact-host checks constrain agent actions, not every network request; redirects may contact another host before detection and blocking.

Interactive tasks need `--interactive`, a business `--operation-key`, and permission for each potentially mutating action. CLI approval requires a terminal; ACP requests permission from its client. MCP denies approval and cannot authorize interactive actions. A goal such as “prepare for review” does not itself authorize a click or submission.

Results include status, verification, evidence, steps/actions, and error codes. `succeeded` requires declared URL/title/page-text checks observed by the worker; model completion alone is insufficient. No checks means no verified success. These simple checks are only as meaningful as the caller’s chosen conditions. Exit codes: 0 for verified success, 2 for another task outcome, 1 for invalid CLI requests.

```sh
/absolute/path/to/brocode/.venv/bin/brocode result RUN_ID
/absolute/path/to/brocode/.venv/bin/brocode events RUN_ID
/absolute/path/to/brocode/.venv/bin/brocode cancel RUN_ID
```

Only one task owns a persistent profile at a time, across processes; contention returns `PROFILE_BUSY`. Cancellation is durable but cannot undo an external write. Request idempotency and operation reservations prevent blind replays, **not exactly-once website submissions**. Check site records and use explicit evidence-based reconciliation before retrying uncertain writes.

## Agent integrations

```sh
/absolute/path/to/brocode/.venv/bin/brocode acp
/absolute/path/to/brocode/.venv/bin/brocode mcp
```

Both are local stdio servers with protocol-only stdout. ACP supports text prompts, session creation/list/load, progress, permissions, and cancellation. Session replay restores transcripts, not a live browser. MCP exposes goal-level task start/status/result/cancel, playbook inspection, and upload registration; background work requires the server to stay alive and is cancelled on shutdown. Neither exposes raw JavaScript, shell, selectors, or coordinate-control tools.

See [integration](docs/integration.md) for request examples, Python usage, and client registration guidance. Brocode has no built-in scheduler; an external scheduler can invoke saved task definitions, but unattended interactive work still requires an actual approval path.

## Reusable tasks and private memory

```sh
/absolute/path/to/brocode/.venv/bin/brocode memory list
/absolute/path/to/brocode/.venv/bin/brocode upload /absolute/path/to/document.pdf
/absolute/path/to/brocode/.venv/bin/brocode tasks save daily-check /absolute/path/to/request.json
/absolute/path/to/brocode/.venv/bin/brocode run --definition daily-check
```

Playbooks are sanitized Markdown procedures, not scripts or authority. Drafts require explicit review and local approval before use; stale procedures are rejected. Verified runs may create generic drafts, not automatically learned site-specific workflows. Personal facts are separate private records with provenance, approval, and review expiry. Never invent missing required answers. Upload registration is not permission to send a file to a website.

`brocode retention --days 30` previews diagnostic-media cleanup; add `--apply` only after review. Write evidence and durable results are retained. `brocode recover` marks proven-dead owners interrupted without replaying work or terminating browsers. Use `brocode reconcile --help` for operation reconciliation.

## Development and release validation

```sh
uv run --locked pytest -q
uv run --locked ruff check --select E4,E7,E9,F,I src tests
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs locked tests, scoped lint, unrelated-cwd adapter tests, and a package build on Python 3.11/3.12. Workflow presence is not a passing CI result. Synthetic tests cover runtime, policy, persistence, memory, and transports without real submissions. Live checks are opt-in after doctor passes; never send messages, buy, delete, or submit applications in CI. Step and wall-clock limits are supported; hard token/cost caps are rejected as unsupported. Cost is reported as unknown rather than a fabricated estimate.

See [architecture](docs/architecture-plan.md) and [implementation status and limitations](docs/implementation-status.md). The status document records the local harmless live acceptance checks and remaining deployment boundaries. Global keyboard actions, website upload dispatch, and automatic CAPTCHA solving are disabled; ambiguous mutation failures stop rather than retrying. Local file registration remains available.
