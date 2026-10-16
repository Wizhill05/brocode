# Brocode integration

All interfaces share `Runtime`; there is no raw browser escape hatch. Complete setup and run `brocode doctor` before browser execution or debugging. See [README](../README.md) for model configuration, display, and the separate browser egress proxy.

## Launch and trust boundary

```sh
/absolute/path/to/brocode/.venv/bin/brocode acp
/absolute/path/to/brocode/.venv/bin/brocode mcp
```

Equivalent module entrypoints are `python -m brocode.adapters.acp` and `python -m brocode.adapters.mcp` in the installed environment. Use absolute executable/configuration paths when launching from another cwd. `BROCODE_ROOT` can select the project/configuration root; session `cwd` is metadata, not filesystem authority.

Both adapters are **local stdio servers**. Stdout belongs exclusively to the official SDK protocol; logs/dependency output use stderr. The lockfile pins the environment; the implementation pins `agent-client-protocol==0.12.1` and uses MCP 2.1.1’s `mcp.server.mcpserver.MCPServer`, not a separate FastMCP dependency. Browser dependencies load worker-side after protocol setup.

Treat clients as trusted local callers. In particular, upload registration can copy a caller-selected readable absolute file after store checks. This is not a restricted remote upload service. Do not expose the stdio server as an unauthenticated network API.

## ACP

Implemented operations:

- `initialize`: SDK protocol negotiation and implemented capabilities.
- `session/new`, `session/load`, `session/list`: durable transcript metadata; list optionally filters exact cwd and has no pagination.
- `session/prompt`: text-only goals, public progress/tool updates, final summary and structured `TaskResult`.
- `session/request_permission`: server-to-client allow-once/deny requests for runtime-generated previews.
- `session/cancel`: cancellation of the session’s tracked task, with runtime-owned cleanup.
- `session/set_config_option`: accepts the single operator-configured model only.

New/load responses expose a `configOptions` select with `id: "model"`, `category: "model"`, and one configured option. A loaded session uses current server configuration; it does not restore a historical model or browser. One prompt per session may be in flight. Session replay does not automatically feed old text back into browser authority: submit a self-contained goal each turn.

No image/audio/resource prompts, arbitrary terminal/filesystem access, authentication flow, session fork/resume/close/modes, or arbitrary model selection are advertised. Injected client MCP servers, directories, metadata, and extensions confer no authority and are not connected to the worker.

### Prompt authority

Ordinary text always uses observe policy. Only explicit HTTP(S) URL hosts become allowed domains:

```text
Read https://example.com/about and report its heading.
```

This scopes `example.com`, not its subdomains or unrelated redirects. No URL means `DOMAINS_REQUIRED`/`needs_input` without opening Chrome. Ordinary JSON-looking text is still text.

Only `/task` parses strict `TaskRequest` JSON; explicit domains are required. A recognized T3 prompt envelope is reduced to its single unambiguous `<user_request>` before parsing or inferring hosts; surrounding orchestration instructions grant no domain authority. The fixed T3 role-label preamble is also stripped. Ambiguous envelopes are rejected. `/task` embedded in ordinary prose is not executed:


```text
/task {"goal":"Read https://example.com and report its title","policy":{"mode":"observe","allowed_domains":["example.com"]},"verification":[{"kind":"title_contains","value":"Example Domain"}],"record":false}
```

For an interactive request, set `policy.mode` to `confirm`, supply a business `operation_key`, and obtain permission separately for each potentially mutating action. Denial, unknown responses, missing client support, timeout, and disconnection never authorize it. Registered handles belong in `upload_handles`; registration alone does not permit sending a file.

ACP fixes `caller_id` to `acp` and supplies the session identity. Conflicting session IDs, unconfigured model overrides, and unknown schema fields are rejected. Approval is not inherited from conversation history or playbooks.

A protocol `stopReason: "end_turn"` only means the turn ended. Inspect `TaskResult.status`, `verification`, `error_code`, and evidence. A blocked/partial/failed task can finish normally at the protocol level.

### Client registration

Configure an ACP-capable client to launch the absolute executable with argument `acp`. In T3 versions supporting local `acpRegistry` providers, the relevant provider configuration is:

```json
{
  "driver": "acpRegistry",
  "displayName": "Brocode",
  "enabled": true,
  "config": {
    "source": "local",
    "commandPath": "/absolute/path/to/brocode/.venv/bin/brocode",
    "commandArgs": ["acp"],
    "enabled": true
  }
}
```

This is an illustrative provider entry, not a complete settings file or a claim about an installed client. Prefer client settings UI, preserve existing settings, and check the client’s current schema. Probe handshake, progress, denial, cancellation, and shutdown before relying on integration. Discover actual provider/model IDs through the client’s live catalog (`orchestrator_capabilities` in T3); do not guess IDs or assume child-task support. Client registration does not prove a live website workflow works.

## MCP

Seven goal-level tools are registered:

| Tool | Arguments | Result |
| --- | --- | --- |
| `task_start` | `request`: strict `TaskRequest`, nonempty `policy.allowed_domains` | `run_id` for background execution |
| `task_status` | `run_id` | Status, terminal flag, verification, error code |
| `task_result` | `run_id` | Full current `TaskResult`, including nonterminal state |
| `task_cancel` | `run_id` | Cancellation acceptance; read status for completion |
| `playbooks_list` | None | Procedural memory listing |
| `playbook_inspect` | `playbook_id` | Validated playbook details |
| `upload_register` | Absolute local `path` | Private upload handle/metadata |

Example `task_start` arguments:

```json
{
  "request": {
    "goal": "Read https://example.com and report its title",
    "policy": {"mode": "observe", "allowed_domains": ["example.com"]},
    "budget": {"max_steps": 15, "timeout_seconds": 120},
    "verification": [{"kind": "title_contains", "value": "Example Domain"}],
    "record": false
  }
}
```

MCP fixes `caller_id` to `mcp` and always denies approval: there is no approval elicitation, sampling, or implicit preauthorization. Confirm-mode requests cannot bypass this. Tools do not expose selectors, coordinates, raw JavaScript, shell, memory promotion, arbitrary MCP servers, or arbitrary download destinations.

Background tasks belong to the server lifespan, not an individual tool call. Keep the server alive; EOF/shutdown cancels owned work and waits for cleanup. Reconnect to inspect durable results, not to resume a live browser. Invalid requests and unknown IDs are SDK tool errors, not fabricated success.

## Python API

```python
import asyncio

from brocode.contracts import Policy, TaskRequest, VerificationCheck
from brocode.runtime import Runtime

async def main():
    runtime = Runtime()
    request = TaskRequest(
        goal="Read https://example.com and report its title",
        policy=Policy(allowed_domains=["example.com"]),
        verification=[VerificationCheck(kind="title_contains", value="Example Domain")],
        record=False,
    )
    result = await runtime.run(request)
    print(result.model_dump_json(indent=2))

asyncio.run(main())
```

`Runtime.run` waits for the durable result. `Runtime.start` returns a persisted run ID and runs background work while the owning event loop remains alive. Optional async `event_sink(TaskEvent)` receives progress; optional async `approval_handler(ApprovalRequest) -> bool` is the trusted permission path. No handler means denial, not approval. `cancel(run_id)` requests cancellation; `cancel_all()` waits for owned tasks to clean up. Synthetic worker/preflight injection is a test seam, not a production transport option.

## Shared limitations and validation

- Default observation is not universally side-effect-free. Redirects may contact another host before scope enforcement; scope is not a browser network firewall.
- Only declared URL/title/page-text checks establish verified success, not model claims. Checks can be too weak to prove a business outcome.
- One active task per persistent profile; no live browser restoration or exactly-once external writes. Reconcile uncertain submissions against site records before retrying.
- Playbook drafts require explicit reviewed approval; private facts need provenance, approval, and current review. Neither grants action authority.
- Step/time limits are supported; hard token/cost caps are rejected. Missing usage/cost information is not zero cost.
- Public progress is filtered and worker credentials are allowlisted, but saved transcripts, evidence, and recordings may contain private content. `record: false` disables video, not all evidence or durable results.

Run `uv run --locked pytest -q` and scoped Ruff checks from the project root. Transport tests use SDK stdio clients with synthetic runtime/worker paths; they are not live client certifications. Live model/browser/client checks remain separate, opt-in release gates after doctor passes. See [implementation status](implementation-status.md); no live-validation result is asserted here.
