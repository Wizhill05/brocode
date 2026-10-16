# Brocode architecture

This document describes the implemented design, not a future proposal or an installation report. See [implementation status](implementation-status.md) for limitations and outstanding validation.

## One execution boundary

```text
CLI / Python / ACP stdio / MCP stdio
                  |
       Runtime: contracts, store, memory
                  |
   exact scope + profile lease + preflight
                  |
       isolated browser-use worker
                  |
       persistent Chrome profile
                  |
      explicit browser egress proxy
```

Callers supply goals, domain scope, registered uploads, permissions, budgets, and verification checks. They do not supply executable site scripts. The runtime owns validation, lifecycle, durable status, cancellation, operation reservations, and finalization. Adapters translate protocols; they do not implement separate browser engines.

| Module | Responsibility |
| --- | --- |
| `contracts.py` | Strict request/result/event, policy, and verification schemas |
| `runtime.py` | Profile lease, preflight, worker process, approval bridge, cancellation, durable finalization |
| `worker.py` | Pinned browser-use integration, guarded action dispatch, page verification, evidence |
| `policy.py` | Exact-host/action allowlists, payload-bound permissions, upload checks |
| `store.py` | SQLite tasks, sessions, events, operation ledger, uploads, task definitions |
| `memory.py` | Validated playbooks, private approvals/facts, retrieval, draft generation |
| `adapters/` | Official ACP and MCP SDK stdio servers |
| `infra/` | Browser setup, read-only diagnostics, explicit egress, optional CAPTCHA integration |

`pyproject.toml` and `uv.lock` define dependencies. New state defaults to the project’s absolute `var/`, with private per-run directories for evidence, worker diagnostics, downloads, and temporary files. Configuration and profile overrides must be absolute. The caller’s cwd does not grant filesystem authority.

## Lifecycle and verification

The runtime persists an initial task before execution. It validates domains, budget support, interactive operation keys, uploads, and memory inputs; acquires an OS profile lease; runs shared preflight; reserves any operation key; then launches the worker. Events and terminal results are persisted on failure and cancellation as well as normal completion.

Statuses: `queued`, `running`, `awaiting_approval`, `needs_input`, `succeeded`, `partial`, `blocked`, `failed`, `cancelled`.

The worker independently reads current URL, title, and page text for the caller’s declared substring checks. Only passed declared checks can produce `succeeded`; a model’s `done` or a protocol end-of-turn cannot. These checks do not independently prove every real-world business outcome. Callers must choose meaningful conditions and inspect site records for consequential writes.

Step and wall-clock budgets are enforced. Requests for hard token/cost caps return `UNSUPPORTED_BUDGET`; cost remains unknown. One action is allowed per step. Unknown tools, raw JavaScript/evaluate, shell, arbitrary file tools, coordinate clicks, and action batches are not caller/model escape hatches. Fixed internal browser inspection is implementation machinery, not a public JavaScript API.

## Authority and ownership

Observe mode permits navigation and observation but denies interactive actions. Confirm mode requires an operation key and separate permission for each potentially mutating action, including supported clicks, native input, and native selections. Website upload dispatch, global keyboard actions, and automatic CAPTCHA solving are disabled because their targets or callbacks cannot be bound safely. Runtime-built previews bind permission to the live element and form state using a private keyed fingerprint; dispatch rechecks context after approval. Mutations use single-attempt exact-node adapters rather than dependency retry/fallback handlers; an ambiguous failure stops the run as `UNCERTAIN_MUTATION`. Denial, timeout, disconnection, or no approval handler means denial. A webpage, saved playbook, or model cannot grant permission.

Exact-host scope is checked before and after actions. Subdomains are not implicitly included. **Navigation and scrolling may have side effects. Redirects can contact an out-of-scope host before detection; the checks are not a network firewall.**

An OS lease prevents simultaneous tasks from owning the same profile, even across processes. Contention returns `PROFILE_BUSY`; there is no multi-profile fleet or durable browser queue. Cancellation cleans up owned processes only, never all Chrome processes. Recovery marks proven-dead owners interrupted; it neither restores a live tab nor replays an operation.

Request idempotency deduplicates caller requests; operation keys reserve a business operation. Reconciliation requires a terminal owning task and a finalized operation, with an atomic expected-state update. Active/reserved work cannot be reopened. Interrupted writes remain uncertain until evidence-based reconciliation against site records. Arbitrary websites do not provide a universal exactly-once guarantee.

## Browser egress and preflight

Model configuration (`OPENAI_BASE_URL`, `OPENAI_API_KEY`, `VISION_MODEL`) is separate from `BROCODE_PROXY_URL`, which Chrome uses for browser traffic. A portable model example is `https://api.openai.com/v1` with `gpt-4.1`; configure and validate your chosen service explicitly.

`brocode.infra.egress` is a loopback HTTP/CONNECT proxy with a required `--mode` and no provider fallback:

- **WARP:** `--mode warp` forwards through a separately configured loopback WARP HTTP proxy. `--warp-host` and `--warp-port` select its upstream. The supplied service template selects WARP.
- **Tailscale:** `--mode tailscale --source-ip "$BROWSER_SOURCE_IP"` binds outbound connections to an operator-selected local source address. An explicit IPv4 source is required in Tailscale mode; there is no default. WARP mode does not require a source address. Preflight requires a priority-5200 source-scoped rule for table 52, a priority-5260 main-table rule, table 52’s default through `tailscale0`, an online selected exit node, and compatible rule precedence.

Adapt the `deploy/` templates to `/absolute/path/to/brocode` and your chosen mode; changing `.env` alone does not reconfigure a running service. Manage infrastructure separately from tasks. Never change host-wide routing or system proxy settings as a runtime repair.

Before browser execution/debugging, run `brocode doctor` and fix every failed check. All execution interfaces repeat shared preflight. Diagnostics verify the listener/process identity, selected mode, route health, selected-route/proxy IP equality, host/proxy isolation, Chrome, X display, profile locks, and required configuration. Doctor uses network probes but does not launch Chrome, repair routing, or remove locks. Model configuration presence is not a successful model API call.

`brocode repair-profile-lock` is a separate, preview-first maintenance command. Only explicit `--apply` removes validated stale singleton symlinks after proving a local owner dead and the profile unused, under the Brocode lease. Apply records private audit evidence. Live/unknown owners, unsafe paths, or incomplete inspection block repair; it never launches/kills Chrome or clears cookies. It cannot make checks/unlink atomic against an independently launched process; keep such launches stopped during repair.

## Memory and private data

Procedural memory consists of inert Markdown with validated metadata and bounded lexical retrieval. Local approval is bound to content/version; verification age, backend changes, and repeated failures can invalidate trust. Drafts require explicit review before approval/use. Verified runs generate generic draft templates, not unrestricted model-written site procedures.

Private facts require provenance, deliberate approval, and review expiry. Required unknown answers must be requested, not invented. Inputs and facts remain per-run/private, never reusable public procedure content. Saved memory grants no authority.

Upload registration copies a caller-selected absolute regular file into private storage with integrity checks; it is not authorization to send it. Local stdio clients are trusted: registration is not a remote filesystem sandbox. Worker environment forwarding is allowlisted; orchestration credentials and arbitrary client MCP servers are not forwarded.

Recordings, screenshots, goals, transcripts, results, and logs may contain sensitive content despite redaction. Keep them private and review retention explicitly. Routine diagnostics can be pruned; write evidence and durable records are retained. Public source must exclude configuration secrets, profiles, runtime state, private archives, uploads, and handoff notes.

## Integration boundaries

ACP provides text-only sessions, progress, permissions, cancellation, and transcript list/load. MCP provides asynchronous goal-level tools but denies approval. Both use local stdio and official SDKs with protocol-only stdout. Neither exposes a general terminal, browser scripting API, remote authenticated service, or arbitrary client-supplied MCP connections.

Session replay restores metadata/transcripts only. Background MCP work belongs to the server lifespan and is cancelled at shutdown. Scheduling is external; unattended callers cannot self-approve. See [integration](integration.md) for portable launch examples.
