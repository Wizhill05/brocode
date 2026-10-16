# Brocode: a dependable browser specialist

Status: proposal, not implemented. Based on a read-only source audit plus the explicitly requested home-file consolidation. No browser tasks were executed, no authenticated profile was opened, no files were deleted, no Git repository was initialized, and no T3 settings were changed.

## 1. Product direction

**Brocode should be the browser specialist other agents delegate to—not another general coding agent and not a folder of website scripts.**

A caller supplies an outcome, constraints, permitted files, and an authorization policy. Brocode owns observation, planning, browser actions, recovery, and verification. It returns a typed outcome with evidence. The caller should not need to know the website's selectors or click sequence.

The normal loop becomes:

`request → validate authority → retrieve relevant playbook → acquire profile → preflight → observe/act → verify → persist result → propose learning`

Keep Python and browser-use initially. They already support the successful flows; changing language or browser framework while changing the agent interface would create unnecessary risk. Pin the currently installed browser-use 0.13.10 first, then evaluate upgrades behind tests.

Non-goals for version one: a general shell/code executor, a custom editor, a fleet of parallel browsers sharing one login, a vector database, automatic retraining, a second scheduler, and public remote ACP hosting.

## 2. What the audit actually found

| Finding | Evidence / implication |
|---|---|
| No Git repository | `git rev-parse` fails in this folder and its parents. Establish history before refactoring. |
| Small codebase, large runtime state | Five top-level Python files total 1,514 lines. The folder is roughly 3.3 GB: 1.6 GB Chrome profile, 1.1 GB artifacts, 716 MB virtualenv. This is mostly state, not excessive application code. |
| No project dependency manifest or test suite found | `.venv` is the effective dependency specification. Capture versions before rebuilding it. |
| `brocode.py` mixes concerns | Settings, preflight, browser construction, model construction, artifact persistence, and CLI in 425 lines. |
| Python API bypasses doctor | Only the CLI calls `doctor()` before `run_task()`. All entrypoints must use the same guarded runtime. |
| No shared task lifecycle | No application-level cross-process profile lease, durable cancellation protocol, result status contract, or submission ledger. A Chrome lock is not a task manager. |
| Success is not verified | The CLI prints “TASK COMPLETED” after `agent.run()` regardless of whether the requested outcome is independently established. Artifacts have final text and history errors, not a durable verified outcome. |
| Evidence is incomplete on wrapper failures | Artifact writing happens after a successful return from `agent.run()`. The installed browser-use does its own close in its normal run-finally path; Brocode must still persist failure/cancellation results and manage ownership at its boundary. Do not misdiagnose this as no browser cleanup anywhere. |
| Runtime files share one namespace | Upload resumes, scraped datasets, screenshots, application summaries, and recordings all live under `artifacts/`. |
| Documentation is stale | README advertises Chrome-daemon commands and flags absent from today's CLI. AGENTS/APPLYING say weak models are refused, while current code merely warns. |
| Egress code and stated policy disagree | `local_exit_proxy.py` prefers a local WARP proxy when available, then falls back to Tailscale. Documentation describes Tailscale-only routing. Different host/proxy IPs alone do not prove the intended provider was used. |
| Sensitive material can leak | Current doctor prints fragments of a solver API key; goals/artifacts may include personal facts. Legacy home scripts contain plaintext login credentials. |
| A forbidden automation script survives | `apply_glassdoor.py` launches Chrome against the shared profile and uses hardcoded selectors and coordinates, contradicting AGENTS.md. |

Preflight was not run: this audit did not attempt browser execution or debugging a failed live run. Before any later smoke test, run doctor and fix all failures.

## 3. Architecture: one runtime, three adapters

```text
T3 / ACP clients ── ACP stdio ──┐
Other agents ────── MCP tools ───┼── Task runtime / policy / memory
Humans / scripts ─ CLI or Python┘          │
                                  exclusive profile lease
                                           │
                                 browser-use worker process
                                           │
                                  existing Chrome profile
                                           │
                              explicitly selected egress route
```

ACP is **Agent Client Protocol**, not Agent Context Protocol or the unrelated Agent Communication Protocol. ACP gives T3 an agent session, streamed progress, permissions, and cancellation. MCP is an optional tool-facing adapter for agents that cannot act as ACP clients. They must not implement different browser logic.

### Small initial code layout

```text
brocode/
  pyproject.toml               # package, entrypoint, dependency groups
  uv.lock                     # reproducible environment
  .env.example                # names/placeholders only
  .gitignore
  README.md
  AGENTS.md                   # concise development + caller rules
  src/brocode/
    __init__.py               # public API
    cli.py                    # run, doctor, status, acp; mcp later
    contracts.py              # requests/results/events/policy models
    runtime.py                # lifecycle, leases, cancellation, verification
    worker.py                 # pinned browser-use adapter + event bridge
    store.py                  # SQLite tasks, sessions, evidence, retrieval
    memory.py                 # playbook loading, sanitization, proposals
    adapters/
      acp.py                  # official Python ACP SDK
      mcp.py                  # only when needed by actual callers
    infra/
      browser.py              # preserve/refactor stealth.py
      preflight.py            # common async preflight
      egress.py               # preserve/refactor local_exit_proxy.py
      captcha.py              # preserve/refactor captcha_solver.py
  playbooks/
    indeed-apply/PLAYBOOK.md   # generalized procedure, no PII
  docs/
    architecture-plan.md
    integration.md
  tests/                      # unit + ACP + local browser fixture tests
  archive/                    # private, ignored, non-executable legacy evidence
  var/                        # private, ignored runtime home
    state.sqlite3
    runs/<run-id>/
    uploads/
    private-facts/
    downloads/
```

This is a target layout, not an instruction to create empty scaffolding now. Split modules when they have real responsibilities; do not add one file per action or website. State defaults to this project's absolute `var/` path, never the caller's working directory or `~/`. An explicit `BROCODE_STATE_DIR` may override it later. The existing `.chrome_profile` remains in place during the first migration, outside Git; changing its path is unnecessary risk.

### Runtime contract

`TaskRequest`: goal, caller/session identity, optional playbook ID and validated inputs, profile ID, upload handles, allowed domains, authorization scope, idempotency key, step/time/token/cost limits where measurable.

`TaskResult`: run/session IDs, status, structured result, verification state, evidence references, error code, timestamps, actual steps/actions, model configuration, and usage/cost when available. Missing pricing is unknown, not zero.

Statuses: queued, running, awaiting_approval, needs_input, succeeded, partial, blocked, failed, cancelled. `succeeded` requires the task's declared verification checks. An agent's `done` message alone never establishes it. Distinguish protocol end-of-turn from browser-task success.

Use UUID/ULID run IDs rather than second-resolution timestamps. Persist an initial task record before execution, append events during it, and finalize in failure/cancellation paths too. Do not infer task failure just because history includes recovered action errors.

Keep the ACP process responsive while a browser worker runs. Put dependency output on worker stderr and use a dedicated framed event channel; the ACP parent's stdout contains only SDK-generated protocol messages. Do not try to sanitize arbitrary mixed stdout with regexes. No broad shell tools in the worker.

### Profile ownership, recovery, and retries

- One active owner per profile across **all** CLI, ACP, MCP, and Python processes. Use an OS file lock, not an in-memory mutex. A database records metadata; it is not the only lock.
- Initially reject a competing request with `PROFILE_BUSY` rather than starting another Chrome. Add a durable bounded queue only if required.
- Hold the lease while awaiting an approval if preserving the current page is necessary; bound that wait and expose its state. An approval approves a particular preview/payload, not an unlimited session.
- Cancellation stops the agent, drains evidence, closes only its owned Chrome, and releases the lease. A timed-out worker gets bounded graceful shutdown then ownership-scoped termination. Never kill all Chrome processes.
- A restarted session restores conversation/task metadata, not a promise that the same live page or half-filled form still exists. Reobserve before continuing.
- Retry transient reads/navigation within budgets. Never automatically replay an uncertain submission. Reconcile against site records first; return `partial`/uncertain if reconciliation is unavailable.
- Keep a submission ledger keyed by account/site/business object and operation. Idempotency is best effort: no universal exactly-once guarantee exists for arbitrary websites.

## 4. ACP and T3 integration

Use the official `agent-client-protocol` Python SDK; do not invent a lookalike protocol. Start with stdio and negotiate the version supported by the installed T3 build. Current public docs include versioned protocol pages, so pin a tested SDK/spec pair instead of assuming latest means compatible.

Implement initialization, session creation, prompt turns, progress/tool updates, permission requests, and cancellation. Add durable session load/list only after correct persistence and transcript replay exist, advertising only implemented capabilities. Use official schema fields—not internal T3 class/function names as wire method names. Do not expose private chain-of-thought; stream task plans and observable actions.

For the v1 baseline, this corresponds to `initialize`, `session/new`, `session/prompt`, `session/update`, `session/request_permission`, and `session/cancel`. v2 or newer features require explicit compatibility tests.

**Installed T3 integration was inspected, not exercised.** Build `0.0.46-nightly.20261015.3171` includes an `acpRegistry` driver with a local-command source and `commandPath`/`commandArgs`. The intended provider entry is:

```json
{
  "brocode": {
    "driver": "acpRegistry",
    "displayName": "Brocode",
    "enabled": true,
    "config": {
      "source": "local",
      "commandPath": "/home/gujju-azure/brocode/.venv/bin/brocode",
      "commandArgs": ["acp"],
      "enabled": true
    }
  }
}
```

This is a **proposed fragment under `providerInstances`**, not a complete settings file and not a command to run today. The installed executable does not exist yet. Register through T3's provider settings when possible; otherwise back up and schema-validate the settings merge. Never replace the whole user's settings. Do not put credentials in the example.

First integration gate: an SDK-backed minimal agent appears in T3, passes its probe, receives a prompt, streams an update, handles denial/cancel, and exits cleanly. Confirm the provider is listed with `canRunChildTask: true` in `orchestrator_capabilities` before claiming other T3 agents can delegate to it. Use the returned provider/model IDs, not a guessed `brocode/default` model. Model/options should be exposed through the negotiated session capabilities/configuration supported by that T3/SDK pair.

Once this passes, T3's `delegate_task` should target that registered instance. Other ACP clients can spawn `brocode acp`; clients that only speak MCP use `brocode mcp` later. Proposed MCP tools: task start/status/cancel/result, playbook list/inspect, and private upload registration. Long browser work returns a run ID rather than forcing a tool connection to wait indefinitely. No raw click/selector escape hatch.

T3 may inject MCP/orchestration context into ACP agents. Brocode does not need arbitrary orchestration tools to browse; do not forward injected tokens to the browser LLM, web pages, memories, or artifacts. Avoid recursive delegation.

## 5. Memory that actually improves repeatability

I interpret the requested reusable “.empty file” as a saved procedure. A literally empty file cannot store that knowledge. Use Markdown with validated YAML front matter, conventionally `PLAYBOOK.md`; a different extension can be supported if you specifically want it.

Keep four things distinct:

1. **Procedural memory:** sanitized, versioned goal-based playbooks.
2. **Personal facts:** private, user-approved records with provenance and review dates; not inside reusable prompts committed to Git.
3. **Episodic evidence:** private task ledger and run artifacts.
4. **Scheduled/preassigned work:** task definitions referring to a playbook and validated inputs, not conversation memory masquerading as a scheduler.

Example procedure:

```markdown
---
id: indeed-apply
version: 1
status: draft
scope: account-owner-approved job application
domains: [indeed.com, smartapply.indeed.com]
required_inputs: [job_url, resume_handle, applicant_facts_ref]
authorization: confirm_before_submit
verification: [confirmation_observed, application_record_observed]
---
# Apply to the specified role
Check the role and requirements against current approved applicant facts.
Use the registered resume; answer only from those facts.
Observe the current form and adapt; do not replay selectors or coordinates.
Ask when a required answer is unknown. Preview the submission and await approval.
After submission, check confirmation and the account's application record.
If the outcome is uncertain, reconcile before attempting another submission.
```

Workflow discovery → retrieve by ID/domain/title/tags with SQLite FTS and bounded selection → validate inputs → execute → check evidence → propose a sanitized new version. Auto-save a draft after a verified run; explicitly approve promotion to trusted procedure. Failed/uncertain attempts may produce a failure note, never a trusted success recipe. Store source run IDs, last-verified date, backend version, known failure conditions, and staleness markers.

One success is useful evidence, not proof that a website flow is permanently solved. Invalidate/review a playbook when the site changes, it repeatedly fails, or its policy changes. Import `APPLYING.md` as a seed only after checking its claimed confirmation evidence. Do not blindly reuse old salary, availability, work-authorization, experience, or education claims; time-sensitive personal facts require review. Unknown required screening answers require input, not a guessed minimum.

No vector store initially. Add semantic retrieval only if measured retrieval misses justify it. No executable code inside playbooks, and page text must never become trusted instructions or user authorization.

## 6. Safety and operational boundaries

- Preserve the existing browser/profile/recording/egress infrastructure during migration. Refactor with tests; do not delete or replace stealth.py, captcha_solver.py, or local_exit_proxy.py as a cleanup shortcut.
- Pick an explicit egress mode; preserve per-browser isolation and never change host-wide Tailscale routing from a task. Do not silently fall back to another provider/IP. Doctor reports selected route and measured health, with secrets redacted.
- Move preflight into the runtime so no entrypoint bypasses it. Make doctor non-destructive by default; stale-lock repair should be explicit and ownership-checked. Current sync `asyncio.run()` solver check also needs conversion for async callers.
- Permission policy is enforced at action dispatch, not only in the system prompt. Scope external mutations/uploads to caller authority. Deny unknown or unclassified mutating actions in conservative mode.
- Audit every available browser-use action, including form submission via keys, JavaScript/evaluate, multi-action batches, downloads, and file writes; disable bypass tools where policy cannot be enforced. Never claim a universal read-only guarantee based on button labels alone. Website navigation can itself have side effects.
- Approval denial, loss of connection, missing approval support, or timeout means **do not perform the mutation**. Preauthorization must identify operation, scope, account, files, and limits. Saved memory grants no authority.
- Treat web content as untrusted data; do not follow page instructions to reveal secrets, change policies, or use other accounts. Use scoped domain transitions and registered upload handles; canonicalize paths and reject escapes/symlinks outside permitted roots.
- Define allowed output paths for browser-use's own filesystem/download tools, not just our wrapper. Never write to caller cwd or home by accident.
- Store state privately, redact logs before storage, limit recording retention, and keep evidence of external writes longer than routine diagnostics. Recordings may contain PII; a blanket “safe to publish” label is inappropriate.
- Preserve current captcha infrastructure as an isolated integration. Its absence/failure must produce an honest blocked/human-needed state, never uncontrolled retrying or automatic egress rotation. Solver policy and credentials need explicit operator configuration.

## 7. Cleanup and migration ledger

### Completed with your authorization

Moved 15 home-level files into private `archive/legacy-workflows/`: seven Webex files and eight Tekstac files. Copied one job-data snapshot from `.hermes/saved_5_jobs.json`; the Hermes original remains because provenance/references are uncertain. Every destination is hash-verified in `archive/consolidation-manifest.json`. No deletions. `.gitignore` now excludes `archive/` and `artifacts/`. Archive files are restricted to owner access. Rotate the plaintext password found in the Tekstac scripts.

Scope was home-level files, selected shallow project references, Downloads, selected agent filenames, and matching temporary filenames—not an exhaustive whole-disk attribution exercise. Unrelated projects/configs/unknown images were left untouched.

### Proposed actions during implementation

| Current path | Action | Delete condition |
|---|---|---|
| `brocode.py` | Extract into package; keep compatibility `run_task` shim during transition | Remove monolith after Python/CLI callers are migrated and tested |
| `bin/brocode` | Replace eventually with packaging console entrypoint; update existing global symlink intentionally | Only after installed entrypoint works from any cwd |
| `stealth.py` | Preserve, move to infra/browser.py after compatibility tests | Never wholesale-delete as clutter |
| `local_exit_proxy.py` | Preserve and make route explicit; document service ownership | No deletion without a tested replacement and operational migration |
| `captcha_solver.py` | Preserve behind an optional capability with controlled lifecycle | No deletion as cleanup |
| `apply_glassdoor.py` | Move to private legacy archive; extract useful goal/verification knowledge | Delete archived copy only after review/backup, not as part of initial refactor |
| `APPLYING.md` | Separate procedure, personal facts, and historical evidence; remove obsolete instructions | Replace old document only after provenance checked |
| `AGENTS.md`, `README.md` | Rewrite to match implemented commands, authority boundaries, and file rules | Keep short authoritative docs, not competing runbooks |
| `.env` | Keep private; add sanitized .env.example, redact diagnostics | Never commit; rotate any exposed secrets |
| `.chrome_profile/` | Keep exact path initially; offline backup before any later relocation | Never clear/delete as project cleanup |
| `.venv/` | Capture package versions; rebuild from tested lock later | Delete only after replacement env validated |
| `.chrome.pid` | Historical daemon marker; inspect process ownership | Remove only when proven stale and unused |
| `__pycache__/` | Generated bytecode | Safe to clear during migration, regenerated automatically |
| `artifacts/resume_*.pdf` | Inventory/hash and register as private uploads; update references | Keep distinct versions; no bulk deduplication by filename |
| `artifacts/task_*.json`, screenshots, recordings | Migrate/import to private run ledger; preserve confirmed outcome evidence | Prune routine media only under reviewed retention policy |
| `artifacts/*saved*`, categories, movie lists | Archive as user datasets, not agent source or trusted memory | Do not delete user output as “cache” |
| `candidates.txt` | Review and move into private job-workspace data | Do not infer it is disposable |
| `archive/` | Non-executable, private legacy evidence | Optional removal only after explicit review/retention decision |

Do not run a sweeping `rm`. Before each relocation check live references, record source/destination/hash, and maintain rollback. State migration should be incremental; the original CLI continues to work until the new package passes the same workflow checks.

### Establish Git safely

First back up source/config and record checksums; back up the authenticated profile only while closed or with an appropriate consistent snapshot. Expand ignore rules for `var/`, runtime media, uploads, credentials, caches, and archives **before** initialization. Run secret scanning, review an explicit source-only staging list, then `git init` and make a baseline commit. Do not use `git add .` on this mixed tree. No remote/public push is needed. Apply changes in small tested commits with migrations and rollback notes.

## 8. Implementation phases and exit gates

1. **Protect and baseline.** Inventory/backup; secret rotation advisory; manifest/lock; source-only Git; truthful docs. Exit: reproducible environment and restore procedure; current behavior characterized.
2. **Prove ACP ↔ T3.** Minimal SDK adapter and clean stdio with a fake worker first. Verify actual local provider registration, model discovery, progress, permission denial, cancellation, disconnect, and child-task targeting. Exit: T3 can reliably call the specialist; no real submissions.
3. **Unify the runtime.** Contracts, cross-process profile lease, preflight on every entrypoint, worker event channel, persistent run status, budgets, deterministic cleanup. Exit: CLI/Python/ACP share behavior; parallel calls never share an active profile.
4. **Enforce policy and verification.** Restrict action set; approval gates; registered files; evidence checks; uncertain-write reconciliation and ledger. Exit: local fixture tests prove denied writes do not occur, including keyboard/script/batch bypass attempts.
5. **Add playbooks and private facts.** Import sanitized Indeed knowledge; provenance, draft promotion, stale-memory handling, repeat task definitions. Exit: retrieved workflow executes with current inputs and cannot fabricate required answers or expand authority.
6. **Caller coverage and retention.** Add MCP only for actual non-ACP callers; wire T3 scheduling to saved task definitions instead of creating another daemon. Complete path migration and retire old entrypoints only after compatibility checks. Exit: no new loose files outside configured roots; recovery/retention documented.

Do not promise a delivery date until phase 2 establishes the T3/SDK compatibility boundary. This is several small milestones, not a massive rewrite in one pass.

## 9. Acceptance tests that define “proper agent”

- ACP frames remain valid under noisy browser dependencies, concurrent updates, malformed input, early EOF, permission denial, and cancellation. Use SDK tests plus the experimental ACP TCK where applicable; TCK success is not official complete conformance.
- Two separate processes targeting the same profile get one owner and one busy result; no second Chrome launch.
- Python API cannot bypass doctor; no task can silently change host routing or switch egress providers.
- A browser-use `done` without outcome evidence is not marked succeeded.
- Failed and cancelled work has durable artifacts and releases owned resources. A fresh request works after an interrupted one.
- Duplicate keys do not create duplicate task execution; uncertain submits are reconciled, not blindly replayed.
- A playbook retrieved from a previous successful run supplies procedure, not obsolete PII or permission to submit.
- Unknown application facts produce a request for input. Prompt injection cannot authorize an upload, external write, arbitrary script, or memory promotion.
- Tests run from a temporary unrelated cwd prove source/home remain unchanged and all outputs land under the configured private root.
- Browser integration tests use local synthetic websites through the agent runtime. A live Indeed test is opt-in: prepare/review first, then one specifically authorized submission and an independent records check. Never auto-apply in CI.

## Sources and evidence

Local source audit: brocode.py, stealth.py, local_exit_proxy.py, captcha_solver.py, apply_glassdoor.py, bin/brocode, README.md, AGENTS.md, APPLYING.md, .gitignore; installed browser-use package metadata and lifecycle source. T3 local-command capability was researched from installed build `0.0.46-nightly.20261015.3171`; runtime handshake remains an implementation gate, not a completed test.

Official references:
- ACP introduction: https://agentclientprotocol.com/get-started/introduction
- ACP v1 lifecycle: https://agentclientprotocol.com/protocol/v1/overview
- Stdio framing and transport constraints: https://agentclientprotocol.com/protocol/v1/transports
- Permission requests/tool events: https://agentclientprotocol.com/protocol/v1/tool-calls
- Python SDK: https://agentclientprotocol.com/libraries/python
- Python SDK quickstart: https://agentclientprotocol.github.io/python-sdk/quickstart/
- Experimental compatibility kit: https://agentclientprotocol.com/libraries/testing
