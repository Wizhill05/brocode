# Implementation status

Source-level capability summary for the current package. This is not a record of completed release testing, live website submissions, or installed client registration.

## Implemented

| Area | Current behavior |
| --- | --- |
| Shared runtime | CLI, Python, ACP, and MCP use strict contracts and the same execution boundary |
| Lifecycle | Durable tasks/events/results, cross-process profile lease, cancellation, proven-dead-owner recovery |
| Lock maintenance | Preview-first `repair-profile-lock`; explicit `--apply` removes only proven-stale singleton symlinks with private audit evidence |
| Preflight | Shared blocking checks for explicit egress, route isolation, Chrome, display, profile, paths, and configuration |
| Browser policy | Exact-host scope, observe default, one guarded action per step, action-specific confirm permissions |
| Verification | Worker-observed URL/title/page-text checks; model `done` alone is insufficient |
| Replay protection | Caller request idempotency, operation reservation, explicit evidence-based reconciliation |
| Files/evidence | Local upload registration (website dispatch disabled), private run directories, screenshots, optional video, diagnostic retention preview |
| Memory | Validated inert Markdown, bounded retrieval, content-bound approval, staleness checks, private facts, generic drafts |
| ACP | Text sessions, transcript list/load, progress, permission requests, cancellation, single configured model |
| MCP | Seven asynchronous goal-level tools; no permission approval path |
| Reusable work | Saved task definitions for externally scheduled execution; no separate scheduler daemon |

## Limitations callers must understand

- Observation is not a universal read-only guarantee: navigation and scrolling can cause side effects.
- Host checks gate agent actions, not all network traffic. A redirect can contact an out-of-scope host before detection and blocking.
- Confirm mode needs an operation key and real per-action approval. CLI requires a terminal; ACP requires client permission support. MCP/unattended callers cannot self-approve.
- There are no raw JavaScript, shell, selector, coordinate-control, arbitrary-file, or arbitrary-MCP-server escape tools.
- Verification is limited to declared substring checks on URL/title/page text. Passing a weak check is not proof of a consequential business outcome.
- One active task per persistent profile. Session replay restores transcripts/metadata, not Chrome state or a half-completed form.
- Cancellation cannot undo an external action. Operation keys reduce blind retries but do not guarantee exactly-once writes; uncertain outcomes require site-record reconciliation.
- Step and wall-clock limits are supported. Hard token/cost caps are rejected as `UNSUPPORTED_BUDGET`; cost remains unknown.
- Draft playbooks require explicit review and approval. Generic verified-run drafts are not automatically learned site-specific workflows. Historical seeds are not trusted just because they exist.
- Private facts must be approved, attributable, and current. Missing required screening answers must be requested, never fabricated.
- Upload registration is a trusted local filesystem operation, not a remote sandbox or permission to upload. Stdio servers must not be exposed to untrusted remote callers.
- Redaction is not a publication guarantee. Goals, transcripts, screenshots, recordings, results, and logs may contain private data. Disabling video does not disable all evidence/persistence.
- Global keyboard actions and automatic CAPTCHA solving are disabled. Challenges block rather than using callback-injection/retry paths. The solver module is retained as infrastructure, not exposed as an authorized action.
- Interactive mutations use exact-node, single-attempt adapters with native input/select controls and direct DOM activation/value assignment, not human-like typing or pointer gestures. Custom widgets or sites requiring trusted events may be unsupported. Website upload dispatch is disabled until approval context can be bound atomically to file assignment; local upload registration remains available. Approval fingerprints include form controls and effective destinations without exposing field values. Ambiguous failures stop further dispatch as `UNCERTAIN_MUTATION`; arbitrary page event handlers remain outside an exactly-once guarantee.
- Infrastructure templates target Linux and need operator-specific paths/options. Tailscale mode requires an explicit local IPv4 `--source-ip`; WARP needs no source address. Explicit `warp`/`tailscale` choices must match service and task configuration; doctor does not repair infrastructure or certify model API compatibility.

Lock repair refuses live/unknown owners and incomplete process inspection. It never launches/kills Chrome or clears cookies. Rechecks cannot eliminate races with independently launched processes; keep unrelated profile users stopped during repair.

GitHub Actions is configured in `.github/workflows/ci.yml` for Python 3.11/3.12: locked tests, scoped Ruff, unrelated-cwd transport tests, and package build. This documents configured checks, not their execution or success.

## Local release validation

The local release checks passed: **258 synthetic tests** (3 opt-in tests skipped by default), scoped Ruff, **10 unrelated-working-directory ACP/MCP SDK tests**, and wheel/source builds. Opt-in tests through the real shared runtime passed verified observation of `https://example.com`, browser cancellation with a clean profile/preflight afterward, and a structured `/task` through the ACP SDK with verification passed. A real delegated task through the local T3 ACP registration also returned `succeeded` with the declared direct check passed. Evidence remains private.

Run the opt-in acceptance suite only with configured infrastructure and after doctor passes:

```sh
BROCODE_LIVE_TESTS=1 uv run --locked pytest tests/test_live.py -q
```

No consequential live mutations or applications were tested. Hosted CI results and other deployments must be verified separately.

## Deployment validation still required

Run and record results in the release process; the existence of tests or source code is not evidence that these gates passed:

1. Reproduce the locked environment; run `uv run --locked pytest -q` and scoped Ruff checks.
2. Review public source, examples, packaged defaults, service templates, and the exact publication file list for portability, identity disclosure, secrets, and private state. Keep private handoff material out of public content.
3. Adapt infrastructure to the target machine, explicitly configure a vision-capable model, and obtain a fully passing doctor result before browser execution.
4. Opt in to harmless observation/local-fixture browser checks through the shared runtime. Verify declared checks, evidence, cleanup, and denial behavior; do not perform consequential writes in CI.
5. Probe actual ACP/MCP clients for handshake, progress, permission denial, cancellation, EOF/shutdown, and durable result retrieval. Discover actual client catalog IDs rather than assuming registration or delegated-task support.

Local validation above does not certify another model, machine, client, or website. No real submission, complete ACP conformance, or universal website compatibility is claimed.
