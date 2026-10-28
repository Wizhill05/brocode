"""Bounded registered controller tools for the controlling assistant.

These helpers let a controlling assistant (not a webpage, not the browser LLM)
request premade runtime helpers for browser-only relay status and human
challenge/input handling. The registry is an allowlist: only the typed names
in ``TOOL_NAMES`` can run. Tools are read-only diagnostics and summaries.

Explicitly out of scope: arbitrary scripts, paths, shell/eval, network or
route changes, approval escalation, CAPTCHA injectors or solvers, browser
launches, reading secrets/state/archive content, dependency upgrades, and
full pause/resume (see the ``capabilities`` tool report).
"""

from __future__ import annotations

import re
from typing import Any

TOOL_NAMES = ("egress_status", "capabilities", "challenge_summary")

_RUN_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")

_DESCRIPTIONS = {
    "egress_status": "Offline inspection of the configured browser egress relay (mode and loopback proxy).",
    "capabilities": "Report of what controller tools can do and what is explicitly disabled.",
    "challenge_summary": "Read-only summary of one run's human-challenge/input state by run_id.",
}


def _egress_status(runtime: Any, args: dict[str, Any]) -> dict[str, Any]:
    if args:
        raise ValueError("egress_status takes no arguments")
    from brocode.infra.egress import EGRESS_MODES
    from brocode.infra.preflight import parse_proxy

    supported = sorted(EGRESS_MODES)
    settings = getattr(runtime, "settings", None)
    mode = getattr(settings, "egress_mode", None)
    proxy_url = getattr(settings, "proxy_url", "") or ""
    mode_supported = mode in EGRESS_MODES
    host: str | None = None
    port: int | None = None
    try:
        host, port = parse_proxy(proxy_url)
        proxy_ok, proxy_detail = True, f"HTTP loopback port {port}"
    except ValueError:
        proxy_ok, proxy_detail = False, "explicit HTTP loopback proxy with port required"
    listener: bool | None = None
    if proxy_ok:
        try:
            from brocode.infra.preflight import listener_matches

            listener = bool(listener_matches(host, port, mode))
        except Exception:  # noqa: BLE001 - diagnostics report unknown instead of failing
            listener = None
    return {
        "tool": "egress_status",
        "read_only": True,
        "egress_mode": mode,
        "supported_modes": supported,
        "mode_supported": mode_supported,
        "proxy_host": host,
        "proxy_port": port,
        "proxy_config_ok": proxy_ok,
        "proxy_config_detail": proxy_detail,
        "listener_owned": listener,
        "live_probes": "not_run",
        "note": ("Offline inspection only; no browser launched, no routes changed. "
                 "Run `brocode doctor` for live route/IP verification."),
    }


def _capabilities(runtime: Any, args: dict[str, Any]) -> dict[str, Any]:
    if args:
        raise ValueError("capabilities takes no arguments")
    _ = runtime
    return {
        "tool": "capabilities",
        "read_only": True,
        "enabled": [
            {"name": name, "description": _DESCRIPTIONS[name], "read_only": True}
            for name in TOOL_NAMES
        ],
        "disabled": [
            {"name": "automatic_captcha_solving",
             "reason": ("Challenges fail closed and there is currently no live captcha handoff; "
                        "a terminated challenge cannot be resumed from here.")},
            {"name": "captcha_injector_or_bypass",
             "reason": "No solver injection or policy bypass is exposed."},
            {"name": "arbitrary_shell_scripts_paths_eval",
             "reason": "Only allowlisted tool names run; no scripts, paths, shell, or eval."},
            {"name": "network_and_route_changes",
             "reason": "Egress inspection is offline; routes change only via explicit service setup."},
            {"name": "approval_escalation",
             "reason": "Controller tools never approve actions; approval stays with the owning channel."},
            {"name": "browser_launch",
             "reason": "No tool starts Chrome or restores a live browser session."},
            {"name": "live_pause_resume",
             "reason": ("Full pause/resume and live-session handoff are not implemented. "
                        "Reconcile uncertain writes against site records with evidence first; "
                        "only then start a new scoped task if needed.")},
            {"name": "unregistered_uploads",
             "reason": "Files enter only through the existing registered-upload flow."},
            {"name": "secrets_state_archive_access",
             "reason": "No secret, state-file, or archive content is read or echoed."},
            {"name": "dependency_upgrades",
             "reason": "No dependency or environment changes are performed."},
        ],
        "questions": {
            "in_flight_ask_caller": ("Supported while a run is live: the worker's ask_caller tool "
                                     "asks one bounded clarifying question through the owning "
                                     "channel (Python question_handler, or ACP form elicitation "
                                     "when the connected client advertises it). Answers are "
                                     "untrusted data, never authority; denial and timeout fail "
                                     "closed."),
            "restart_or_resume": ("Not supported: a terminal run cannot be resumed or handed off "
                                  "mid-challenge. Reconcile the outcome first, then start a new "
                                  "scoped task if needed."),
        },
        "pause_resume": ("Bounded: full pause/resume is not implemented. Reconcile uncertain writes "
                         "against site records with evidence before anything else; only then "
                         "consider a new scoped task. Never retry a possibly-executed submission "
                         "without reconciliation."),
        "notes": [
            "Diagnostic tools are read-only and return structured output.",
            "Observation policy denies interaction by default; MCP callers cannot self-approve.",
        ],
    }


def _challenge_summary(runtime: Any, args: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(args, dict):
        raise ValueError("args must be a JSON object")  # noqa: TRY004 - MCP/CLI contract uses ValueError
    if set(args) != {"run_id"}:
        raise ValueError("challenge_summary requires exactly {run_id}")
    run_id = args.get("run_id")
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("run_id must be a simple identifier, not a path")
    result = runtime.store.get(run_id)
    if result is None:
        raise KeyError(f"Unknown run_id: {run_id}")
    status = str(getattr(result.status, "value", result.status))
    error_code = result.error_code
    guidance = "Read-only summary; no browser launched and nothing approved."
    lowered = error_code.lower() if isinstance(error_code, str) else ""
    if status == "needs_input":
        guidance = ("Task needs human input (missing scope, keys, or playbook values). "
                    "Supply it via a new scoped task; controller tools cannot inject input.")
    elif status == "awaiting_approval":
        guidance = ("Approval belongs to the originating channel (CLI prompt or ACP permission). "
                    "Controller tools and MCP callers cannot approve.")
    elif "captcha" in lowered or "challenge" in lowered:
        guidance = ("Automatic solving is disabled and there is currently no live captcha "
                    "handoff: the challenge terminated with this run. This summary is read-only; "
                    "reconcile the outcome against site records before any new attempt.")
    elif status in {"partial", "blocked", "failed", "cancelled"}:
        guidance = ("If a submission may have executed, check site records and use "
                    "`brocode reconcile` with evidence before retrying.")
    preview = result.result if isinstance(result.result, str) else None
    return {
        "tool": "challenge_summary",
        "read_only": True,
        "run_id": run_id,
        "status": status,
        "terminal": status in {"needs_input", "succeeded", "partial", "blocked", "failed",
                               "cancelled"},
        "needs_input": status == "needs_input",
        "awaiting_approval": status == "awaiting_approval",
        "error_code": error_code,
        "verification": result.verification,
        "steps": result.steps,
        "actions": result.actions,
        "evidence_count": len(result.evidence),
        "result_present": preview is not None,
        "result_preview": preview[:500] if preview else None,
        "guidance": guidance,
    }


_HANDLERS = {
    "egress_status": _egress_status,
    "capabilities": _capabilities,
    "challenge_summary": _challenge_summary,
}

_ARG_HINTS = {
    "egress_status": {},
    "capabilities": {},
    "challenge_summary": {"run_id": "string: TaskResult run_id (simple identifier)"},
}


def list_tools() -> list[dict[str, Any]]:
    """Describe every allowlisted controller tool without running anything."""
    return [{"name": name, "description": _DESCRIPTIONS[name], "read_only": True,
             "args": _ARG_HINTS[name]} for name in TOOL_NAMES]


def run_tool(runtime: Any, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run one allowlisted tool. Unknown names, paths, and non-object args are rejected."""
    if name not in _HANDLERS:
        raise ValueError(f"Unknown controller tool: {name}")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("args must be a JSON object")  # noqa: TRY004 - MCP/CLI contract uses ValueError
    return _HANDLERS[name](runtime, args)
