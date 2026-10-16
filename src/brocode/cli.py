"""Human and machine CLI; every browser task goes through Runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from .contracts import ApprovalRequest, Budget, Policy, TaskRequest, VerificationCheck


def _json(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    print(json.dumps(value, indent=2, default=str))


def infer_domains(goal: str) -> list[str]:
    return sorted(
        {
            urlparse(url.rstrip(".,);]>")).hostname
            for url in re.findall(r"https?://[^\s]+", goal)
            if urlparse(url.rstrip(".,);]>")).hostname
        }
    )


async def _approval(request: ApprovalRequest) -> bool:
    if not sys.stdin.isatty():
        return False
    print(
        f"\nApproval required: {request.description}\n{json.dumps(request.payload, indent=2)}",
        file=sys.stderr,
    )
    try:
        answer = await asyncio.to_thread(input, "Allow this exact action once? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() == "y"


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="brocode", description="Goal-driven browser specialist over ACP and MCP")
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run a browser goal and return a typed result")
    run.add_argument("goal", nargs="?")
    run.add_argument("--request", type=Path, help="JSON TaskRequest file")
    run.add_argument("--definition", help="Run a saved task definition")
    run.add_argument("--domain", action="append", default=[])
    run.add_argument("--model")
    run.add_argument("--max-actions", "--max-steps", type=int, default=30, dest="max_steps")
    run.add_argument("--timeout", type=int, default=600)
    run.add_argument("--file", "-f", action="append", default=[], type=Path)
    run.add_argument("--upload", action="append", default=[])
    run.add_argument(
        "--interactive", action="store_true", help="Confirm each potentially mutating browser action"
    )
    run.add_argument("--operation-key")
    run.add_argument("--idempotency-key")
    run.add_argument("--playbook")
    run.add_argument("--input", action="append", default=[], help="Playbook input NAME=JSON_VALUE")
    run.add_argument("--verify-url")
    run.add_argument("--verify-text")
    run.add_argument("--verify-title")
    run.add_argument("--no-record", action="store_true")
    doctor = sub.add_parser("doctor", help="Read-only preflight; never repairs routing or profile locks")
    doctor.add_argument("goal", nargs="?")
    doctor.add_argument("--model")
    doctor.add_argument("--file", action="append", default=[], type=Path)
    sub.add_parser("status")
    sub.add_parser("recover", help="Mark proven dead task owners interrupted; never replay writes")
    repair = sub.add_parser(
        "repair-profile-lock", help="Preview conservative stale Chrome singleton repair; never kill processes"
    )
    repair.add_argument("--apply", action="store_true", help="Remove only proven stale singleton symlinks")
    retention = sub.add_parser("retention", help="Preview diagnostics pruning; writes evidence is always retained")
    retention.add_argument("--days", type=int, default=30)
    retention.add_argument("--apply", action="store_true")
    sub.add_parser("acp", help="Serve Agent Client Protocol over clean stdio")
    sub.add_parser("mcp", help="Serve goal-oriented MCP tools over stdio")
    for name in ("result", "cancel", "events"):
        cmd = sub.add_parser(name)
        cmd.add_argument("run_id")
    upload = sub.add_parser("upload")
    upload.add_argument("path", type=Path)
    memory = sub.add_parser("memory")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    memory_sub.add_parser("list")
    for name in ("inspect", "approve"):
        cmd = memory_sub.add_parser(name)
        cmd.add_argument("playbook_id")
        if name == "approve":
            cmd.add_argument("--verified-at")
            cmd.add_argument("--evidence")
    facts = sub.add_parser("facts", help="Inspect/import explicitly approved private facts")
    facts.add_argument("name")
    facts.add_argument("--file", type=Path)
    facts.add_argument("--provenance")
    facts.add_argument("--review-days", type=int, default=90)
    definitions = sub.add_parser("tasks", help="Saved definitions; schedule them externally with T3")
    defs = definitions.add_subparsers(dest="tasks_command", required=True)
    defs.add_parser("list")
    save = defs.add_parser("save")
    save.add_argument("name")
    save.add_argument("request", type=Path)
    imp = sub.add_parser(
        "import-legacy", help="Index old task evidence and register resumes without deleting originals"
    )
    imp.add_argument("path", type=Path, nargs="?")
    reconcile = sub.add_parser(
        "reconcile", help="Explicitly resolve an operation after checking site records"
    )
    reconcile.add_argument("key")
    reconcile.add_argument("--caller", default="local")
    reconcile.add_argument("--outcome", choices=["succeeded", "not_sent"], required=True)
    reconcile.add_argument("--evidence", required=True)
    return p


async def dispatch(args) -> int:
    from .runtime import Runtime

    runtime = Runtime()
    if args.command == "run":
        if args.request:
            request = TaskRequest.model_validate_json(args.request.read_text())
        elif args.definition:
            request = runtime.store.get_definition(args.definition)
        else:
            if not args.goal:
                raise ValueError("Supply a goal, --request, or --definition")
            inputs = {}
            for item in args.input:
                key, sep, value = item.partition("=")
                if not sep:
                    raise ValueError("--input requires NAME=JSON_VALUE")
                inputs[key] = json.loads(value)
            checks = [
                VerificationCheck(kind=kind, value=value)
                for kind, value in (
                    ("url_contains", args.verify_url),
                    ("page_text_contains", args.verify_text),
                    ("title_contains", args.verify_title),
                )
                if value
            ]
            handles = list(args.upload)
            for path in args.file:
                handles.append(runtime.store.register_upload(path)["handle"])
            request = TaskRequest(
                goal=args.goal,
                model=args.model,
                budget=Budget(max_steps=args.max_steps, timeout_seconds=args.timeout),
                policy=Policy(
                    mode="confirm" if args.interactive else "observe",
                    allowed_domains=args.domain or infer_domains(args.goal),
                ),
                upload_handles=handles,
                playbook_id=args.playbook,
                inputs=inputs,
                verification=checks,
                operation_key=args.operation_key,
                idempotency_key=args.idempotency_key,
                record=not args.no_record,
            )

        async def events(event):
            print(f"[{event.kind}] {event.message}", file=sys.stderr, flush=True)

        result = await runtime.run(request, event_sink=events, approval_handler=_approval)
        _json(result)
        return 0 if result.status == "succeeded" else 2
    if args.command == "doctor":
        from .infra.preflight import preflight

        request = (
            TaskRequest(
                goal=args.goal, model=args.model, policy=Policy(allowed_domains=infer_domains(args.goal))
            )
            if args.goal
            else None
        )
        checks = await preflight(runtime.settings, request)
        for path in args.file:
            checks.append(
                {
                    "name": f"upload {path.name}",
                    "ok": path.is_file() and not path.is_symlink(),
                    "detail": str(path),
                }
            )
        _json(checks)
        return 0 if all(c["ok"] for c in checks) else 1
    if args.command == "status":
        settings = runtime.settings
        _json(
            {
                "root": settings.root,
                "state_dir": settings.state_dir,
                "profile_dir": settings.profile_dir,
                "model": settings.model,
                "egress_mode": settings.egress_mode,
                "proxy": settings.proxy_url,
                "browser": settings.chrome_path,
                "sessions": len(runtime.store.list_sessions()),
            }
        )
    elif args.command == "recover":
        from .maintenance import recover
        _json(recover(runtime))
    elif args.command == "repair-profile-lock":
        from .maintenance import repair_profile_lock
        report = repair_profile_lock(runtime, apply=args.apply)
        _json(report)
        return 0 if report["ok"] else 1
    elif args.command == "retention":
        from .maintenance import retention
        _json(retention(runtime, days=args.days, apply=args.apply))
    elif args.command == "result":
        result = runtime.store.get(args.run_id)
        if result is None:
            raise ValueError("Unknown run ID")
        _json(result)
    elif args.command == "events":
        _json(runtime.store.events(args.run_id))
    elif args.command == "cancel":
        _json({"cancel_requested": await runtime.cancel(args.run_id)})
    elif args.command == "upload":
        _json(runtime.store.register_upload(args.path))
    elif args.command == "memory":
        if args.memory_command == "list":
            _json(runtime.memory.list())
        elif args.memory_command == "inspect":
            _json(runtime.memory.inspect(args.playbook_id))
        else:
            _json(runtime.memory.approve(args.playbook_id, last_verified=args.verified_at,
                                         backend_version=runtime.memory.backend_version,
                                         evidence=args.evidence))
    elif args.command == "facts":
        if args.file:
            if not args.provenance:
                raise ValueError("--provenance is required when approving facts")
            _json(
                runtime.memory.save_facts(
                    args.name,
                    json.loads(args.file.read_text()),
                    provenance=args.provenance,
                    approved=True,
                    review_after=(datetime.now(UTC) + timedelta(days=args.review_days)).isoformat(),
                )
            )
        else:
            _json(runtime.memory.load_facts(args.name))
    elif args.command == "tasks":
        if args.tasks_command == "list":
            _json(runtime.store.list_definitions())
        else:
            request = TaskRequest.model_validate_json(args.request.read_text())
            _json(runtime.store.save_definition(args.name, request))
    elif args.command == "import-legacy":
        _json(runtime.store.import_legacy(args.path or runtime.settings.root / "artifacts"))
    elif args.command == "reconcile":
        operation = runtime.store.operation(args.caller, args.key)
        if operation is None:
            raise ValueError("Unknown operation key")
        runtime.store.reconcile_operation(args.caller, args.key, operation["run_id"],
                                          args.outcome, args.evidence)
        _json(runtime.store.operation(args.caller, args.key))
    return 0


def main() -> None:
    args = parser().parse_args()
    # Adapters import their SDKs only in server mode; SDK alone owns stdout.
    if args.command == "acp":
        from .adapters.acp import serve

        asyncio.run(serve())
        return
    if args.command == "mcp":
        from .adapters.mcp import serve

        serve()
        return
    try:
        raise SystemExit(asyncio.run(dispatch(args)))
    except (ValueError, FileNotFoundError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
