"""Single execution boundary used by CLI, Python, ACP and MCP."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import signal
import socket
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Awaitable, Callable

from dotenv import dotenv_values

from .contracts import (
    TERMINAL,
    ApprovalRequest,
    Status,
    TaskEvent,
    TaskRequest,
    TaskResult,
    WorkerOutcome,
    now,
)
from .settings import Settings, private_dir

EventSink = Callable[[TaskEvent], Awaitable[None]]
ApprovalHandler = Callable[[ApprovalRequest], Awaitable[bool]]


class ProfileBusy(RuntimeError):
    pass


class ProfileLease:
    """Kernel-enforced across processes and state directories sharing a profile."""

    def __init__(self, profile: Path):
        self.profile = profile
        self.fd: int | None = None

    def __enter__(self):
        private_dir(self.profile)
        path = self.profile / ".brocode-lease"
        self.fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self.fd)
            self.fd = None
            raise ProfileBusy("Another task owns this browser profile") from exc
        os.ftruncate(self.fd, 0)
        os.write(self.fd, str(os.getpid()).encode())
        return self

    def __exit__(self, *_):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def _redact(value: str, settings: Settings) -> str:
    values = dict(dotenv_values(settings.root / ".env"))
    values.update(os.environ)
    secrets = [settings.api_key] + [
        str(v)
        for k, v in values.items()
        if v and any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "AUTHORIZATION"))
    ]
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) >= 4:
            value = value.replace(secret, "[REDACTED]")
    return value


async def stop_owned_group(process, *, grace: float = 12, kill_grace: float = 2) -> None:
    """Verify the isolated group, not just its leader; never signal unrelated groups."""
    import psutil

    group = process.pid  # start_new_session=True establishes PID == PGID == SID.
    if group == os.getpgrp():
        raise RuntimeError("Refusing to terminate caller process group")

    def survivors():
        found = []
        for member in psutil.process_iter():
            try:
                if os.getpgid(member.pid) == group and member.status() != psutil.STATUS_ZOMBIE:
                    found.append(member.pid)
            except (ProcessLookupError, psutil.NoSuchProcess):
                continue
        return found

    async def wait_empty(seconds):
        deadline = asyncio.get_running_loop().time() + seconds
        while survivors():
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.05)
        return True

    # Give the worker a chance to close Chrome via CDP. Sending SIGTERM to
    # Chrome at the same time leaves persistent-profile locks behind.
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.send_signal(signal.SIGTERM)
    if not await wait_empty(grace):
        with suppress(ProcessLookupError):
            os.killpg(group, signal.SIGTERM)
        if not await wait_empty(kill_grace):
            with suppress(ProcessLookupError):
                os.killpg(group, signal.SIGKILL)
            if not await wait_empty(kill_grace):
                raise RuntimeError("Owned process group did not stop; inspect profile before reuse")
    await process.wait()


async def finish_cleanup(awaitable):
    """Repeated cancellation cannot abandon ownership-scoped cleanup halfway through."""
    task = asyncio.create_task(awaitable)
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
    result = task.result()
    if interrupted:
        raise asyncio.CancelledError
    return result


class Runtime:
    def __init__(self, settings: Settings | None = None, *, worker_runner=None, preflight_checker=None):
        from .memory import Memory
        from .store import Store

        self.settings = settings or Settings.load()
        private_dir(self.settings.state_dir)
        self.store = Store(self.settings.state_dir)
        self.memory = Memory(self.settings.root, self.store)
        self._tasks: dict[str, asyncio.Task] = {}
        self._executing: set[str] = set()
        self._worker_runner = worker_runner
        self._preflight_checker = preflight_checker

    async def _emit(self, run_id: str, event: TaskEvent, sink: EventSink | None) -> None:
        event = TaskEvent.model_validate_json(_redact(event.model_dump_json(), self.settings))
        self.store.append_event(run_id, event)
        if sink:
            await sink(event)

    async def start(self, request: TaskRequest, *, event_sink=None, approval_handler=None) -> str:
        result, created = self.store.create_task(request, model=request.model or self.settings.model)
        if created:
            task = asyncio.create_task(self._execute(request, result, event_sink, approval_handler))
            self._tasks[result.run_id] = task
            task.add_done_callback(lambda t: self._background_done(result.run_id, t))
        return result.run_id

    def _background_done(self, run_id: str, task: asyncio.Task) -> None:
        self._tasks.pop(run_id, None)
        if not task.cancelled():
            with suppress(Exception):
                task.exception()

    async def run(self, request: TaskRequest, *, event_sink=None, approval_handler=None) -> TaskResult:
        result, created = self.store.create_task(request, model=request.model or self.settings.model)
        if not created:
            return result
        current = asyncio.current_task()
        if current:
            self._tasks[result.run_id] = current
        try:
            return await self._execute(request, result, event_sink, approval_handler)
        finally:
            self._tasks.pop(result.run_id, None)

    async def cancel(self, run_id: str) -> bool:
        result = self.store.get(run_id)
        if result is None or result.status in TERMINAL:
            return False
        run_dir = private_dir(self.settings.state_dir / "runs" / result.run_id)
        flag = run_dir / "cancel.requested"
        flag.touch(mode=0o600)
        task = self._tasks.get(run_id)
        if task and run_id in self._executing and task is not asyncio.current_task() and not task.cancelling():
            task.cancel()
        return True

    async def cancel_all(self) -> None:
        tasks = list(self._tasks.items())
        for run_id, task in tasks:
            if task is not asyncio.current_task():
                await self.cancel(run_id)
        await asyncio.gather(
            *(t for _, t in tasks if t is not asyncio.current_task()), return_exceptions=True
        )

    async def _execute(self, request, result, sink, approval_handler) -> TaskResult:
        deadline = asyncio.get_running_loop().time() + request.budget.timeout_seconds
        async with asyncio.timeout_at(deadline):
            return await self._execute_task(request, result, sink, approval_handler, deadline)

    async def _execute_task(self, request, result, sink, approval_handler, deadline) -> TaskResult:
        run_dir = private_dir(self.settings.state_dir / "runs" / result.run_id)
        reserved = False
        self._executing.add(result.run_id)
        import psutil
        owner_file = run_dir / "owner.json"
        owner_file.write_text(json.dumps({"pid": os.getpid(), "created": psutil.Process().create_time()}))
        owner_file.chmod(0o600)
        try:
            if (run_dir / "cancel.requested").exists():
                raise asyncio.CancelledError
            if request.budget.max_tokens is not None or request.budget.max_cost_usd is not None:
                result.status, result.error_code = Status.BLOCKED, "UNSUPPORTED_BUDGET"
                result.result = (
                    "Token/cost hard caps are not supported by this backend; use step and wall-clock limits."
                )
                return result
            if not request.policy.allowed_domains:
                result.status, result.error_code = Status.NEEDS_INPUT, "DOMAINS_REQUIRED"
                result.result = "Supply exact allowed domains before opening a browser."
                return result
            if request.policy.mode == "confirm" and not request.operation_key:
                result.status, result.error_code = Status.NEEDS_INPUT, "OPERATION_KEY_REQUIRED"
                result.result = (
                    "Interactive tasks require an operation key to prevent uncertain write replays."
                )
                return result
            upload_paths = self.store.resolve_uploads(request.upload_handles)
            from .memory import MemoryValidationError
            try:
                context = self.memory.context(request)
            except MemoryValidationError as exc:
                result.status, result.error_code = Status.NEEDS_INPUT, "PLAYBOOK_INPUT_REQUIRED"
                result.result = str(exc)
                return result
            with ProfileLease(self.settings.profile_dir):
                result.status = Status.RUNNING
                result.updated_at = now()
                self.store.update(result)
                await self._emit(
                    result.run_id, TaskEvent(kind="preflight", message="Checking browser prerequisites"), sink
                )
                if self._preflight_checker:
                    checks = await self._preflight_checker(self.settings, request)
                else:
                    from .infra.preflight import preflight

                    checks = await preflight(self.settings, request)
                result.data["preflight"] = checks
                if any(not c["ok"] for c in checks):
                    result.status, result.error_code = Status.BLOCKED, "PREFLIGHT_FAILED"
                    result.result = "Preflight failed; browser was not started."
                    return result
                if request.operation_key:
                    reserved = self.store.reserve_operation(
                        request.caller_id, request.operation_key, result.run_id
                    )
                    if not reserved:
                        result.status, result.error_code = Status.BLOCKED, "OPERATION_ALREADY_RESERVED"
                        result.result = (
                            "This operation is already recorded; reconcile its outcome before retrying."
                        )
                        return result
                await self._emit(
                    result.run_id, TaskEvent(kind="started", message="Browser task started"), sink
                )

                async def approve(approval: ApprovalRequest) -> bool:
                    if request.policy.mode != "confirm" or approval_handler is None:
                        return False
                    result.status, result.updated_at = Status.AWAITING_APPROVAL, now()
                    self.store.update(result)
                    await self._emit(
                        result.run_id,
                        TaskEvent(
                            kind="approval",
                            message=approval.description,
                            data={"action_id": approval.action_id},
                        ),
                        sink,
                    )
                    try:
                        allowed = await asyncio.wait_for(
                            approval_handler(approval), request.policy.approval_timeout_seconds
                        )
                        return allowed is True
                    except (TimeoutError, ConnectionError):
                        return False
                    finally:
                        result.status, result.updated_at = Status.RUNNING, now()
                        self.store.update(result)

                async def invoke():
                    if self._worker_runner:
                        return await self._worker_runner(
                            request,
                            run_dir,
                            upload_paths,
                            context,
                            lambda e: self._emit(result.run_id, e, sink),
                            approve,
                        )
                    return await self._worker(
                        request,
                        run_dir,
                        upload_paths,
                        context,
                        lambda e: self._emit(result.run_id, e, sink),
                        approve,
                    )

                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError
                worker_task = asyncio.create_task(invoke())
                monitor = asyncio.create_task(self._monitor_cancel(run_dir, worker_task))
                try:
                    outcome = await asyncio.wait_for(worker_task, remaining)
                finally:
                    # A second caller cancellation must not interrupt wait_for's
                    # child cleanup and release the lease while Chrome still exits.
                    async def settle_worker():
                        if not worker_task.done() and not worker_task.cancelling():
                            worker_task.cancel()
                        await asyncio.gather(worker_task, return_exceptions=True)
                        monitor.cancel()
                        await asyncio.gather(monitor, return_exceptions=True)
                    await finish_cleanup(settle_worker())
                outcome = WorkerOutcome.model_validate(outcome)
                result.result = outcome.result
                result.data.update(outcome.data)
                result.evidence = outcome.evidence
                result.steps, result.actions = outcome.steps, outcome.actions
                result.usage = outcome.usage
                result.error_code = outcome.error_code
                if outcome.error_code:
                    result.status = Status.PARTIAL if outcome.mutated else Status.BLOCKED
                elif request.verification and outcome.checks_passed:
                    result.status, result.verification = Status.SUCCEEDED, "passed"
                else:
                    result.status = Status.PARTIAL
                    result.verification = "failed" if request.verification else "not_requested"
                if result.status == Status.SUCCEEDED:
                    try:
                        draft = self.memory.draft_from_result(request, result)
                        if draft:
                            result.data["memory_draft"] = str(draft)
                    except (ValueError, OSError) as exc:
                        result.data["memory_warning"] = _redact(str(exc), self.settings)
        except ProfileBusy:
            result.status, result.error_code = Status.BLOCKED, "PROFILE_BUSY"
            result.result = "Another task owns this browser profile; no second Chrome was launched."
        except asyncio.CancelledError:
            if asyncio.get_running_loop().time() >= deadline:
                result.status, result.error_code = Status.PARTIAL, "TIMEOUT"
                result.result = "Wall-clock limit reached; any uncertain writes require reconciliation."
            else:
                result.status, result.error_code = Status.CANCELLED, "CANCELLED"
                result.result = "Task cancelled. Reconcile any uncertain external writes before retrying."
        except TimeoutError:
            result.status, result.error_code = Status.PARTIAL, "TIMEOUT"
            result.result = "Wall-clock limit reached; any uncertain writes require reconciliation."
        except Exception as exc:
            result.status, result.error_code = Status.FAILED, type(exc).__name__.upper()
            result.result = _redact(str(exc), self.settings)
        finally:
            if reserved:
                status = "succeeded" if result.status == Status.SUCCEEDED else "uncertain"
                try:
                    self.store.finish_operation(request.caller_id, request.operation_key, result.run_id, status)
                except Exception:
                    result.status, result.error_code = Status.PARTIAL, "OPERATION_FINALIZATION_FAILED"
                    result.result = "Operation ledger finalization failed; do not retry without reconciliation."
                    result.verification = "unknown"
            if request.playbook_id and result.error_code != "PLAYBOOK_INPUT_REQUIRED":
                with suppress(ValueError, KeyError, OSError):
                    self.memory.record_outcome(request.playbook_id, result)
            result.updated_at = now()
            sanitized = TaskResult.model_validate_json(_redact(result.model_dump_json(), self.settings))
            for key in type(result).model_fields:
                setattr(result, key, getattr(sanitized, key))
            self._executing.discard(result.run_id)
            artifact = run_dir / "result.json"
            artifact.write_text(result.model_dump_json(indent=2) + "\n")
            artifact.chmod(0o600)
            self.store.update(result)
            with suppress(Exception):
                await self._emit(
                    result.run_id,
                    TaskEvent(kind="finished", message=result.status, data={"error_code": result.error_code}),
                    sink,
                )
        return result

    async def _monitor_cancel(self, run_dir: Path, worker_task: asyncio.Task):
        while not worker_task.done():
            if (run_dir / "cancel.requested").exists():
                worker_task.cancel()
                return
            await asyncio.sleep(0.2)

    def _worker_env(self, run_dir: Path, *, temp_dir: Path | None = None) -> dict[str, str]:
        allowed = ("PATH", "HOME", "DISPLAY", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR")
        env = {k: os.environ[k] for k in allowed if k in os.environ}
        values = {**dotenv_values(self.settings.root / ".env"), **os.environ}
        for key in ("NOCAPTCHA_API_KEY", "NOCAPTCHA_API_URL", "BROCODE_DISPLAY", "BROCODE_SCREEN"):
            if values.get(key):
                env[key] = str(values[key])
        env.update(
            {
                "BROCODE_WORKER_API_KEY": self.settings.api_key,
                "DISPLAY": self.settings.display,
                "BROCODE_PROXY_URL": self.settings.proxy_url,
                "BROCODE_EGRESS_MODE": self.settings.egress_mode,
                "BROCODE_CHROME_PATH": self.settings.chrome_path,
                "CHROME_USER_DATA_DIR": str(self.settings.profile_dir),
                "BROWSER_USE_TELEMETRY": "false",
                "ANONYMIZED_TELEMETRY": "false",
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                "TMPDIR": str(private_dir(temp_dir or run_dir / "tmp")),
            }
        )
        return env

    async def _worker(self, request, run_dir, uploads, context, emit, approve) -> WorkerOutcome:
        request_path = run_dir / "worker-request.json"
        # Chrome creates Unix sockets below TMPDIR. UUID run paths can exceed
        # Linux's sockaddr_un limit before Chrome even exposes CDP.
        temp_dir = Path(tempfile.mkdtemp(dir=private_dir(self.settings.state_dir / "tmp")))
        temp_dir.chmod(0o700)
        if len(os.fsencode(temp_dir / "com.google.Chrome.XXXXXX/SingletonSocket")) >= 108:
            temp_dir.rmdir()
            raise ValueError("State path is too long for Chrome sockets; configure a shorter absolute BROCODE_STATE_DIR")
        envelope = {
            "temp_dir": str(temp_dir),
            "request": request.model_dump(mode="json"),
            "run_dir": str(run_dir),
            "profile_dir": str(self.settings.profile_dir),
            "model": request.model or self.settings.model,
            "base_url": self.settings.base_url,
            "proxy_url": self.settings.proxy_url,
            "egress_mode": self.settings.egress_mode,
            "upload_paths": uploads,
            "playbook_context": context,
        }
        request_path.write_text(json.dumps(envelope))
        request_path.chmod(0o600)
        parent_sock, child_sock = socket.socketpair()
        parent_sock.setblocking(False)
        process = None
        reader = writer = None
        log_task = None
        outcome = None
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "brocode.worker",
                "--request",
                str(request_path),
                "--events-fd",
                str(child_sock.fileno()),
                pass_fds=(child_sock.fileno(),),
                cwd=str(run_dir),
                env=self._worker_env(run_dir, temp_dir=temp_dir),
                start_new_session=True,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            owner_file = run_dir / "owner.json"
            owner = json.loads(owner_file.read_text())
            owner["worker_pid"] = process.pid
            owner_file.write_text(json.dumps(owner))
            owner_file.chmod(0o600)
            child_sock.close()
            reader, writer = await asyncio.open_connection(sock=parent_sock, limit=8 * 1024 * 1024)

            async def logs():
                # Private, bounded, redacted diagnostics; never forwarded as protocol output.
                path = run_dir / "worker.log"
                size = 0
                with path.open("w") as handle:
                    path.chmod(0o600)
                    pending = b""
                    while chunk := await process.stderr.read(8192):
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            text = _redact(line.decode(errors="replace") + "\n", self.settings)
                            if size < 2_000_000:
                                handle.write(text)
                                size += len(text)
                        # Do not retain unbounded or partially-redacted dependency output.
                        if len(pending) > 128_000:
                            pending = b"[oversized diagnostic line omitted]"
                    if pending and size < 2_000_000:
                        handle.write(_redact(pending.decode(errors="replace"), self.settings))

            log_task = asyncio.create_task(logs())
            while line := await reader.readline():
                message = json.loads(line)
                if message["type"] == "event":
                    await emit(TaskEvent.model_validate(message["event"]))
                elif message["type"] == "approval":
                    approval = ApprovalRequest.model_validate(message["approval"])
                    allowed = await approve(approval)
                    writer.write(
                        (
                            json.dumps(
                                {
                                    "type": "approval_response",
                                    "action_id": approval.action_id,
                                    "allow": allowed,
                                }
                            )
                            + "\n"
                        ).encode()
                    )
                    await writer.drain()
                elif message["type"] == "outcome":
                    outcome = WorkerOutcome.model_validate(message["outcome"])
            await process.wait()
            if outcome is None:
                raise RuntimeError(f"Worker exited without an outcome (exit {process.returncode})")
            if process.returncode != 0 and not outcome.error_code:
                outcome.error_code = "WORKER_EXIT"
            return outcome
        finally:
            async def cleanup():
                child_sock.close()
                try:
                    if process is not None:
                        await stop_owned_group(process)
                finally:
                    if log_task:
                        with suppress(Exception):
                            await asyncio.wait_for(log_task, 2)
                    if writer:
                        writer.close()
                        with suppress(Exception):
                            await writer.wait_closed()
                    else:
                        parent_sock.close()
                    request_path.unlink(missing_ok=True)
            await finish_cleanup(cleanup())
