"""Explicit maintenance only: no automatic deletion, replay, or process termination."""
from __future__ import annotations

import json
import os
import socket
import stat
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import psutil

from .contracts import TERMINAL, Status, now


def retention(runtime, *, days: int = 30, apply: bool = False) -> dict:
    """Prune only diagnostics for non-interactive terminal runs. Results are retained."""
    if days < 1:
        raise ValueError("Retention must be at least one day")
    cutoff = datetime.now(UTC) - timedelta(days=days)
    candidates = []
    runs = runtime.settings.state_dir / "runs"
    if runs.exists():
        for run_dir in sorted(runs.iterdir()):
            if not run_dir.is_dir() or run_dir.is_symlink():
                continue
            result = runtime.store.get(run_dir.name)
            if result is None or result.status not in TERMINAL:
                continue
            request = runtime.store.request(run_dir.name)
            if request.operation_key or request.policy.mode != "observe":
                continue  # Never prune external-write evidence with a generic diagnostics policy.
            updated = datetime.fromisoformat(result.updated_at)
            if updated.tzinfo is None or updated >= cutoff:
                continue
            for path in run_dir.rglob("*"):
                if (path.is_symlink() or not path.is_file() or path.name in
                        {"result.json", "owner.json", "cancel.requested"}):
                    continue
                if any(part.is_symlink() for part in (path, *path.parents)):
                    continue
                if path.suffix.lower() not in {".png", ".mp4", ".webm", ".mkv", ".log"}:
                    continue
                entry = {"run_id": result.run_id, "path": str(path), "bytes": path.stat().st_size}
                candidates.append(entry)
                if apply:
                    path.unlink()
    report = {"applied": apply, "days": days, "files": candidates,
              "bytes": sum(item["bytes"] for item in candidates), "timestamp": now()}
    if apply:
        log = runtime.settings.state_dir / "retention.jsonl"
        with log.open("a") as stream:
            log.chmod(0o600)
            stream.write(json.dumps(report) + "\n")
    return report


_SINGLETONS = ("SingletonSocket", "SingletonCookie", "SingletonLock")  # Remove the owner marker last.


@contextmanager
def _directory(path: Path, *, create: bool = False):
    """Pin a directory without following *any* symlink, including ancestor components."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Maintenance paths must be absolute and contain no '..'")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _same_directory(path: Path, fd: int) -> None:
    with _directory(path) as current:
        before, after = os.fstat(fd), os.fstat(current)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("Maintenance directory changed during inspection")


def _link_identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _singleton_snapshot(fd: int) -> dict:
    snapshot = {}
    for name in _SINGLETONS:
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError(f"{name} must be a symlink owned by the current user")
        target = os.readlink(name, dir_fd=fd)
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if _link_identity(info) != _link_identity(after):
            raise ValueError("Singleton symlink changed during inspection")
        snapshot[name] = (_link_identity(info), target)
    return snapshot


def _prove_stale_owner(snapshot: dict) -> None:
    if "SingletonLock" not in snapshot:
        raise ValueError("No proven stale SingletonLock; socket/cookie alone cannot be repaired")
    target = snapshot["SingletonLock"][1]
    host, sep, pid_text = target.rpartition("-")
    if (not sep or not host or "/" in host or not pid_text.isascii() or not pid_text.isdecimal()
            or pid_text.startswith("0") or len(pid_text) > 10):
        raise ValueError("Malformed SingletonLock owner; expected hostname-PID")
    if host != socket.gethostname():
        raise ValueError("SingletonLock owner is on another or unknown host")
    pid = int(pid_text)
    if not 0 < pid <= 2147483647:
        raise ValueError("Malformed SingletonLock PID")
    # pid_exists treats permission-denied as alive. Never accept PID reuse as stale.
    if psutil.pid_exists(pid):
        raise ValueError("SingletonLock owner PID is still live")


def _profile_in_use(profile: Path) -> bool:
    """Inspect real argv, not cached process_iter info (which can hide AccessDenied)."""
    wanted = profile.resolve(strict=True)
    try:
        for proc in psutil.process_iter():
            try:
                args = proc.cmdline()
                if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
                    raise TypeError("Cannot inspect a process command line")
                for index, arg in enumerate(args):
                    if arg == "--user-data-dir":
                        if index + 1 == len(args):
                            raise ValueError("Incomplete process profile argument")
                        value = args[index + 1]
                    elif arg.startswith("--user-data-dir="):
                        value = arg.partition("=")[2]
                    else:
                        continue
                    if not value:
                        raise ValueError("Empty process profile argument")
                    path = Path(value)
                    if not path.is_absolute():
                        path = Path(proc.cwd()) / path
                    if path.resolve() == wanted:
                        return True
            except psutil.NoSuchProcess:
                continue  # A process that disappeared cannot still hold the profile.
    except (OSError, TypeError, psutil.Error) as exc:
        raise ValueError("Cannot prove profile is unused: process inspection failed") from exc
    return False


def repair_profile_lock(runtime, *, apply: bool = False) -> dict:
    """Explicit, conservative singleton-only repair. Never launch or terminate Chrome.

    The Brocode lease excludes cooperating tasks, not independently launched Chrome.
    Rechecks narrow races; filesystem inspection and unlink cannot be made atomic
    against an unrelated process deliberately replacing entries concurrently.
    """
    from .runtime import ProfileBusy, ProfileLease

    profile, state = Path(runtime.settings.profile_dir), Path(runtime.settings.state_dir)
    report = {"ok": False, "applied": False, "repairable": False, "timestamp": now(),
              "profile": str(profile), "files": [], "removed": []}
    audit_fd = None

    def save_audit():
        if audit_fd is not None:
            os.lseek(audit_fd, 0, os.SEEK_SET)
            data = (json.dumps(report, indent=2) + "\n").encode()
            os.ftruncate(audit_fd, 0)
            with os.fdopen(os.dup(audit_fd), "wb") as stream:
                stream.write(data)
                stream.flush()
            os.fsync(audit_fd)

    try:
        # Enter the no-symlink directory guard before acquiring the shared profile lease.
        with _directory(profile) as fd, ProfileLease(profile):
            _same_directory(profile, fd)
            snapshot = _singleton_snapshot(fd)
            _prove_stale_owner(snapshot)
            if _profile_in_use(profile):
                raise ValueError("Active profile process; no repair performed")
            report["files"] = list(snapshot)
            report["singleton_evidence"] = {
                name: {"target": target, "device": identity[0], "inode": identity[1], "uid": identity[2]}
                for name, (identity, target) in snapshot.items()
            }
            report["repairable"] = True
            if not apply:
                report.update(ok=True, reason="Preview only; no singleton symlinks removed")
                return report
            with _directory(state, create=True) as state_fd:
                name = f"profile-lock-repair-{uuid4().hex}.json"
                audit_fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                   0o600, dir_fd=state_fd)
                os.fchmod(audit_fd, 0o600)
                report["audit_report"] = str(state / name)
                report["reason"] = "Validated repair intent; completion not yet recorded"
                save_audit()  # Refuse removal if private evidence cannot be persisted.
                os.fsync(state_fd)
                _same_directory(state, state_fd)
                # Re-prove ownership, process absence, and the *entire* snapshot immediately
                # before each unlink. Keep the lock until its companion links are gone.
                remaining = dict(snapshot)
                for singleton in snapshot:
                    _same_directory(profile, fd)
                    if _singleton_snapshot(fd) != remaining:
                        raise ValueError("Singleton snapshot changed; repair stopped")
                    _prove_stale_owner(remaining)
                    if _profile_in_use(profile):
                        raise ValueError("Active profile process; repair stopped")
                    # Process inspection can take time: recheck the entries again after it.
                    _same_directory(profile, fd)
                    if _singleton_snapshot(fd) != remaining:
                        raise ValueError("Singleton snapshot changed; repair stopped")
                    _prove_stale_owner(remaining)
                    os.unlink(singleton, dir_fd=fd)
                    report["removed"].append(singleton)
                    report["applied"] = True
                    del remaining[singleton]
                os.fsync(fd)
                report.update(ok=True, reason="Removed only proven stale singleton symlinks")
                save_audit()
    except (ProfileBusy, OSError, ValueError, psutil.Error) as exc:
        report.update(ok=False, repairable=False, reason=str(exc))
        try:
            save_audit()
        except OSError:
            report["audit_error"] = "Could not finalize audit; inspect the intent report before retrying"
    finally:
        if audit_fd is not None:
            os.close(audit_fd)
    return report


def recover(runtime) -> dict:
    """Mark proven dead owners interrupted. Never relaunch or kill a browser here."""
    recovered, uncertain = [], []
    runs = runtime.settings.state_dir / "runs"
    if not runs.exists():
        return {"recovered": recovered, "manual_review": uncertain}
    from .runtime import ProfileBusy, ProfileLease
    try:
        with ProfileLease(runtime.settings.profile_dir):
            # An OS lease alone does not exclude an orphaned worker holding Chrome.
            try:
                if _profile_in_use(runtime.settings.profile_dir):
                    return {"recovered": [], "manual_review": ["Active profile process; no recovery performed"]}
            except (OSError, ValueError, psutil.Error):
                return {"recovered": [], "manual_review": ["Cannot prove profile is unused; no recovery performed"]}
            for run_dir in runs.iterdir():
                if not run_dir.is_dir() or run_dir.is_symlink():
                    continue
                result = runtime.store.get(run_dir.name)
                if result is None or result.status in TERMINAL:
                    continue
                owner_path = run_dir / "owner.json"
                if not owner_path.is_file() or owner_path.is_symlink():
                    uncertain.append(run_dir.name)
                    continue
                try:
                    owner = json.loads(owner_path.read_text())
                    process = psutil.Process(owner["pid"])
                    alive = abs(process.create_time() - owner["created"]) < 0.01
                except psutil.NoSuchProcess:
                    alive = False
                except (OSError, ValueError, KeyError, psutil.Error):
                    uncertain.append(run_dir.name)
                    continue
                if alive:
                    continue
                worker = owner.get("worker_pid")
                if worker and psutil.pid_exists(worker):
                    uncertain.append(run_dir.name)
                    continue
                result.status, result.error_code = Status.PARTIAL, "OWNER_INTERRUPTED"
                result.result = "Previous owner exited. Reobserve and reconcile external writes before retrying."
                result.updated_at = now()
                runtime.store.update(result)
                artifact = run_dir / "result.json"
                artifact.write_text(result.model_dump_json(indent=2) + "\n")
                artifact.chmod(0o600)
                req = runtime.store.request(result.run_id)
                if req.operation_key:
                    operation = runtime.store.operation(req.caller_id, req.operation_key)
                    if operation and operation["status"] == "reserved":
                        runtime.store.finish_operation(req.caller_id, req.operation_key, result.run_id, "uncertain")
                recovered.append(result.run_id)
    except ProfileBusy:
        uncertain.append("Profile leased by active task; no recovery performed")
    return {"recovered": recovered, "manual_review": uncertain}
