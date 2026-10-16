"""Private, local persistence. No implicit home paths and no browser dependencies.

SQLite uses DELETE journals (not WAL): journals inherit the database's 0600 mode.
Transactions use BEGIN IMMEDIATE for compare-and-create operations across processes.
The private root is an owner-only trust boundary, not protection from the same UID.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import TERMINAL, Evidence, Status, TaskEvent, TaskRequest, TaskResult, now

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")


class IdempotencyConflict(ValueError):
    error_code = "IDEMPOTENCY_CONFLICT"


class OperationConflict(ValueError):
    error_code = "OPERATION_CONFLICT"


class UnsafePath(ValueError):
    error_code = "UNSAFE_PATH"


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.fullmatch(name) or ".." in name:
        raise ValueError("Expected a simple identifier, not a path")
    return name


def _absolute(path: str | Path) -> Path:
    path = Path(path)
    if ".." in path.parts:
        raise UnsafePath("Parent traversal is not permitted")
    return Path(os.path.abspath(path))


def _directory_fd(path: Path, *, create: bool = False) -> int:
    """Walk with openat/O_NOFOLLOW, including every ancestor, without resolving links."""
    path = _absolute(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
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
        return fd
    except OSError as exc:
        os.close(fd)
        raise UnsafePath("Directory missing, inaccessible, or contains a symlink") from exc


def validate_directory(path: Path) -> Path:
    """Check every directory component without creating or changing source paths."""
    path = _absolute(path)
    fd = _directory_fd(path)
    os.close(fd)
    return path


def private_directory(path: Path) -> Path:
    path = _absolute(path)
    fd = _directory_fd(path, create=True)
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    return path


@contextmanager
def safe_file(path: Path, *, max_bytes: int | None = None) -> Iterator[Any]:
    """Open a regular source file without following links or blocking on a FIFO."""
    path = _absolute(path)
    parent_fd = _directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    except OSError as exc:
        raise UnsafePath("File missing, inaccessible, or a symlink") from exc
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePath("Only regular files are allowed")
        if max_bytes is not None and info.st_size > max_bytes:
            raise ValueError(f"File exceeds {max_bytes} byte limit")
        yield source


def private_write(path: Path, content: bytes) -> None:
    """Atomically replace an owner-only file; never follow a destination symlink."""
    parent = private_directory(path.parent)
    fd = _directory_fd(parent)
    temporary = f".{uuid4()}.tmp"
    try:
        try:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafePath("Destination must be a regular file")
        except FileNotFoundError:
            pass
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=fd)
        with os.fdopen(output, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def redact(value: Any, secrets: Mapping[str, str] | None = None) -> Any:
    """Redact credentials, not personal facts. Stored state is still PRIVATE.

    By default only secret-looking environment variables contribute known values.
    An explicit mapping is useful to freeze the runtime's redaction configuration.
    """
    values = secrets if secrets is not None else {
        key: item for key, item in os.environ.items()
        if re.search(r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|CREDENTIAL|COOKIE)", key, re.IGNORECASE)
    }
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if re.fullmatch(
            r"(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|cookie|authorization)",
            str(key), re.IGNORECASE) else redact(item, values)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, values) for item in value]
    if not isinstance(value, str):
        return value
    for secret in sorted(set(values.values()), key=len, reverse=True):
        if len(secret) >= 4:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 [REDACTED]", value)
    value = re.sub(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    value = re.sub(
        r'''(?ix)(\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*)["']?[^\s,"';&}]+''',
        r"\1[REDACTED]", value,
    )
    return value


redact_text = redact


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class Store:
    def __init__(self, state_dir: Path):
        self.state_dir = private_directory(Path(state_dir))
        self.root = self.state_dir
        self.uploads_dir = private_directory(self.state_dir / "uploads")
        self.db_path = self.state_dir / "state.sqlite3"
        directory = _directory_fd(self.state_dir)
        try:
            fd = os.open(self.db_path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise UnsafePath("Database must be a regular file")
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            for suffix in ("-wal", "-shm", "-journal"):
                try:
                    info = os.stat(self.db_path.name + suffix, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise UnsafePath("Unsafe SQLite sidecar")
                    side = os.open(self.db_path.name + suffix, os.O_RDONLY | os.O_NOFOLLOW,
                                   dir_fd=directory)
                    try:
                        os.fchmod(side, 0o600)
                    finally:
                        os.close(side)
                except FileNotFoundError:
                    pass
        finally:
            os.close(directory)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    run_id TEXT PRIMARY KEY, caller_id TEXT NOT NULL, idempotency_key TEXT,
                    fingerprint TEXT NOT NULL, request TEXT NOT NULL, result TEXT NOT NULL,
                    UNIQUE(caller_id, idempotency_key));
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES tasks(run_id),
                    event TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, cwd TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS messages (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL REFERENCES sessions(id),
                    role TEXT NOT NULL, text TEXT NOT NULL, timestamp TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS uploads (
                    handle TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    source TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS definitions (
                    name TEXT PRIMARY KEY, request TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operations (
                    caller_id TEXT NOT NULL, key TEXT NOT NULL, run_id TEXT NOT NULL,
                    status TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL,
                    PRIMARY KEY(caller_id, key));
                CREATE TABLE IF NOT EXISTS legacy (
                    sha256 TEXT PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL,
                    reference TEXT, imported_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS playbook_index (
                    id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE VIRTUAL TABLE IF NOT EXISTS playbook_fts USING fts5(id UNINDEXED, text);
            """)

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        # No shared connection: safe for separate threads/processes and explicit transaction scopes.
        with safe_file(self.db_path):
            pass
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA busy_timeout=30000")
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except BaseException:
            if write:
                db.rollback()
            raise
        finally:
            db.close()

    def create_task(self, request: TaskRequest, model: str | None = None) -> tuple[TaskResult, bool]:
        serialized = request.model_dump(mode="json")
        selected_model = model if model is not None else request.model
        fingerprint = hashlib.sha256(_json({"request": serialized, "model": selected_model}).encode()).hexdigest()
        with self._connect(write=True) as db:
            if request.idempotency_key is not None:
                row = db.execute("SELECT fingerprint,result FROM tasks WHERE caller_id=? AND idempotency_key=?",
                                 (request.caller_id, request.idempotency_key)).fetchone()
                if row:
                    if row["fingerprint"] != fingerprint:
                        raise IdempotencyConflict("Idempotency key already belongs to a different request")
                    return TaskResult.model_validate_json(row["result"]), False
            result = TaskResult(session_id=request.session_id, model=selected_model)
            db.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?)", (
                result.run_id, request.caller_id, request.idempotency_key, fingerprint,
                _json(redact(serialized)), _json(redact(result.model_dump(mode="json"))),
            ))
        return result, True

    def get(self, run_id: str) -> TaskResult | None:
        with self._connect() as db:
            row = db.execute("SELECT result FROM tasks WHERE run_id=?", (run_id,)).fetchone()
        return TaskResult.model_validate_json(row[0]) if row else None

    def request(self, run_id: str) -> TaskRequest:
        with self._connect() as db:
            row = db.execute("SELECT request FROM tasks WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(run_id)
        return TaskRequest.model_validate_json(row[0])

    def update(self, result: TaskResult) -> None:
        result.updated_at = now()
        with self._connect(write=True) as db:
            changed = db.execute("UPDATE tasks SET result=? WHERE run_id=?",
                                 (_json(redact(result.model_dump(mode="json"))), result.run_id)).rowcount
            if not changed:
                raise KeyError(result.run_id)

    def append_event(self, run_id: str, event: TaskEvent) -> None:
        with self._connect(write=True) as db:
            db.execute("INSERT INTO events(run_id,event) VALUES (?,?)",
                       (run_id, _json(redact(event.model_dump(mode="json")))))

    def events(self, run_id: str) -> list[dict]:
        with self._connect() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT event FROM events WHERE run_id=? ORDER BY seq", (run_id,))]

    def create_session(self, cwd: str | Path) -> str:
        session_id = str(uuid4())
        with self._connect(write=True) as db:
            db.execute("INSERT INTO sessions VALUES (?,?,?)", (session_id, str(cwd), now()))
        return session_id

    def get_session(self, session_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM sessions ORDER BY created_at,id")]

    def add_message(self, session_id: str, role: str, text: str) -> None:
        if role not in {"user", "assistant", "system", "tool"}:
            raise ValueError("Invalid message role")
        with self._connect(write=True) as db:
            db.execute("INSERT INTO messages(session_id,role,text,timestamp) VALUES (?,?,?,?)",
                       (session_id, role, redact(text), now()))

    def messages(self, session_id: str) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT role,text,timestamp FROM messages WHERE session_id=? ORDER BY seq", (session_id,))]

    def _copy_upload(self, path: Path, db: sqlite3.Connection) -> dict:
        path = _absolute(path)
        handle = str(uuid4())
        destination = self.uploads_dir / handle
        digest = hashlib.sha256()
        size = 0
        folder = _directory_fd(self.uploads_dir)
        try:
            with safe_file(path, max_bytes=MAX_UPLOAD_BYTES) as source:
                fd = os.open(handle, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=folder)
                with os.fdopen(fd, "wb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_UPLOAD_BYTES:
                            raise ValueError("Upload exceeds 50 MB")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            row = {"handle": handle, "path": str(destination), "sha256": digest.hexdigest(),
                   "source": str(path), "size": size, "created_at": now()}
            db.execute("INSERT INTO uploads VALUES (:handle,:path,:sha256,:source,:size,:created_at)", row)
            return row
        except BaseException:
            # Only our fresh UUID may be cleaned up. Original inputs/media are never touched.
            try:
                os.unlink(handle, dir_fd=folder)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(folder)

    def register_upload(self, path: str | Path) -> dict:
        with self._connect(write=True) as db:
            return self._copy_upload(Path(path), db)

    def resolve_uploads(self, handles: list[str]) -> list[str]:
        result = []
        with self._connect() as db:
            for handle in handles:
                validate_name(handle)
                row = db.execute("SELECT * FROM uploads WHERE handle=?", (handle,)).fetchone()
                if row is None:
                    raise KeyError(handle)
                # Database paths are metadata, not filesystem authority.
                path = self.uploads_dir / handle
                if row["path"] != str(path):
                    raise UnsafePath("Upload path does not match registered private location")
                digest = hashlib.sha256()
                size = 0
                with safe_file(path, max_bytes=MAX_UPLOAD_BYTES) as source:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        if size > MAX_UPLOAD_BYTES:
                            raise ValueError("Upload exceeds 50 MB")
                        digest.update(chunk)
                if size != row["size"] or digest.hexdigest() != row["sha256"]:
                    raise ValueError("Upload integrity check failed")
                result.append(str(path))
        return result

    def save_definition(self, name: str, request: TaskRequest) -> dict:
        validate_name(name)
        timestamp = now()
        with self._connect(write=True) as db:
            db.execute("INSERT INTO definitions VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET "
                       "request=excluded.request,updated_at=excluded.updated_at",
                       (name, _json(redact(request.model_dump(mode="json"))), timestamp))
        return {"name": name, "updated_at": timestamp}

    def get_definition(self, name: str) -> TaskRequest:
        validate_name(name)
        with self._connect() as db:
            row = db.execute("SELECT request FROM definitions WHERE name=?", (name,)).fetchone()
        if row is None:
            raise KeyError(name)
        return TaskRequest.model_validate_json(row[0])

    def list_definitions(self) -> list[dict]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT name,updated_at FROM definitions ORDER BY name")]

    def reserve_operation(self, caller_id: str, key: str, run_id: str) -> bool:
        if not caller_id or not key or not run_id:
            raise ValueError("Operation identity is required")
        with self._connect(write=True) as db:
            row = db.execute("SELECT status FROM operations WHERE caller_id=? AND key=?",
                             (caller_id, key)).fetchone()
            if row is None:
                db.execute("INSERT INTO operations(caller_id,key,run_id,status,updated_at) VALUES (?,?,?,?,?)",
                           (caller_id, key, run_id, "reserved", now()))
                return True
            if row["status"] == "not_sent":
                db.execute("UPDATE operations SET run_id=?,status='reserved',updated_at=? "
                           "WHERE caller_id=? AND key=?", (run_id, now(), caller_id, key))
                return True
            return False

    def operation(self, caller_id: str, key: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM operations WHERE caller_id=? AND key=?", (caller_id, key)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["evidence"] = json.loads(result["evidence"])
        return result

    def finish_operation(self, caller_id: str, key: str, run_id: str, status: str) -> None:
        # A failure is NOT evidence that nothing was sent. It remains non-retryable.
        if status not in {"succeeded", "uncertain", "unknown", "failed", "partial", "cancelled"}:
            raise ValueError("Use reconcile_operation with evidence to declare not_sent")
        with self._connect(write=True) as db:
            row = db.execute("SELECT * FROM operations WHERE caller_id=? AND key=?", (caller_id, key)).fetchone()
            if row is None or row["run_id"] != run_id:
                raise OperationConflict("Operation is not owned by this run")
            if row["status"] not in {"reserved", status}:
                raise OperationConflict("Operation is already finalized; reconcile explicitly")
            db.execute("UPDATE operations SET status=?,updated_at=? WHERE caller_id=? AND key=?",
                       (status, now(), caller_id, key))

    def reconcile_operation(self, caller_id: str, key: str, run_id: str, status: str,
                            evidence: str | dict | list) -> None:
        """Reconcile finalized operations only after their owning task is terminal.

        A terminal task with a reserved operation still needs conservative runtime
        recovery; evidence must not release a reservation a worker may still own.
        """
        if status not in {"succeeded", "not_sent"} or not evidence:
            raise ValueError("Reconciliation requires succeeded/not_sent and nonempty evidence")
        with self._connect(write=True) as db:
            row = db.execute("SELECT * FROM operations WHERE caller_id=? AND key=?", (caller_id, key)).fetchone()
            if row is None or row["run_id"] != run_id:
                raise OperationConflict("Operation is not owned by this run")
            task = db.execute("SELECT caller_id,result FROM tasks WHERE run_id=?", (run_id,)).fetchone()
            if task is None or task["caller_id"] != caller_id:
                raise OperationConflict("Operation has no matching owning task")
            result = TaskResult.model_validate_json(task["result"])
            if result.run_id != run_id:
                raise OperationConflict("Owning task run ID does not match")
            if result.status not in TERMINAL:
                raise OperationConflict("Owning task must be terminal before reconciliation")
            if row["status"] not in {
                "succeeded", "uncertain", "unknown", "failed", "partial", "cancelled", "not_sent",
            }:
                raise OperationConflict("Operation must be finalized before reconciliation")
            if row["status"] == "succeeded" and status != "succeeded":
                raise OperationConflict("A recorded success cannot be reopened")
            history = json.loads(row["evidence"])
            history.append({"run_id": run_id, "status": status, "evidence": redact(evidence), "timestamp": now()})
            changed = db.execute(
                "UPDATE operations SET status=?,evidence=?,updated_at=? "
                "WHERE caller_id=? AND key=? AND run_id=? AND status=? AND evidence=?",
                (status, _json(history), now(), caller_id, key, run_id, row["status"], row["evidence"]),
            ).rowcount
            if changed != 1:
                raise OperationConflict("Operation changed during reconciliation")

    def index_playbooks(self, documents: list[dict]) -> None:
        """Replace the derived FTS index, never the source Markdown or its trust metadata."""
        with self._connect(write=True) as db:
            db.execute("DELETE FROM playbook_index")
            db.execute("DELETE FROM playbook_fts")
            for doc in documents:
                db.execute("INSERT INTO playbook_index VALUES (?,?)", (doc["id"], _json(doc)))
                search = " ".join([doc["id"], doc.get("title", ""), doc.get("body", ""),
                                   *doc.get("tags", []), *doc.get("domains", [])])
                db.execute("INSERT INTO playbook_fts VALUES (?,?)", (doc["id"], search))

    def search_playbooks(self, goal: str, limit: int = 20) -> list[dict]:
        tokens = list(dict.fromkeys(re.findall(r"[\w-]{2,48}", goal.lower())))[:12]
        if not tokens:
            return []
        query = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)
        with self._connect() as db:
            rows = db.execute("SELECT p.document FROM playbook_fts f JOIN playbook_index p ON p.id=f.id "
                              "WHERE playbook_fts MATCH ? ORDER BY bm25(playbook_fts),p.id LIMIT ?",
                              (query, max(1, min(limit, 50))))
            return [json.loads(row[0]) for row in rows]

    def import_legacy(self, artifacts_dir: Path) -> dict:
        """Hash-index originals without moving/deleting media or trusting historical prose.

        Resume PDFs become registered copies. Tasks become PARTIAL/unknown records;
        datasets and media remain references to originals. Import is incremental and
        content-addressed; invalid or unsafe inputs are reported, not executed.
        """
        root = _absolute(artifacts_dir)
        root_fd = _directory_fd(root)
        os.close(root_fd)
        report: dict[str, Any] = {"imported": 0, "skipped": 0, "errors": [], "items": []}
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
            for name in sorted(files):
                path = Path(directory) / name
                try:
                    digest = hashlib.sha256()
                    with safe_file(path) as source:
                        while chunk := source.read(1024 * 1024):
                            digest.update(chunk)
                    sha = digest.hexdigest()
                    with self._connect(write=True) as db:
                        if db.execute("SELECT 1 FROM legacy WHERE sha256=?", (sha,)).fetchone():
                            report["skipped"] += 1
                            continue
                        reference = str(path)
                        kind = "dataset"
                        if path.suffix.lower() == ".pdf" and "resume" in path.stem.lower():
                            kind = "upload"
                            copied = self._copy_upload(path, db)
                            if copied["sha256"] != sha:
                                raise ValueError("Legacy source changed while importing")
                            reference = copied["handle"]
                        elif name.startswith("task_") and path.suffix.lower() == ".json":
                            kind = "task"
                            with safe_file(path, max_bytes=MAX_UPLOAD_BYTES) as source:
                                raw_bytes = source.read(MAX_UPLOAD_BYTES + 1)
                            if hashlib.sha256(raw_bytes).hexdigest() != sha:
                                raise ValueError("Legacy source changed while importing")
                            raw = json.loads(raw_bytes)
                            if not isinstance(raw, dict):
                                raise ValueError("Legacy task must be an object")
                            goal = raw.get("task") or raw.get("goal") or "Historical browser task"
                            request = TaskRequest(goal=str(redact(goal))[:50000], caller_id="legacy-import")
                            result = TaskResult(status=Status.PARTIAL, verification="unknown",
                                                error_code="HISTORICAL_UNVERIFIED",
                                                data={"historical": True, "source": str(path), "sha256": sha},
                                                evidence=[Evidence(kind="legacy_artifact", path=str(path),
                                                                   description="Unverified historical source")])
                            reference = result.run_id
                            db.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?)", (
                                result.run_id, request.caller_id, None, sha, request.model_dump_json(),
                                result.model_dump_json(),
                            ))
                        elif path.suffix.lower() in {".mp4", ".webm", ".mkv", ".png", ".jpg", ".jpeg"}:
                            kind = "media"
                        db.execute("INSERT INTO legacy VALUES (?,?,?,?,?)", (sha, str(path), kind, reference, now()))
                    report["imported"] += 1
                    report["items"].append({"source": str(path), "sha256": sha, "kind": kind, "reference": reference})
                except (OSError, ValueError, sqlite3.Error) as exc:
                    report["errors"].append({"source": str(path), "error": redact(str(exc))})
        return report
