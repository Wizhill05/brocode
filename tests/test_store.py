import hashlib
import json
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from multiprocessing import get_context
from pathlib import Path

import pytest

from brocode.contracts import Status, TaskEvent, TaskRequest
from brocode.store import IdempotencyConflict, OperationConflict, Store, UnsafePath, redact


def _create_task_at(args):
    root, caller = args
    store = Store(Path(root))
    result, created = store.create_task(TaskRequest(goal="Read a page", caller_id=caller, idempotency_key="same"))
    return result.run_id, created


def test_task_idempotency_scope_and_fingerprint(tmp_path):
    store = Store(tmp_path / "state")
    request = TaskRequest(goal="Read a page", idempotency_key="key")
    first, created = store.create_task(request, model="model-a")
    second, again = store.create_task(request, model="model-a")
    assert created and not again and first.run_id == second.run_id
    assert store.request(first.run_id) == request
    with pytest.raises(IdempotencyConflict):
        store.create_task(request.model_copy(update={"goal": "Submit form"}), model="model-a")
    with pytest.raises(IdempotencyConflict):
        store.create_task(request, model="model-b")
    other, created = store.create_task(request.model_copy(update={"caller_id": "other"}), model="model-a")
    assert created and other.run_id != first.run_id
    assert store.create_task(TaskRequest(goal="repeat"))[0].run_id != store.create_task(TaskRequest(goal="repeat"))[0].run_id


def test_atomic_across_processes(tmp_path):
    root = tmp_path / "state"
    Store(root)
    with get_context("spawn").Pool(4) as pool:
        outcomes = pool.map(_create_task_at, [(str(root), "client")] * 12)
    assert sum(created for _, created in outcomes) == 1
    assert len({run_id for run_id, _ in outcomes}) == 1


def test_sessions_events_results_definitions(tmp_path, monkeypatch):
    store = Store(tmp_path / "state")
    monkeypatch.setenv("TEST_API_KEY", "secret-value-123")
    session = store.create_session(tmp_path / "caller")
    assert store.get_session(session)["cwd"] == str(tmp_path / "caller")
    assert store.list_sessions()[0]["id"] == session
    assert store.get_session("missing") is None
    store.add_message(session, "user", "My name is Honest Person. Bearer abc123")
    assert store.messages(session)[0]["text"] == "My name is Honest Person. Bearer [REDACTED]"
    with pytest.raises(sqlite3.IntegrityError):
        store.add_message("missing", "user", "text")
    request = TaskRequest(goal="Read page", session_id=session)
    result, _ = store.create_task(request)
    store.append_event(result.run_id, TaskEvent(kind="progress", message="secret-value-123", data={"password": "pw"}))
    assert store.events(result.run_id)[0]["message"] == "[REDACTED]"
    assert store.events(result.run_id)[0]["data"]["password"] == "[REDACTED]"
    result.status = Status.FAILED
    result.result = "password=abc123"
    store.update(result)
    assert store.get(result.run_id).status == Status.FAILED
    assert "abc123" not in store.get(result.run_id).result
    assert store.get("missing") is None
    with pytest.raises(KeyError):
        store.request("missing")
    with pytest.raises(KeyError):
        store.update(result.model_copy(update={"run_id": "missing"}))
    assert store.save_definition("daily", request)["name"] == "daily"
    assert store.get_definition("daily") == request
    assert store.list_definitions()[0]["name"] == "daily"
    with pytest.raises(ValueError):
        store.save_definition("../escape", request)


def test_permissions_and_only_explicit_root(tmp_path, monkeypatch):
    home, unrelated = tmp_path / "home", tmp_path / "caller"
    home.mkdir()
    unrelated.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(unrelated)
    old_mask = os.umask(0)
    try:
        store = Store(tmp_path / "private" / "state")
        assert stat.S_IMODE(store.state_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.state_dir.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(store.db_path.stat().st_mode) == 0o600
        with store._connect(write=True) as db:
            db.execute("INSERT INTO sessions VALUES ('test','cwd','date')")
            journal = Path(str(store.db_path) + "-journal")
            assert journal.exists() and stat.S_IMODE(journal.stat().st_mode) == 0o600
        source = tmp_path / "source.pdf"
        source.write_bytes(b"resume")
        row = store.register_upload(source)
        assert stat.S_IMODE(Path(row["path"]).stat().st_mode) == 0o600
        assert stat.S_IMODE(store.uploads_dir.stat().st_mode) == 0o700
    finally:
        os.umask(old_mask)
    assert not list(home.iterdir())
    assert not list(unrelated.iterdir())


def test_upload_copy_integrity_and_no_extension_authority(tmp_path):
    store = Store(tmp_path / "state")
    source = tmp_path / "resume.pdf"
    source.write_bytes(b"original bytes")
    uploaded = store.register_upload(source)
    copy = Path(uploaded["path"])
    assert uploaded["sha256"] == hashlib.sha256(b"original bytes").hexdigest()
    assert uploaded["source"] == str(source)
    assert copy.name == uploaded["handle"] and copy.parent == store.uploads_dir
    source.write_bytes(b"changed outside")
    assert store.resolve_uploads([uploaded["handle"]]) == [str(copy)]
    assert copy.read_bytes() == b"original bytes"
    copy.write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="integrity"):
        store.resolve_uploads([uploaded["handle"]])
    with pytest.raises(KeyError):
        store.resolve_uploads(["unregistered"])
    with pytest.raises(ValueError):
        store.resolve_uploads(["../../escape"])


def test_symlink_components_and_traversal_rejected(tmp_path):
    store = Store(tmp_path / "state")
    source = tmp_path / "real.txt"
    source.write_text("private")
    linked = tmp_path / "linked.txt"
    linked.symlink_to(source)
    with pytest.raises(UnsafePath):
        store.register_upload(linked)
    directory = tmp_path / "alias"
    directory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(UnsafePath):
        store.register_upload(directory / "real.txt")
    with pytest.raises(UnsafePath):
        Store(directory / "new-state")
    with pytest.raises(UnsafePath):
        store.register_upload(tmp_path / "state" / ".." / "real.txt")
    uploaded = store.register_upload(source)
    destination = Path(uploaded["path"])
    destination.unlink()
    destination.symlink_to(source)
    with pytest.raises(UnsafePath):
        store.resolve_uploads([uploaded["handle"]])
    dangerous = tmp_path / "unsafe-state"
    dangerous.mkdir()
    (dangerous / "state.sqlite3").symlink_to(source)
    with pytest.raises(OSError):
        Store(dangerous)
    assert source.read_text() == "private"


def test_large_upload_nonregular_and_forged_database_path(tmp_path):
    store = Store(tmp_path / "state")
    large = tmp_path / "large"
    with large.open("wb") as stream:
        stream.truncate(50 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="limit"):
        store.register_upload(large)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(UnsafePath):
        store.register_upload(fifo)
    source = tmp_path / "source"
    source.write_bytes(b"data")
    row = store.register_upload(source)
    with store._connect(write=True) as db:
        db.execute("UPDATE uploads SET path=? WHERE handle=?", (str(source), row["handle"]))
    with pytest.raises(UnsafePath):
        store.resolve_uploads([row["handle"]])


def test_operation_ledger_uncertainty_and_explicit_reconciliation(tmp_path):
    store = Store(tmp_path / "state")
    first, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client", operation_key="submit"))
    third, _ = store.create_task(TaskRequest(goal="Retry form", caller_id="client", operation_key="submit"))
    run1, run3 = first.run_id, third.run_id
    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(lambda _: store.reserve_operation("client", "submit", run1), range(12)))
    assert sum(reservations) == 1
    assert not store.reserve_operation("client", "submit", run1)
    assert store.reserve_operation("another-client", "submit", "run2")
    with pytest.raises(OperationConflict):
        store.finish_operation("client", "submit", "wrong-owner", "uncertain")
    store.finish_operation("client", "submit", run1, "uncertain")
    assert not store.reserve_operation("client", "submit", run3)
    with pytest.raises(ValueError):
        store.finish_operation("client", "submit", run1, "not_sent")
    with pytest.raises(ValueError):
        store.reconcile_operation("client", "submit", run1, "not_sent", evidence=[])
    first.status = Status.PARTIAL
    store.update(first)
    store.reconcile_operation("client", "submit", run1, "not_sent", evidence="Reviewed site record; no submission")
    assert store.reserve_operation("client", "submit", run3)
    before = store.operation("client", "submit")
    assert before["evidence"][0]["status"] == "not_sent"
    with pytest.raises(OperationConflict, match="not owned"):
        store.reconcile_operation("client", "submit", run1, "not_sent", evidence="Stale review")
    assert store.operation("client", "submit") == before
    assert not store.reserve_operation("client", "submit", "run4")
    store.finish_operation("client", "submit", run3, "succeeded")
    third.status = Status.SUCCEEDED
    store.update(third)
    assert not store.reserve_operation("client", "submit", "run4")
    with pytest.raises(OperationConflict):
        store.reconcile_operation("client", "submit", run3, "not_sent", evidence="contradiction")
    assert store.operation("missing", "nothing") is None


@pytest.mark.parametrize("task_status", [Status.QUEUED, Status.RUNNING, Status.AWAITING_APPROVAL])
@pytest.mark.parametrize("operation_status", ["reserved", "uncertain", "succeeded"])
@pytest.mark.parametrize("target", ["not_sent", "succeeded"])
def test_reconciliation_rejects_live_task_without_unlocking(tmp_path, task_status, operation_status, target):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client", operation_key="submit"))
    result.status = task_status
    store.update(result)
    assert store.reserve_operation("client", "submit", result.run_id)
    if operation_status != "reserved":
        # Runtime finalizes the ledger before it persists the terminal task result.
        store.finish_operation("client", "submit", result.run_id, operation_status)
    before = store.operation("client", "submit")
    with pytest.raises(OperationConflict, match="must be terminal"):
        store.reconcile_operation("client", "submit", result.run_id, target, evidence="Reviewed site records")
    assert store.operation("client", "submit") == before
    assert not store.reserve_operation("client", "submit", "next-run")


@pytest.mark.parametrize("target", ["not_sent", "succeeded"])
def test_terminal_task_reserved_operation_needs_runtime_recovery(tmp_path, target):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client"))
    assert store.reserve_operation("client", "submit", result.run_id)
    result.status = Status.CANCELLED
    store.update(result)
    before = store.operation("client", "submit")
    with pytest.raises(OperationConflict, match="must be finalized"):
        store.reconcile_operation("client", "submit", result.run_id, target, evidence="Reviewed site records")
    assert store.operation("client", "submit") == before
    assert not store.reserve_operation("client", "submit", "next-run")
    # Only conservative runtime recovery can finalize a stranded reservation.
    store.finish_operation("client", "submit", result.run_id, "uncertain")
    store.reconcile_operation("client", "submit", result.run_id, target, evidence="Reviewed site records")
    assert store.reserve_operation("client", "submit", "next-run") == (target == "not_sent")


@pytest.mark.parametrize("ownership", ["missing_task", "wrong_caller", "wrong_result_run", "wrong_operation_run"])
def test_reconciliation_checks_task_and_operation_ownership(tmp_path, ownership):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client"))
    result.status = Status.PARTIAL
    store.update(result)
    assert store.reserve_operation("client", "submit", result.run_id)
    store.finish_operation("client", "submit", result.run_id, "uncertain")
    with store._connect(write=True) as db:
        if ownership == "missing_task":
            db.execute("DELETE FROM tasks WHERE run_id=?", (result.run_id,))
        elif ownership == "wrong_caller":
            db.execute("UPDATE tasks SET caller_id='other' WHERE run_id=?", (result.run_id,))
        elif ownership == "wrong_result_run":
            changed = result.model_copy(update={"run_id": "other-run"})
            db.execute("UPDATE tasks SET result=? WHERE run_id=?", (changed.model_dump_json(), result.run_id))
        else:
            db.execute("UPDATE operations SET run_id='other-run' WHERE key='submit'")
    before = store.operation("client", "submit")
    with pytest.raises(OperationConflict):
        store.reconcile_operation("client", "submit", result.run_id, "not_sent", evidence="Reviewed site records")
    assert store.operation("client", "submit") == before
    assert not store.reserve_operation("client", "submit", "next-run")


@pytest.mark.parametrize("operation_status", ["uncertain", "unknown", "failed", "partial", "cancelled", "succeeded"])
@pytest.mark.parametrize("target", ["not_sent", "succeeded"])
def test_terminal_reconciliation_allowed_transitions(tmp_path, operation_status, target):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client"))
    assert store.reserve_operation("client", "submit", result.run_id)
    store.finish_operation("client", "submit", result.run_id, operation_status)
    result.status = Status.PARTIAL
    store.update(result)
    if operation_status == "succeeded" and target == "not_sent":
        with pytest.raises(OperationConflict, match="success cannot be reopened"):
            store.reconcile_operation("client", "submit", result.run_id, target, evidence="Contradiction")
        assert store.operation("client", "submit")["evidence"] == []
        assert not store.reserve_operation("client", "submit", "next-run")
    else:
        evidence = {"review": "Checked site records", "password": "do-not-store"}
        store.reconcile_operation("client", "submit", result.run_id, target, evidence=evidence)
        record = store.operation("client", "submit")
        assert record["status"] == target and record["run_id"] == result.run_id
        assert record["evidence"][0]["evidence"] == {
            "review": "Checked site records", "password": "[REDACTED]",
        }
        assert store.reserve_operation("client", "submit", "next-run") == (target == "not_sent")


@pytest.mark.parametrize("changed_column,changed_value", [
    ("status", "succeeded"), ("run_id", "new-owner"), ("evidence", '[{"review":"new evidence"}]'),
])
def test_reconciliation_compare_and_set_rejects_changed_ledger(tmp_path, monkeypatch, changed_column, changed_value):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client"))
    assert store.reserve_operation("client", "submit", result.run_id)
    store.finish_operation("client", "submit", result.run_id, "uncertain")
    result.status = Status.PARTIAL
    store.update(result)
    before = store.operation("client", "submit")
    connect = store._connect
    intercepted = False

    class ChangedLedger:
        def __init__(self, db):
            self.db = db

        def execute(self, sql, params=()):
            nonlocal intercepted
            if sql.startswith("UPDATE operations SET status=?,evidence=?"):
                intercepted = True
                # Inject a state change between the read and conditional write.
                self.db.execute(
                    f"UPDATE operations SET {changed_column}=? WHERE caller_id=? AND key=?",
                    (changed_value, "client", "submit"),
                )
            return self.db.execute(sql, params)

    @contextmanager
    def changed_connect(*, write=False):
        with connect(write=write) as db:
            yield ChangedLedger(db) if write else db

    with monkeypatch.context() as patch:
        patch.setattr(store, "_connect", changed_connect)
        with pytest.raises(OperationConflict, match="changed during reconciliation"):
            store.reconcile_operation("client", "submit", result.run_id, "not_sent", evidence="Old review")
    assert intercepted
    assert store.operation("client", "submit") == before
    assert not store.reserve_operation("client", "submit", "next-run")


def test_concurrent_terminal_reconciliations_preserve_evidence(tmp_path):
    store = Store(tmp_path / "state")
    result, _ = store.create_task(TaskRequest(goal="Submit form", caller_id="client"))
    assert store.reserve_operation("client", "submit", result.run_id)
    store.finish_operation("client", "submit", result.run_id, "uncertain")
    result.status = Status.PARTIAL
    store.update(result)

    def reconcile(index):
        other = Store(store.state_dir)
        other.reconcile_operation("client", "submit", result.run_id, "succeeded", evidence={"review": index})

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(reconcile, range(8)))
    record = store.operation("client", "submit")
    assert record["status"] == "succeeded"
    assert sorted(item["evidence"]["review"] for item in record["evidence"]) == list(range(8))
    assert not store.reserve_operation("client", "submit", "next-run")


def test_import_legacy_idempotent_preserves_originals_and_uncertain(tmp_path):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    task = legacy / "task_123.json"
    task.write_text(json.dumps({"task": "Apply to role", "model": "old-model", "final_result": "Successfully applied!"}))
    resume = legacy / "resume_v1.pdf"
    resume.write_bytes(b"pdf bytes")
    dataset = legacy / "saved_jobs.json"
    dataset.write_text('[{"title":"Private role"}]')
    media = legacy / "movie.mp4"
    media.write_bytes(b"video")
    originals = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in legacy.iterdir()}
    store = Store(tmp_path / "state")
    report = store.import_legacy(legacy)
    assert report["imported"] == 4 and not report["errors"]
    record = next(item for item in report["items"] if item["kind"] == "task")
    result = store.get(record["reference"])
    assert result.status == Status.PARTIAL and result.verification == "unknown"
    assert result.result is None and result.error_code == "HISTORICAL_UNVERIFIED"
    upload = next(item for item in report["items"] if item["kind"] == "upload")
    assert Path(store.resolve_uploads([upload["reference"]])[0]).read_bytes() == b"pdf bytes"
    assert next(item for item in report["items"] if item["kind"] == "dataset")["reference"] == str(dataset)
    assert store.import_legacy(legacy)["skipped"] == 4
    assert originals == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in legacy.iterdir()}
    (legacy / "task_bad.json").write_text("{bad json")
    (legacy / "link").symlink_to(media)
    errors = store.import_legacy(legacy)["errors"]
    assert len(errors) == 2


def test_redaction_keeps_honest_user_facts():
    value = {"name": "A Real Person", "work_authorization": "authorized", "salary": 120000,
             "password": "sensitive", "note": "Bearer credential123 api_key=abcdef "
             "https://user:pass@example.com/?access_token=xyz known-value"}
    result = redact(value, {"KEY": "known-value"})
    assert result["name"] == value["name"] and result["salary"] == 120000
    assert result["work_authorization"] == "authorized"
    assert result["password"] == "[REDACTED]"
    assert all(secret not in result["note"] for secret in ["credential123", "abcdef", "user:pass", "xyz", "known-value"])
