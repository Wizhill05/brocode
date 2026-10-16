import json

import pytest

from brocode.cli import dispatch, parser
from brocode.contracts import Status, TaskRequest
from brocode.memory import Memory
from brocode.store import Store


@pytest.fixture
def local_state(tmp_path, monkeypatch):
    monkeypatch.setenv("BROCODE_ROOT", str(tmp_path))
    monkeypatch.setenv("BROCODE_STATE_DIR", str(tmp_path / "var"))
    return tmp_path


async def test_cli_facts_review_and_definitions(local_state, capsys):
    path = local_state / "facts.json"
    path.write_text(json.dumps({"availability": "ask again"}))
    args = parser().parse_args(["facts", "applicant", "--file", str(path),
                                "--provenance", "explicit user review", "--review-days", "10"])
    assert await dispatch(args) == 0
    memory = Memory(local_state, Store(local_state / "var"))
    assert memory.load_facts("applicant")["approved"]
    req = local_state / "request.json"
    req.write_text(TaskRequest(goal="Read").model_dump_json())
    assert await dispatch(parser().parse_args(["tasks", "save", "read", str(req)])) == 0
    assert Store(local_state / "var").get_definition("read").goal == "Read"


async def test_cli_operation_reconciliation(local_state):
    store = Store(local_state / "var")
    result, _ = store.create_task(TaskRequest(goal="read"))
    assert store.reserve_operation("local", "account:record", result.run_id)
    store.finish_operation("local", "account:record", result.run_id, "uncertain")
    result.status = Status.PARTIAL
    store.update(result)
    args = parser().parse_args(["reconcile", "account:record", "--outcome", "not_sent",
                                "--evidence", "Account records checked; absent"])
    assert await dispatch(args) == 0
    assert store.operation("local", "account:record")["status"] == "not_sent"
