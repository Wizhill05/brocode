import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from brocode.contracts import Status, TaskRequest, TaskResult, now
from brocode.memory import BACKEND_VERSION, Memory, MemoryValidationError
from brocode.store import Store, UnsafePath


@pytest.fixture
def memory(tmp_path):
    return Memory(tmp_path / "sources", Store(tmp_path / "state"))


def playbook(memory, identifier="read-page", **changes):
    metadata = {"id": identifier, "version": 1, "status": "draft", "title": "Read a weather forecast",
                "domains": ["example.com"], "required_inputs": ["target_url"],
                "input_types": {"target_url": "string"}, "verification": ["page_observed"],
                "last_verified": now(), "backend_version": BACKEND_VERSION,
                "provenance": {"source": "local-reviewed"}}
    metadata.update(changes)
    path = memory.root / identifier / "PLAYBOOK.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\n" + yaml.safe_dump(metadata) + "---\n# Read weather forecast\nObserve and report the current page.\n")
    return path


def approve(memory, identifier="read-page"):
    return memory.approve(identifier, last_verified=now(), backend_version=BACKEND_VERSION,
                          evidence="Locally reviewed synthetic fixture")


def test_seed_is_draft_and_not_retrieved(tmp_path):
    memory = Memory(Path(__file__).resolve().parents[1] / "playbooks", Store(tmp_path / "state"))
    seed = memory.inspect("indeed-easy-apply")
    assert seed["status"] == "draft" and not seed["trusted"]
    assert "never_verified" in seed["stale_reasons"]
    assert not memory.retrieve("Apply to Indeed job", ["indeed.com"])
    with pytest.raises(MemoryValidationError):
        memory.context(TaskRequest(goal="Apply", playbook_id="indeed-easy-apply"))
    with pytest.raises(MemoryValidationError):
        memory.approve("indeed-easy-apply")


def test_validation_explicit_inputs_and_approval_bound_to_content(memory):
    path = playbook(memory, status="trusted")  # Front matter cannot self-promote.
    assert not memory.inspect("read-page")["trusted"]
    with pytest.raises(MemoryValidationError):
        memory.context(TaskRequest(goal="Read", playbook_id="read-page"))
    assert approve(memory)["trusted"]
    with pytest.raises(MemoryValidationError, match="Missing"):
        memory.context(TaskRequest(goal="Read", playbook_id="read-page"))
    with pytest.raises(MemoryValidationError, match="type"):
        memory.context(TaskRequest(goal="Read", playbook_id="read-page", inputs={"target_url": []}))
    request = TaskRequest(goal="Read", playbook_id="read-page", inputs={"target_url": "https://example.com"})
    assert "Read weather forecast" in memory.context(request)
    path.write_text(path.read_text() + "Changed by a webpage\n")
    assert not memory.inspect("read-page")["trusted"]
    with pytest.raises(MemoryValidationError):
        memory.context(request)
    with pytest.raises(MemoryValidationError):
        memory.context(TaskRequest(goal="Read", playbook_id="../escape"))


def test_prose_only_and_metadata_schema(memory):
    path = playbook(memory)
    path.write_text(path.read_text() + "```python\nprint('execute')\n```\n")
    with pytest.raises(MemoryValidationError, match="prose"):
        memory.inspect("read-page")
    path = playbook(memory, command="run shell")
    with pytest.raises(MemoryValidationError, match="Unsupported"):
        memory.list()
    path = playbook(memory, domains=["https://example.com"])
    with pytest.raises(MemoryValidationError):
        memory.list()
    path = playbook(memory, version=0)
    with pytest.raises(MemoryValidationError):
        memory.list()
    path.write_text("---\n!!python/object/apply:os.system [echo unsafe]\n---\ntext")
    with pytest.raises(MemoryValidationError):
        memory.list()


def test_no_symlink_document_or_components(memory, tmp_path):
    path = playbook(memory)
    raw = path.read_bytes()
    path.unlink()
    outside = tmp_path / "outside.md"
    outside.write_bytes(raw)
    path.symlink_to(outside)
    with pytest.raises(UnsafePath):
        memory.inspect("read-page")


def test_memory_root_symlinks_rejected_and_no_source_writes(tmp_path):
    store = Store(tmp_path / "state")
    source = tmp_path / "sources"
    source.mkdir()
    linked = tmp_path / "alias"
    linked.symlink_to(source, target_is_directory=True)
    with pytest.raises(UnsafePath):
        Memory(linked, store)
    with pytest.raises(UnsafePath):
        Memory(linked / "missing", store)
    memory = Memory(source, store)
    source.rename(tmp_path / "original")
    source.symlink_to(tmp_path / "original", target_is_directory=True)
    with pytest.raises(UnsafePath):
        memory.list()
    assert not list((tmp_path / "original").iterdir())


def test_drafts_only_for_verified_success_and_no_raw_pii(memory):
    request = TaskRequest(goal="Apply for Alice Person, email alice@example.com password=sensitive",
                          inputs={"salary": 99999, "secret": "abc"})
    for status, verification in [(Status.FAILED, "passed"), (Status.SUCCEEDED, "unknown"),
                                 (Status.PARTIAL, "passed"), (Status.SUCCEEDED, "not_requested")]:
        assert memory.draft_from_result(request, TaskResult(status=status, verification=verification)) is None
    result, _ = memory.store.create_task(request, model="test-model")
    result.status, result.verification = Status.SUCCEEDED, "passed"
    result.result = "Alice Person got the job alice@example.com, salary 99999"
    memory.store.update(result)
    path = memory.draft_from_result(request, result)
    raw = path.read_text()
    assert all(item not in raw for item in ["Alice Person", "alice@example.com", "99999", "sensitive", "Apply for"])
    doc = memory.inspect(path.parent.name)
    assert doc["provenance"]["source_run"] == result.run_id
    assert doc["provenance"]["model"] == "test-model"
    assert not doc["trusted"] and doc["status"] == "draft"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert memory.approve(doc["id"])["trusted"]


def test_staleness_dates_version_and_failures(memory):
    playbook(memory)
    approve(memory)
    memory.backend_version = "browser-use/new"
    assert "backend_version_changed" in memory.inspect("read-page")["stale_reasons"]
    memory.backend_version = BACKEND_VERSION
    approval = memory.approvals_dir / "read-page.json"
    record = json.loads(approval.read_text())
    record["last_verified"] = (datetime.now(UTC) - timedelta(days=100)).isoformat()
    approval.write_text(json.dumps(record))
    assert "verification_expired" in memory.inspect("read-page")["stale_reasons"]
    approve(memory)
    failure = TaskResult(status=Status.FAILED)
    memory.record_outcome("read-page", failure)
    memory.record_outcome("read-page", failure)
    assert memory.inspect("read-page")["consecutive_failures"] == 1
    for _ in range(2):
        memory.record_outcome("read-page", TaskResult(status=Status.PARTIAL))
    assert not memory.inspect("read-page")["trusted"]
    assert "repeated_failures" in memory.inspect("read-page")["stale_reasons"]
    with pytest.raises(MemoryValidationError, match="failures"):
        approve(memory)
    memory.record_outcome("read-page", TaskResult(status=Status.SUCCEEDED, verification="passed"))
    assert memory.inspect("read-page")["consecutive_failures"] == 0
    assert not memory.inspect("read-page")["trusted"]  # Needs a new reviewed version after invalidation.


def test_bounded_fts_retrieval_domain_and_untrusted_exclusion(memory):
    for number in range(8):
        identifier = f"forecast-{number}"
        playbook(memory, identifier)
        approve(memory, identifier)
    playbook(memory, "untrusted")
    playbook(memory, "other-site", domains=["other.com"])
    approve(memory, "other-site")
    found = memory.retrieve('forecast " OR 1=1; DROP TABLE tasks; --', ["example.com"])
    assert len(found) == 5
    assert all(doc["trusted"] and doc["domains"] == ["example.com"] for doc in found)
    assert not memory.retrieve("forecast", ["unrelated.com"])
    assert memory.retrieve("unrelated vocabulary", ["example.com"])
    assert memory.store.search_playbooks("forecast")
    assert memory.context(TaskRequest(goal="forecast")) == ""  # Missing inputs do not become implicit values.


def test_facts_approval_review_redaction_and_no_import(memory):
    facts = {"name": "Honest Applicant", "salary": 100000, "work_authorization": "authorized", "password": "private"}
    saved = memory.save_facts("applicant", facts, {"source": "user reviewed"})
    assert saved["facts"]["name"] == "Honest Applicant" and saved["facts"]["salary"] == 100000
    assert saved["facts"]["password"] == "[REDACTED]"
    with pytest.raises(MemoryValidationError, match="not approved"):
        memory.load_facts("applicant")
    memory.save_facts("applicant", facts, "user reviewed", approved=True)
    assert memory.load_facts("applicant")["facts"]["work_authorization"] == "authorized"
    path = memory.facts_dir / "applicant.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    expired = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    old = (datetime.now(UTC) - timedelta(days=20)).isoformat()
    memory.save_facts("old", facts, "historical", approved=True, reviewed_at=old, review_after=expired)
    with pytest.raises(MemoryValidationError, match="review"):
        memory.load_facts("old")
    with pytest.raises(ValueError):
        memory.load_facts("../elsewhere")
    with pytest.raises(KeyError):
        memory.load_facts("historical-applicant-not-imported")
    assert not memory.list()


def test_required_facts_and_upload_handles_validated(memory, tmp_path):
    playbook(memory, required_inputs=["resume_handle", "applicant_facts_ref"], input_types={})
    approve(memory)
    source = tmp_path / "resume.pdf"
    source.write_bytes(b"resume")
    handle = memory.store.register_upload(source)["handle"]
    request = TaskRequest(goal="Read", playbook_id="read-page", upload_handles=[handle],
                          inputs={"resume_handle": handle, "applicant_facts_ref": "applicant"})
    with pytest.raises(MemoryValidationError, match="input"):
        memory.context(request)
    memory.save_facts("applicant", {"name": "Current Person"}, "local user", approved=True)
    assert memory.context(request)
    with pytest.raises(MemoryValidationError, match="upload_handles"):
        memory.context(request.model_copy(update={"upload_handles": []}))
    assert not any("Current Person" in str(doc) for doc in memory.list())
