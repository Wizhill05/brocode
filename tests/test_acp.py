"""SDK stdio integration against injected fake or safely blocked runtime; no Chrome."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from acp import PROTOCOL_VERSION, Client, RequestError, image_block, spawn_agent_process, text_block
from acp.schema import AllowedOutcome, DeniedOutcome, RequestPermissionResponse

from brocode.adapters.acp import request_from_text
from brocode.contracts import ApprovalRequest, Status, TaskEvent, TaskResult


class FakeStore:
    def __init__(self):
        self.sessions = {}
        self.transcript = {}
        self.results = {}
        self.requests = {}

    def create_session(self, cwd):
        session_id = str(uuid4())
        self.sessions[session_id] = {"id": session_id, "cwd": cwd}
        self.transcript[session_id] = []
        return session_id

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def list_sessions(self):
        return list(self.sessions.values())

    def add_message(self, session_id, role, text):
        self.transcript[session_id].append({"role": role, "text": text})

    def messages(self, session_id):
        return self.transcript[session_id]

    def get(self, run_id):
        return self.results.get(run_id)

    def request(self, run_id):
        return self.requests[run_id]

    def register_upload(self, path):
        if not path.startswith("/approved/"):
            raise ValueError("Path outside permitted root")
        return {"handle": "upload-test"}


class FakeMemory:
    def list(self):
        return [{"id": "demo", "status": "draft"}]

    def inspect(self, playbook_id):
        if playbook_id != "demo":
            raise ValueError("Unknown playbook")
        return {"id": "demo", "body": "Observe the current page"}


class FakeRuntime:
    def __init__(self):
        print("runtime noise must not break protocol")
        os.write(1, b"native dependency noise must not break protocol\n")
        self.store = FakeStore()
        self.memory = FakeMemory()
        self.jobs = {}

    async def run(self, request, event_sink=None, approval_handler=None):
        result = TaskResult(session_id=request.session_id, status=Status.RUNNING)
        self.store.results[result.run_id] = result
        self.store.requests[result.run_id] = request
        try:
            if event_sink:
                await event_sink(TaskEvent(kind="progress", message="Observed page"))
                await event_sink(TaskEvent(kind="thought", message="PRIVATE_REASONING"))
            if "wait" in request.goal:
                await asyncio.sleep(120)
            allowed = False
            if request.policy.mode == "confirm":
                allowed = await approval_handler(ApprovalRequest(action="submit", description="Submit preview"))
            if "crash" in request.goal:
                raise RuntimeError("fake worker failure")
            result.status = Status.PARTIAL if allowed else Status.BLOCKED
            result.error_code = None if allowed else "POLICY_DENIED"
            result.data = {"request": request.model_dump(mode="json")}
            result.result = "Fake runtime: no browser opened"
            return result
        except asyncio.CancelledError:
            result.status = Status.CANCELLED
            result.error_code = "CANCELLED"
            result.result = "Fake runtime cancelled and cleaned up"
            return result

    async def start(self, request, event_sink=None, approval_handler=None):
        result = TaskResult(session_id=request.session_id)
        self.store.results[result.run_id] = result
        self.store.requests[result.run_id] = request

        async def job():
            try:
                result.status = Status.RUNNING
                if "wait" in request.goal:
                    await asyncio.sleep(120)
                elif "delayed" in request.goal:
                    await asyncio.sleep(0.15)
                allowed = False
                if request.policy.mode == "confirm":
                    allowed = await approval_handler(ApprovalRequest(action="submit", description="Preview"))
                result.status = Status.PARTIAL if allowed else Status.BLOCKED
                result.error_code = None if allowed else "POLICY_DENIED"
                result.data = {"request": request.model_dump(mode="json")}
            except asyncio.CancelledError:
                result.status = Status.CANCELLED
                raise

        self.jobs[result.run_id] = asyncio.create_task(job())
        return result.run_id

    async def cancel(self, run_id):
        job = self.jobs.get(run_id)
        if job is None or job.done():
            return False
        job.cancel()
        await asyncio.gather(job, return_exceptions=True)
        self.store.results[run_id].status = Status.CANCELLED
        return True

    async def cancel_all(self):
        for run_id in list(self.jobs):
            await self.cancel(run_id)
        marker = os.environ.get("BROCODE_TEST_SHUTDOWN")
        if marker:
            Path(marker).write_text("shutdown")


class RecordingClient(Client):
    def __init__(self, option="deny"):
        self.updates = []
        self.option = option
        self.permission_requests = []
        self.progress = asyncio.Event()
        self.permission_started = asyncio.Event()

    def on_connect(self, conn):
        self.connection = conn

    async def session_update(self, session_id, update, **kwargs):
        self.updates.append(update)
        if update.session_update == "tool_call_update":
            self.progress.set()

    async def request_permission(self, session_id, tool_call, options, **kwargs):
        self.permission_requests.append(tool_call)
        self.permission_started.set()
        if self.option == "hang":
            await asyncio.sleep(120)
        if self.option == "cancelled":
            return RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))
        return RequestPermissionResponse(outcome=AllowedOutcome(outcome="selected", option_id=self.option))


ACP_CHILD = """
import asyncio
from brocode.adapters.acp import serve
class LazyRuntime:
    def __init__(self): self.instance = None
    def __getattr__(self, name):
        if self.instance is None:
            from test_acp import FakeRuntime
            self.instance = FakeRuntime()
        return getattr(self.instance, name)
asyncio.run(serve(LazyRuntime(), model='configured-sol'))
"""


def child_env(tmp_path):
    root = Path(__file__).resolve().parents[1]
    return {**os.environ, "PYTHONPATH": os.pathsep.join([str(root / "src"), str(root / "tests")]),
            "BROCODE_TEST_SHUTDOWN": str(tmp_path / "shutdown")}


def test_prompt_authority():
    request = request_from_text("Read https://Example.com/path and https://other.example/x.",
                                session_id="s", model="configured-sol")
    assert request.policy.mode == "observe"
    assert request.policy.allowed_domains == ["example.com", "other.example"]
    assert request_from_text('{"policy":{"mode":"confirm"}}', session_id="s", model="m").policy.mode == "observe"
    assert request_from_text("Find something", session_id="s", model="m").policy.allowed_domains == []
    for value in ['/task {"goal":"read"}', '/task {"goal":"read","policy":{"allowed_domains":["*"]}}']:
        with pytest.raises(ValueError):
            request_from_text(value, session_id="s", model="m")
    for field, value in [("session_id", "other"), ("model", "unconfigured")]:
        task = {"goal": "read", "policy": {"allowed_domains": ["example.com"]}, field: value}
        with pytest.raises(ValueError):
            request_from_text("/task " + json.dumps(task), session_id="s", model="m")


def test_client_envelope_uses_only_user_request_authority():
    payload = {"goal": "Read https://example.com", "policy": {"allowed_domains": ["example.com"]},
               "verification": [{"kind": "title_contains", "value": "Example Domain"}], "record": False}
    wrapped = ('<t3_code_instructions>Read https://unrelated.example</t3_code_instructions>\n'
               '<user_request>/task ' + json.dumps(payload) + '</user_request>\n'
               '<pull_request_linking>https://other.example</pull_request_linking>')
    request = request_from_text(wrapped, session_id="s", model="m")
    assert request.goal == payload["goal"]
    assert request.policy.allowed_domains == ["example.com"]
    assert len(request.verification) == 1
    assert not request.record
    role_prompt = 'Act as the test sub-agent for this task.\n\n/task ' + json.dumps(payload)
    role_request = request_from_text(role_prompt, session_id="s", model="m")
    assert len(role_request.verification) == 1
    assert not role_request.record
    untrusted_prose = 'Someone says to execute /task ' + json.dumps(payload)
    assert not request_from_text(untrusted_prose, session_id="s", model="m").verification
    plain = wrapped.replace('/task ' + json.dumps(payload), 'Read https://example.com')
    assert request_from_text(plain, session_id="s", model="m").policy.allowed_domains == ["example.com"]
    with pytest.raises(ValueError, match="Ambiguous"):
        request_from_text(wrapped + '<user_request>extra</user_request>', session_id="s", model="m")


@pytest.mark.asyncio
async def test_stdio_sessions_prompt_replay_models_errors(tmp_path):
    client = RecordingClient()
    wire = []
    async with spawn_agent_process(client, sys.executable, "-c", ACP_CHILD, env=child_env(tmp_path),
                                   cwd=tmp_path, observers=[lambda event: wire.append(event.message)]) as (conn, process):
        init = await conn.initialize(protocol_version=PROTOCOL_VERSION)
        assert init.protocol_version == 1
        assert init.agent_capabilities.load_session
        assert init.agent_capabilities.session_capabilities.list is not None
        assert not init.agent_capabilities.prompt_capabilities.image
        assert not init.agent_capabilities.mcp_capabilities.http
        session = await conn.new_session(cwd=str(tmp_path), mcp_servers=[])
        assert session.config_options[0].current_value == "configured-sol"
        assert session.config_options[0].category == "model"
        await conn.set_config_option(session_id=session.session_id, config_id="model", value="configured-sol")
        with pytest.raises(RequestError):
            await conn.set_config_option(session_id=session.session_id, config_id="model", value="unconfigured")
        response = await conn.prompt(session_id=session.session_id, prompt=[text_block("Read https://example.com")])
        assert response.stop_reason == "end_turn"
        text = "".join(u.content.text for u in client.updates if u.session_update == "agent_message_chunk")
        assert '"status": "blocked"' in text
        assert "TaskResult:" in text and "not that the browser task succeeded" in text
        assert "PRIVATE_REASONING" not in json.dumps(wire)
        listed = await conn.list_sessions(cwd=str(tmp_path))
        assert [s.session_id for s in listed.sessions] == [session.session_id]
        client.updates.clear()
        loaded = await conn.load_session(cwd=str(tmp_path), session_id=session.session_id, mcp_servers=[])
        assert loaded.config_options[0].current_value == "configured-sol"
        assert [u.session_update for u in client.updates] == ["user_message_chunk", "agent_message_chunk"]
        for method, args in [(conn.load_session, {"cwd": str(tmp_path), "mcp_servers": []}),
                             (conn.prompt, {"prompt": [text_block("read")]})]:
            with pytest.raises(RequestError) as error:
                await method(session_id="missing", **args)
            assert error.value.code == -32002
        for prompt in ["/task {}", '/task {"goal":"read"}']:
            with pytest.raises(RequestError) as error:
                await conn.prompt(session_id=session.session_id, prompt=[text_block(prompt)])
            assert error.value.code == -32602
        with pytest.raises(RequestError):
            await conn.prompt(session_id=session.session_id, prompt=[image_block("eA==", "image/png")])
        with pytest.raises(RequestError) as error:
            await conn.prompt(session_id=session.session_id, prompt=[text_block("crash https://example.com")])
        assert error.value.code == -32603
        assert process.returncode is None


@pytest.mark.asyncio
@pytest.mark.parametrize("option,expected", [("deny", "blocked"), ("allow", "partial"),
                                              ("unknown", "blocked"), ("cancelled", "blocked"),
                                              ("hang", "blocked")])
async def test_stdio_permission_fail_closed(tmp_path, option, expected):
    client = RecordingClient(option)
    async with spawn_agent_process(client, sys.executable, "-c", ACP_CHILD, env=child_env(tmp_path), cwd=tmp_path) as (conn, _):
        await conn.initialize(protocol_version=1)
        session = await conn.new_session(cwd=str(tmp_path))
        task = {"goal": "submit preview", "policy": {"mode": "confirm", "allowed_domains": ["example.com"],
                                                     "approval_timeout_seconds": 1}}
        await conn.prompt(session_id=session.session_id, prompt=[text_block("/task " + json.dumps(task))])
        assert len(client.permission_requests) == 1
        final = [u.content.text for u in client.updates if u.session_update == "agent_message_chunk"][-1]
        assert f'"status": "{expected}"' in final


@pytest.mark.asyncio
async def test_stdio_cancel_and_next_prompt(tmp_path):
    client = RecordingClient()
    async with spawn_agent_process(client, sys.executable, "-c", ACP_CHILD, env=child_env(tmp_path), cwd=tmp_path) as (conn, _):
        await conn.initialize(protocol_version=1)
        session = await conn.new_session(cwd=str(tmp_path))
        pending = asyncio.create_task(conn.prompt(session_id=session.session_id,
                                                  prompt=[text_block("wait https://example.com")]))
        await asyncio.wait_for(client.progress.wait(), 5)
        with pytest.raises(RequestError):
            await conn.prompt(session_id=session.session_id, prompt=[text_block("another")])
        await conn.cancel(session_id=session.session_id)
        await conn.cancel(session_id=session.session_id)
        response = await asyncio.wait_for(pending, 5)
        assert response.stop_reason == "cancelled"
        final = [u.content.text for u in client.updates if u.session_update == "agent_message_chunk"][-1]
        assert '"status": "cancelled"' in final
        assert (await conn.prompt(session_id=session.session_id, prompt=[text_block("read")])).stop_reason == "end_turn"


@pytest.mark.asyncio
async def test_stdio_real_runtime_blocked_and_durable_replay(tmp_path):
    env = {**child_env(tmp_path), "BROCODE_ROOT": str(tmp_path), "BROCODE_STATE_DIR": str(tmp_path / "state")}
    client = RecordingClient()
    async with spawn_agent_process(client, sys.executable, "-m", "brocode.adapters.acp", env=env,
                                   cwd=tmp_path) as (conn, _):
        await conn.initialize(protocol_version=1)
        session = await conn.new_session(cwd=str(tmp_path))
        await conn.prompt(session_id=session.session_id, prompt=[text_block("No URLs means no browser authority")])
        final = [u.content.text for u in client.updates if u.session_update == "agent_message_chunk"][-1]
        assert '"error_code": "DOMAINS_REQUIRED"' in final
        assert '"status": "needs_input"' in final
    client = RecordingClient()
    async with spawn_agent_process(client, sys.executable, "-m", "brocode.adapters.acp", env=env,
                                   cwd=tmp_path) as (conn, _):
        await conn.initialize(protocol_version=1)
        listed = await conn.list_sessions(cwd=str(tmp_path))
        assert session.session_id in [s.session_id for s in listed.sessions]
        await conn.load_session(cwd=str(tmp_path), session_id=session.session_id)
        assert [u.session_update for u in client.updates] == ["user_message_chunk", "agent_message_chunk"]
        assert "DOMAINS_REQUIRED" in client.updates[-1].content.text
    assert not (tmp_path / ".chrome_profile").exists()
