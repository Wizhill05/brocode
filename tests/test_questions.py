"""Synthetic caller-question path: no browser, network, or profile.

Mocks IPC (socketpair EventChannel), runtime (injected worker_runner),
policy (real ActionPolicy), and handlers (async fakes).
"""
from __future__ import annotations

import asyncio
import json
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from brocode import worker
from brocode.contracts import (
    MAX_ANSWER_CHARS,
    Policy,
    QuestionError,
    QuestionRequest,
    Status,
    TaskRequest,
    WorkerOutcome,
)
from brocode.policy import ActionPolicy
from brocode.runtime import Runtime
from brocode.settings import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        root=tmp_path,
        state_dir=tmp_path / "var",
        profile_dir=tmp_path / "profile",
        proxy_url="http://127.0.0.1:1088",
        egress_mode="tailscale",
        model="test-model",
        base_url="https://api.example.test/v1",
        api_key="test-secret-123",
        chrome_path="/no/chrome",
    )


async def good_checks(*_):
    return [{"name": "fixture", "ok": True, "detail": "synthetic preflight"}]


def request(**kwargs):
    return TaskRequest(
        goal="Read https://example.com", policy=Policy(allowed_domains=["example.com"]), **kwargs
    )


# --- contracts ---


def test_question_schema_accepts_bounded_question_with_choices():
    q = QuestionRequest(question="Which filter?", choices=["newest", "oldest"])
    assert q.question == "Which filter?"
    assert q.timeout_seconds == 120
    assert q.question_id


def test_question_schema_rejects_empty_overlong_and_many_choices():
    with pytest.raises(ValidationError):
        QuestionRequest(question="")
    with pytest.raises(ValidationError):
        QuestionRequest(question="x" * 2001)
    with pytest.raises(ValidationError):
        QuestionRequest(question="Pick?", choices=[f"c{i}" for i in range(9)])
    with pytest.raises(ValidationError):
        QuestionRequest(question="Pick?", timeout_seconds=0)
    with pytest.raises(ValidationError):
        QuestionRequest(question="Pick?", timeout_seconds=301)


@pytest.mark.parametrize("probe", [
    "What is your password?",
    "Share your API key please",
    "Enter the auth token shown",
    "Paste your seed phrase",
    "What is the one-time code?",
])
def test_question_schema_never_requests_secrets(probe):
    with pytest.raises(ValidationError, match="secret"):
        QuestionRequest(question=probe)


# --- runtime ask propagation ---


async def test_runtime_without_handler_fails_closed_not_guessed(settings):
    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        try:
            await ask(QuestionRequest(question="Which page?"))
            return WorkerOutcome(result="guessed")
        except QuestionError as exc:
            return WorkerOutcome(error_code=exc.code)

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    result = await runtime.run(request())
    assert result.error_code == "QUESTION_HANDLER_REQUIRED"
    assert result.result != "guessed"


async def test_runtime_handler_answer_flows_through(settings):
    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        answer = await ask(QuestionRequest(question="Which filter?"))
        return WorkerOutcome(result=f"saw:{answer}")

    async def handler(question):
        assert isinstance(question, QuestionRequest)
        return "newest"

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    result = await runtime.run(request(), question_handler=handler)
    assert "saw:newest" in (result.result or "")


async def test_runtime_truncates_overlong_answer(settings):
    seen = {}

    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        answer = await ask(QuestionRequest(question="Describe?"))
        seen["len"] = len(answer)
        return WorkerOutcome(result="ok")

    async def handler(question):
        return "y" * (MAX_ANSWER_CHARS + 500)

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    await runtime.run(request(), question_handler=handler)
    assert seen["len"] == MAX_ANSWER_CHARS


async def test_runtime_declined_answer_is_explicit(settings):
    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        try:
            await ask(QuestionRequest(question="Proceed?"))
            return WorkerOutcome(result="unexpected")
        except QuestionError as exc:
            return WorkerOutcome(error_code=exc.code)

    async def handler(question):
        return None

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    result = await runtime.run(request(), question_handler=handler)
    assert result.error_code == "QUESTION_DECLINED"


async def test_runtime_question_timeout_capped_by_wall_clock(settings):
    from brocode.contracts import Budget

    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        started = time.monotonic()
        try:
            await ask(QuestionRequest(question="Pick?", timeout_seconds=300))
            return WorkerOutcome(result="unexpected")
        except QuestionError as exc:
            return WorkerOutcome(error_code=f"{exc.code}:{time.monotonic() - started:.1f}s")

    async def handler(question):
        await asyncio.sleep(60)

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    result = await runtime.run(
        request(budget=Budget(timeout_seconds=1)), question_handler=handler
    )
    assert result.error_code.startswith("QUESTION_TIMEOUT:")
    waited = float(result.error_code.split(":")[1].rstrip("s"))
    assert waited < 5


async def test_runtime_cancel_settles_pending_question_and_releases_lease(settings):
    from brocode.runtime import ProfileLease

    asked = asyncio.Event()
    release = asyncio.Event()

    async def runner(request, run_dir, uploads, context, emit, approve, ask):
        try:
            await ask(QuestionRequest(question="Which one?", timeout_seconds=300))
            return WorkerOutcome(result="unexpected")
        except (QuestionError, asyncio.CancelledError):
            raise asyncio.CancelledError

    async def handler(question):
        asked.set()
        await release.wait()

    runtime = Runtime(settings, worker_runner=runner, preflight_checker=good_checks)
    run_id = await runtime.start(request(), question_handler=handler)
    await asyncio.wait_for(asked.wait(), 5)
    assert await runtime.cancel(run_id)
    await runtime.cancel_all()
    assert runtime.store.get(run_id).status == Status.CANCELLED
    release.set()
    with ProfileLease(settings.profile_dir):
        pass


# --- worker EventChannel IPC ---


async def _channel_pair():
    a, b = socket.socketpair()
    b.setblocking(False)
    channel = await worker.EventChannel.from_fd(a.detach())
    reader, writer = await asyncio.open_connection(sock=b)
    return channel, reader, writer


async def test_event_channel_question_round_trip():
    channel, reader, writer = await _channel_pair()
    try:
        question = QuestionRequest(question="Which filter?", choices=["a", "b"])
        pending = asyncio.create_task(channel.ask(question, timeout=5))
        frame = json.loads(await asyncio.wait_for(reader.readline(), 5))
        assert frame["type"] == "question"
        assert frame["question"]["question"] == "Which filter?"
        assert frame["question"]["question_id"] == question.question_id
        writer.write((json.dumps({
            "type": "question_response",
            "question_id": question.question_id,
            "answer": "  a  ",
            "error_code": None,
        }) + "\n").encode())
        await writer.drain()
        assert await asyncio.wait_for(pending, 5) == "a"
    finally:
        writer.close()
        await writer.wait_closed()
        await channel.close()


async def test_event_channel_question_error_propagates_code():
    channel, reader, writer = await _channel_pair()
    try:
        question = QuestionRequest(question="Proceed?")
        pending = asyncio.create_task(channel.ask(question, timeout=5))
        frame = json.loads(await asyncio.wait_for(reader.readline(), 5))
        writer.write((json.dumps({
            "type": "question_response",
            "question_id": frame["question"]["question_id"],
            "answer": None,
            "error_code": "QUESTION_HANDLER_REQUIRED",
        }) + "\n").encode())
        await writer.drain()
        with pytest.raises(QuestionError) as excinfo:
            await asyncio.wait_for(pending, 5)
        assert excinfo.value.code == "QUESTION_HANDLER_REQUIRED"
    finally:
        writer.close()
        await writer.wait_closed()
        await channel.close()


async def test_event_channel_close_settles_pending_question():
    channel, reader, writer = await _channel_pair()
    try:
        pending = asyncio.create_task(
            channel.ask(QuestionRequest(question="Waiting?"), timeout=30)
        )
        await asyncio.wait_for(reader.readline(), 5)
        await channel.close()
        with pytest.raises(QuestionError) as excinfo:
            await asyncio.wait_for(pending, 5)
        assert excinfo.value.code == "QUESTION_CANCELLED"
    finally:
        writer.close()
        await writer.wait_closed()


# --- worker ask_caller dispatch ---


class FakeQuestionChannel:
    def __init__(self, answer="newest", error=None):
        self.answer = answer
        self.error = error
        self.events = []
        self.questions = []

    async def event(self, *args, **kwargs):
        self.events.append((args, kwargs))

    async def approve(self, approval):
        return False

    async def ask(self, question, timeout):
        self.questions.append((question, timeout))
        if self.error:
            raise QuestionError(self.error)
        return self.answer


def make_tools(tmp_path, channel=None, mode="observe"):
    channel = channel or FakeQuestionChannel()
    req = TaskRequest(
        goal="read", operation_key="op",
        policy=Policy(mode=mode, allowed_domains=["example.com"]),
    )
    policy = ActionPolicy(req, [], channel.approve)
    return worker.guarded_tools_class()(policy, req, channel, tmp_path), policy, req, channel


async def _in_scope(monkeypatch, url="https://example.com/list"):
    async def identity(browser):
        return {"url": url, "title": "t"}
    monkeypatch.setattr(worker, "page_identity", identity)


async def test_ask_caller_registered_and_unknown_still_denied(tmp_path, monkeypatch):
    tools, _, _, _ = make_tools(tmp_path)
    assert "ask_caller" in tools.registry.registry.actions
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action("evaluate", {}, SimpleNamespace())
    assert result.error == "ACTION_NOT_ALLOWED"


async def test_ask_caller_returns_answer_as_untrusted_data(tmp_path, monkeypatch):
    tools, policy, _, channel = make_tools(tmp_path)
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Which filter?"}, SimpleNamespace())
    assert not result.error
    assert "newest" in result.extracted_content
    assert "untrusted" in result.extracted_content
    assert policy.actions == 1 and not policy.mutated
    assert len(channel.questions) == 1
    assert policy.error_code is None


async def test_ask_caller_scope_guard_blocks_out_of_scope(tmp_path, monkeypatch):
    tools, policy, _, channel = make_tools(tmp_path)
    await _in_scope(monkeypatch, url="https://evil.test/phish")
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Proceed?"}, SimpleNamespace())
    assert result.error == "DOMAIN_OUT_OF_SCOPE"
    assert not channel.questions and policy.actions == 0


async def test_ask_caller_rejects_secret_solicitation(tmp_path, monkeypatch):
    tools, _policy, _, channel = make_tools(tmp_path)
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "What is your password?"}, SimpleNamespace())
    assert result.error == "QUESTION_NOT_ALLOWED"
    assert not channel.questions


async def test_ask_caller_no_handler_fails_closed(tmp_path, monkeypatch):
    tools, _policy, _, _ = make_tools(tmp_path, FakeQuestionChannel(error="QUESTION_HANDLER_REQUIRED"))
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Which one?"}, SimpleNamespace())
    assert result.error == "QUESTION_HANDLER_REQUIRED"


async def test_ask_caller_denied_after_uncertain_mutation(tmp_path, monkeypatch):
    from brocode.policy import PolicyBlocked

    tools, _policy, _, channel = make_tools(tmp_path)
    with pytest.raises(PolicyBlocked):
        tools.uncertain()
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Which one?"}, SimpleNamespace())
    assert result.error == "UNCERTAIN_MUTATION"
    assert not channel.questions


# --- ACP question handler ---


def _agent():
    from brocode.adapters.acp import BrocodeAgent
    return BrocodeAgent(SimpleNamespace(), model="m")


async def test_acp_question_without_elicitation_is_explicitly_unsupported():
    agent = _agent()
    agent.connection = SimpleNamespace()  # no create_elicitation
    agent._client_caps = SimpleNamespace(elicitation=None)
    handler = agent._question_handler("session", "tool")
    with pytest.raises(QuestionError) as excinfo:
        await handler(QuestionRequest(question="Which filter?"))
    assert excinfo.value.code == "QUESTION_ACP_UNSUPPORTED"


async def test_acp_question_accept_returns_bounded_answer():
    agent = _agent()

    async def create_elicitation(message, mode):
        assert message == "Which filter?"
        assert mode.session_id == "session" and mode.tool_call_id == "tool"
        return SimpleNamespace(action="accept", content={"answer": "  newest  "})

    agent.connection = SimpleNamespace(create_elicitation=create_elicitation)
    agent._client_caps = SimpleNamespace(elicitation=SimpleNamespace(form=SimpleNamespace()))
    handler = agent._question_handler("session", "tool")
    assert await handler(QuestionRequest(question="Which filter?")) == "newest"


async def test_acp_question_decline_and_cancel_map_to_codes():
    from brocode.adapters.acp import BrocodeAgent  # noqa: F401  (import surface check)

    for action, code in (("decline", "QUESTION_DECLINED"), ("cancel", "QUESTION_CANCELLED")):
        agent = _agent()

        async def create_elicitation(message, mode, _action=action):
            return SimpleNamespace(action=_action, content={})

        agent.connection = SimpleNamespace(create_elicitation=create_elicitation)
        agent._client_caps = SimpleNamespace(elicitation=SimpleNamespace(form=SimpleNamespace()))
        with pytest.raises(QuestionError) as excinfo:
            await agent._question_handler("session", "tool")(
                QuestionRequest(question="Proceed?"))
        assert excinfo.value.code == code


# --- review regressions: secret choices, ACP choices, finalization latching ---


@pytest.mark.parametrize("probe", [
    "What is your password?",
    "Share your api key",
    "Enter the auth token",
    "paste your seed phrase here",
])
def test_question_schema_rejects_secret_markers_in_choices(probe):
    with pytest.raises(ValidationError, match="secret"):
        QuestionRequest(question="Which option?", choices=[probe])
    # Parent IPC validation uses the same schema, so the wire payload rejects too.
    with pytest.raises(ValidationError, match="secret"):
        QuestionRequest.model_validate({
            "question": "Which option?",
            "choices": ["ok", probe],
            "timeout_seconds": 120,
            "question_id": "00000000-0000-0000-0000-000000000000",
        })


def test_ask_caller_params_reject_secret_markers_in_choices():
    from brocode.worker import AskCallerParams

    with pytest.raises(ValidationError, match="secret"):
        AskCallerParams(question="Pick?", choices=["your password please"])


async def test_ask_caller_rejects_secret_choice_without_calling_caller(tmp_path, monkeypatch):
    tools, _policy, _, channel = make_tools(tmp_path)
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Pick?", "choices": ["your password please"]},
        SimpleNamespace())
    assert result.error == "QUESTION_NOT_ALLOWED"
    assert not channel.questions


async def test_acp_question_preserves_choices_in_schema_and_message():
    from acp.schema import AcceptElicitationResponse  # noqa: F401 (real SDK surface check)

    agent = _agent()
    seen = {}

    async def create_elicitation(message, mode):
        seen["message"] = message
        seen["schema"] = mode.requested_schema
        return SimpleNamespace(action="accept", content={"answer": "b"})

    agent.connection = SimpleNamespace(create_elicitation=create_elicitation)
    agent._client_caps = SimpleNamespace(elicitation=SimpleNamespace(form=SimpleNamespace()))
    handler = agent._question_handler("session", "tool")
    assert await handler(QuestionRequest(question="Pick?", choices=["a", "b"])) == "b"
    assert "a" in seen["message"] and "b" in seen["message"] and "Pick?" in seen["message"]
    answer_schema = seen["schema"].properties["answer"]
    assert answer_schema.enum == ["a", "b"]


async def test_ask_caller_failure_latches_outcome_and_policy(tmp_path, monkeypatch):
    tools, policy, _, _ = make_tools(tmp_path, FakeQuestionChannel(error="QUESTION_TIMEOUT"))
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Which one?"}, SimpleNamespace())
    assert result.error == "QUESTION_TIMEOUT"
    assert policy.error_code == "QUESTION_TIMEOUT"
    assert tools.outcome.error_code == "QUESTION_TIMEOUT"


async def test_ask_caller_failure_never_downgrades_uncertain(tmp_path, monkeypatch):
    from brocode.policy import PolicyBlocked

    tools, _, _, _ = make_tools(tmp_path, FakeQuestionChannel(error="QUESTION_TIMEOUT"))
    with pytest.raises(PolicyBlocked):
        tools.uncertain()
    await _in_scope(monkeypatch)
    result = await tools.registry.execute_action(
        "ask_caller", {"question": "Which one?"}, SimpleNamespace())
    assert result.error == "UNCERTAIN_MUTATION"
    assert tools.outcome.error_code == "UNCERTAIN_MUTATION"


async def test_run_browser_preserves_question_wire_error_not_verification(tmp_path, monkeypatch):
    """Synthetic run_browser finalization: question failure survives, not VERIFICATION_NOT_COMPLETED."""
    import browser_use
    from browser_use import llm

    from brocode.infra import browser as infra_browser

    run_dir, profile = tmp_path / "run", tmp_path / "profile"
    run_dir.mkdir()
    profile.mkdir()
    # Resolve lazy Agent annotations while Browser is still the real class.
    assert browser_use.Agent is not None
    captured: dict = {}
    RealCls = worker.guarded_tools_class()

    class CapturingCls(RealCls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["tools"] = self

    monkeypatch.setattr(worker, "guarded_tools_class", lambda: CapturingCls)
    monkeypatch.setattr(worker, "page_identity",
                        lambda browser: asyncio.sleep(0, result={"url": "https://example.com", "title": "t"}))
    monkeypatch.setattr(worker, "sanitize_environment", lambda: None)
    monkeypatch.setattr(worker, "capture_screenshot", AsyncMock())

    class FailingChannel:
        closed = False

        async def event(self, *args, **kwargs):
            return None

        async def approve(self, approval):
            return False

        async def ask(self, question, timeout):
            raise QuestionError("QUESTION_TIMEOUT", "Caller did not answer in time")

    class AskingAgent:
        def __init__(self, **kwargs):
            captured["agent_kwargs"] = kwargs
            self.multi_act = AsyncMock()

        async def run(self, **kwargs):
            tools = captured["tools"]
            result = await tools.registry.execute_action(
                "ask_caller", {"question": "Which filter?"}, SimpleNamespace())
            assert result.error == "QUESTION_TIMEOUT"
            assert tools.outcome.error_code == "QUESTION_TIMEOUT"
            assert tools.policy.error_code == "QUESTION_TIMEOUT"
            return SimpleNamespace(usage=None)

    def browser_factory(**kwargs):
        return SimpleNamespace(kill=AsyncMock())

    monkeypatch.setattr(browser_use, "Browser", browser_factory)
    monkeypatch.setattr(browser_use, "Agent", AskingAgent)
    monkeypatch.setattr(llm, "ChatOpenAI", lambda **kwargs: None)
    monkeypatch.setattr(infra_browser, "browser_kwargs", lambda **kwargs: {})
    monkeypatch.setattr(infra_browser, "cleanup_owned_processes", AsyncMock())
    monkeypatch.setenv("BROCODE_WORKER_API_KEY", "transient-key")
    monkeypatch.chdir(tmp_path)
    import tempfile
    old_tmp = tempfile.tempdir
    try:
        outcome = await worker.run_browser(
            {"request": {"goal": "read", "policy": {"allowed_domains": ["example.com"]}},
             "run_dir": str(run_dir), "profile_dir": str(profile),
             "model": "test-model", "base_url": "https://api.example.test/v1",
             "proxy_url": "http://127.0.0.1:1088", "egress_mode": "warp"},
            FailingChannel(),
        )
    finally:
        tempfile.tempdir = old_tmp
    assert outcome.error_code == "QUESTION_TIMEOUT"
    assert outcome.error_code != "VERIFICATION_NOT_COMPLETED"
    assert not outcome.checks_passed


async def test_run_browser_uncertain_stays_sticky_over_question_failure(tmp_path, monkeypatch):
    """Synthetic finalization: UNCERTAIN_MUTATION outranks a later question failure."""
    import browser_use
    from browser_use import llm

    from brocode.infra import browser as infra_browser

    run_dir, profile = tmp_path / "run2", tmp_path / "profile2"
    run_dir.mkdir()
    profile.mkdir()
    # Resolve lazy Agent annotations while Browser is still the real class.
    assert browser_use.Agent is not None
    captured: dict = {}
    RealCls = worker.guarded_tools_class()

    class CapturingCls(RealCls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["tools"] = self

    monkeypatch.setattr(worker, "guarded_tools_class", lambda: CapturingCls)
    monkeypatch.setattr(worker, "page_identity",
                        lambda browser: asyncio.sleep(0, result={"url": "https://example.com", "title": "t"}))
    monkeypatch.setattr(worker, "sanitize_environment", lambda: None)
    monkeypatch.setattr(worker, "capture_screenshot", AsyncMock())

    class FailingChannel:
        closed = False

        async def event(self, *args, **kwargs):
            return None

        async def approve(self, approval):
            return False

        async def ask(self, question, timeout):
            raise QuestionError("QUESTION_TIMEOUT", "Caller did not answer in time")

    class UncertainAgent:
        def __init__(self, **kwargs):
            self.multi_act = AsyncMock()

        async def run(self, **kwargs):
            from brocode.policy import PolicyBlocked

            tools = captured["tools"]
            with pytest.raises(PolicyBlocked):
                tools.uncertain()
            result = await tools.registry.execute_action(
                "ask_caller", {"question": "Which?"}, SimpleNamespace())
            assert result.error == "UNCERTAIN_MUTATION"
            return SimpleNamespace(usage=None)

    monkeypatch.setattr(browser_use, "Browser", lambda **kwargs: SimpleNamespace(kill=AsyncMock()))
    monkeypatch.setattr(browser_use, "Agent", UncertainAgent)
    monkeypatch.setattr(llm, "ChatOpenAI", lambda **kwargs: None)
    monkeypatch.setattr(infra_browser, "browser_kwargs", lambda **kwargs: {})
    monkeypatch.setattr(infra_browser, "cleanup_owned_processes", AsyncMock())
    monkeypatch.setenv("BROCODE_WORKER_API_KEY", "transient-key")
    monkeypatch.chdir(tmp_path)
    import tempfile
    old_tmp = tempfile.tempdir
    try:
        outcome = await worker.run_browser(
            {"request": {"goal": "read", "policy": {"allowed_domains": ["example.com"]}},
             "run_dir": str(run_dir), "profile_dir": str(profile),
             "model": "test-model", "base_url": "https://api.example.test/v1",
             "proxy_url": "http://127.0.0.1:1088", "egress_mode": "warp"},
            FailingChannel(),
        )
    finally:
        tempfile.tempdir = old_tmp
    assert outcome.error_code == "UNCERTAIN_MUTATION"
