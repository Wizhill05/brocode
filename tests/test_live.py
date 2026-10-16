"""Opt-in harmless browser acceptance tests; never enabled in CI.

Uses only the shared Runtime. Doctor and the exclusive profile lease are not
mocked. Results/evidence stay in the configured private state directory.
"""
import asyncio
import os

import pytest

from brocode.contracts import Budget, Policy, Status, TaskRequest, VerificationCheck
from brocode.infra.preflight import preflight
from brocode.runtime import ProfileLease, Runtime

pytestmark = pytest.mark.skipif(
    os.environ.get("BROCODE_LIVE_TESTS") != "1", reason="Explicit live browser opt-in required"
)


async def checked_runtime():
    runtime = Runtime()
    checks = await preflight(runtime.settings)
    assert all(check["ok"] for check in checks), [c["name"] for c in checks if not c["ok"]]
    return runtime


async def test_live_verified_observation():
    runtime = await checked_runtime()
    try:
        result = await runtime.run(TaskRequest(
            goal="Read https://example.com and report the page title. Do not interact with any controls.",
            policy=Policy(allowed_domains=["example.com"]),
            verification=[VerificationCheck(kind="title_contains", value="Example Domain")],
            budget=Budget(max_steps=8, timeout_seconds=120),
            record=False,
        ))
        assert result.status == Status.SUCCEEDED, result.error_code
        assert result.verification == "passed"
        assert result.steps > 0
        assert any(e.kind == "screenshot" for e in result.evidence)
        assert runtime.store.get(result.run_id).status == Status.SUCCEEDED
        with ProfileLease(runtime.settings.profile_dir):
            pass
    finally:
        await runtime.cancel_all()


async def test_live_acp_verified_observation():
    import json
    import sys

    from acp import PROTOCOL_VERSION, Client, spawn_agent_process, text_block
    from acp.schema import DeniedOutcome, RequestPermissionResponse

    runtime = await checked_runtime()

    class DenyingClient(Client):
        async def session_update(self, session_id, update, **kwargs):
            pass

        async def request_permission(self, **kwargs):
            return RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))

    async with spawn_agent_process(DenyingClient(), sys.executable, "-m", "brocode.adapters.acp",
                                   cwd=runtime.settings.root) as (connection, process):
        await connection.initialize(protocol_version=PROTOCOL_VERSION)
        session = await connection.new_session(cwd=str(runtime.settings.root), mcp_servers=[])
        payload = {"goal": "Read https://example.com and report its title. Do not interact with controls.",
                   "policy": {"mode": "observe", "allowed_domains": ["example.com"]},
                   "verification": [{"kind": "title_contains", "value": "Example Domain"}],
                   "budget": {"max_steps": 8, "timeout_seconds": 120}, "record": False}
        # Exercise the actual client envelope as well as the official SDK wire.
        prompt = ('<t3_code_instructions>Metadata https://outside.example</t3_code_instructions>\n'
                  '<user_request>Act as the test sub-agent for this task.\n\n/task '
                  + json.dumps(payload) + '</user_request>\n'
                  '<pull_request_linking>Not browser authority</pull_request_linking>')
        response = await connection.prompt(session_id=session.session_id,
                                           prompt=[text_block(prompt)])
        assert response.stop_reason == "end_turn"
        transcript = runtime.store.messages(session.session_id)
        final = next(m["text"] for m in reversed(transcript) if m["role"] == "assistant")
        assert '"status": "succeeded"' in final
        assert '"verification": "passed"' in final


async def test_live_cancel_releases_profile():
    runtime = await checked_runtime()
    observed = asyncio.Event()

    async def progress(event):
        if event.kind == "step":
            observed.set()

    try:
        run_id = await runtime.start(TaskRequest(
            goal="Read https://example.com and report its page title. Do not interact with controls.",
            policy=Policy(allowed_domains=["example.com"]),
            budget=Budget(max_steps=8, timeout_seconds=120), record=False,
        ), event_sink=progress)
        await asyncio.wait_for(observed.wait(), 60)
        assert await runtime.cancel(run_id)
        await asyncio.wait_for(runtime.cancel_all(), 30)
        assert runtime.store.get(run_id).status == Status.CANCELLED
        with ProfileLease(runtime.settings.profile_dir):
            pass
        checks = await preflight(runtime.settings)
        assert all(c["ok"] for c in checks), [c["name"] for c in checks if not c["ok"]]
    finally:
        await runtime.cancel_all()
