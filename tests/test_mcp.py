"""Real MCP 2.1.1 stdio clients; all task execution uses an injected fake runtime."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from test_acp import child_env

MCP_CHILD = """
from brocode.adapters.mcp import create_server
# Runtime construction happens in server lifespan after SDK stdio takes ownership.
class LazyRuntime:
    def __init__(self): self.instance = None
    def __getattr__(self, name):
        if self.instance is None:
            from test_acp import FakeRuntime
            self.instance = FakeRuntime()
        return getattr(self.instance, name)
create_server(LazyRuntime()).run(transport='stdio')
"""


def parameters(tmp_path):
    return StdioServerParameters(command=sys.executable, args=["-c", MCP_CHILD],
                                 env=child_env(tmp_path), cwd=tmp_path)


def payload(result):
    assert not result.is_error, result
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_stdio_tools_background_results_validation_and_shutdown(tmp_path):
    async with stdio_client(parameters(tmp_path)) as (reader, writer):  # noqa: SIM117
        async with ClientSession(reader, writer) as client:
            initialized = await client.initialize()
            assert initialized.server_info.name == "Brocode"
            listed = await client.list_tools()
            tools = {tool.name: tool for tool in listed.tools}
            assert set(tools) == {"task_start", "task_status", "task_result", "task_cancel",
                                  "playbooks_list", "playbook_inspect", "upload_register"}
            assert "request" in tools["task_start"].input_schema["properties"]
            missing = await client.call_tool("task_start", {"request": {"goal": "read"}})
            assert missing.is_error
            invalid = await client.call_tool("task_start", {"request": {"goal": "read", "extra": True}})
            assert invalid.is_error
            for tool in ("task_status", "task_result", "task_cancel"):
                assert (await client.call_tool(tool, {"run_id": "missing"})).is_error
            request = {"goal": "delayed work", "policy": {"mode": "confirm", "allowed_domains": ["example.com"]}}
            started = payload(await client.call_tool("task_start", {"request": request}))
            run_id = started["run_id"]
            result = None
            for _ in range(30):
                result = payload(await client.call_tool("task_result", {"run_id": run_id}))
                if result["status"] == "blocked":
                    break
                await asyncio.sleep(0.02)
            assert result["status"] == "blocked"
            assert result["error_code"] == "POLICY_DENIED"
            assert result["data"]["request"]["caller_id"] == "mcp"
            status = payload(await client.call_tool("task_status", {"run_id": run_id}))
            assert status["terminal"] is True
            assert status["verification"] == "not_requested"
            assert payload(await client.call_tool("task_cancel", {"run_id": run_id}))["cancelled"] is False
            assert (await client.call_tool("playbooks_list")).is_error is False
            assert payload(await client.call_tool("playbook_inspect", {"playbook_id": "demo"}))["id"] == "demo"
            assert (await client.call_tool("playbook_inspect", {"playbook_id": "missing"})).is_error
            assert payload(await client.call_tool("upload_register", {"path": "/approved/resume.pdf"}))["handle"]
            assert (await client.call_tool("upload_register", {"path": "/forbidden/file"})).is_error
            started = payload(await client.call_tool("task_start", {
                "request": {"goal": "wait", "policy": {"allowed_domains": ["example.com"]}}
            }))
            run_id = started["run_id"]
            assert payload(await client.call_tool("task_cancel", {"run_id": run_id}))["cancelled"] is True
            assert payload(await client.call_tool("task_status", {"run_id": run_id}))["status"] == "cancelled"
            # Leave one background job active. EOF must cancel it through lifespan cleanup.
            await client.call_tool("task_start", {
                "request": {"goal": "wait", "policy": {"allowed_domains": ["example.com"]}}
            })
    assert Path(tmp_path / "shutdown").read_text() == "shutdown"
