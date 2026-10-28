"""Tool-facing stdio adapter for mcp 2.1.1 (FastMCP was renamed MCPServer)."""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from brocode.contracts import TERMINAL, ApprovalRequest, TaskRequest


def create_server(runtime: Any = None) -> MCPServer:
    """Create a server without starting workers or importing browser dependencies."""
    state: dict[str, Any] = {}

    @asynccontextmanager
    async def lifespan(server: MCPServer):
        nonlocal runtime
        if runtime is None:
            from brocode.runtime import Runtime
            runtime = Runtime()
        state["runtime"] = runtime
        try:
            yield state
        finally:
            # The server's request cancellation scope may already be cancelled on EOF.
            with anyio.CancelScope(shield=True):
                await runtime.cancel_all()
            state.clear()

    server = MCPServer(
        "Brocode", version="0.1.0", lifespan=lifespan,
        instructions=("Browser specialist. Start a scoped TaskRequest, then poll task_status/task_result. "
                      "This transport never approves mutations. No selectors, shell or arbitrary MCP servers."),
    )

    def active_runtime() -> Any:
        if "runtime" not in state:
            raise ToolError("Server lifespan is not active")
        return state["runtime"]

    def lookup(run_id: str):
        result = active_runtime().store.get(run_id)
        if result is None:
            raise ToolError("Unknown run_id")
        return result

    async def deny_approval(approval: ApprovalRequest) -> bool:
        return False

    @server.tool()
    async def task_start(request: TaskRequest) -> dict[str, Any]:
        """Start background browser work. Explicit nonempty policy.allowed_domains is required.

        Observe is the default. Confirm-mode requests still cannot gain approval over MCP.
        Registered upload handles, not arbitrary filesystem paths, belong in the request.
        """
        if not request.policy.allowed_domains:
            raise ToolError("task_start requires a nonempty policy.allowed_domains list")
        request = request.model_copy(update={"caller_id": "mcp"})
        try:
            run_id = await active_runtime().start(request, approval_handler=deny_approval)
        except (ValueError, KeyError) as exc:
            raise ToolError("Task request rejected by runtime; check request identity and policy") from exc
        return {"run_id": run_id}

    @server.tool()
    async def task_status(run_id: str) -> dict[str, Any]:
        """Get durable task status; a protocol response is not proof of browser success."""
        result = lookup(run_id)
        return {
            "run_id": result.run_id, "status": result.status.value,
            "terminal": result.status in TERMINAL, "verification": result.verification,
            "error_code": result.error_code, "updated_at": result.updated_at,
        }

    @server.tool()
    async def task_cancel(run_id: str) -> dict[str, Any]:
        """Ask the shared runtime to cancel this run and clean up its owned worker."""
        lookup(run_id)
        return {"run_id": run_id, "cancelled": await active_runtime().cancel(run_id)}

    @server.tool()
    async def task_result(run_id: str) -> dict[str, Any]:
        """Read the full TaskResult, including verification, evidence and error fields."""
        return lookup(run_id).model_dump(mode="json")

    @server.tool()
    async def playbooks_list() -> list[dict[str, Any]]:
        """List procedural memory; saved playbooks grant no task authority."""
        return active_runtime().memory.list()

    @server.tool()
    async def playbook_inspect(playbook_id: str) -> dict[str, Any]:
        """Inspect a playbook by ID, not an arbitrary file path."""
        try:
            return active_runtime().memory.inspect(playbook_id)
        except (ValueError, KeyError, OSError) as exc:
            raise ToolError("Playbook not found or rejected by memory validation") from exc

    @server.tool()
    async def upload_register(path: str) -> dict[str, Any]:
        """Register a caller-selected absolute local file through store path/symlink checks.

        Registration is not permission to upload. Pass the returned handle in a scoped task.
        """
        try:
            return active_runtime().store.register_upload(path)
        except (ValueError, KeyError, OSError) as exc:
            raise ToolError("Upload registration rejected; provide an allowed absolute regular file") from exc

    @server.tool()
    async def controller_list() -> list[dict[str, Any]]:
        """List bounded read-only controller helpers (relay status, capability and challenge reports)."""
        from brocode.controller_tools import list_tools
        return list_tools()

    @server.tool()
    async def controller_run(name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one allowlisted read-only controller tool by name.

        Unknown names and non-object args are rejected. These tools never launch a
        browser, approve actions, or solve challenges; they only report.
        """
        from brocode.controller_tools import run_tool
        try:
            return run_tool(active_runtime(), name, args or {})
        except (ValueError, KeyError) as exc:
            raise ToolError(str(exc)) from exc

    return server


def serve(runtime: Any = None) -> None:
    """Blocking entrypoint for the package CLI; SDK owns the event loop and stdio."""
    # SDK 2.1.1 claims stdout before entering lifespan, redirecting stray fd-level output to stderr.
    create_server(runtime).run(transport="stdio")


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    serve()


if __name__ == "__main__":
    main()
