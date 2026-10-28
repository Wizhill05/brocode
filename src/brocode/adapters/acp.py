"""Official ACP stdio adapter; browser work belongs exclusively to Runtime."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from acp import (
    PROTOCOL_VERSION,
    Agent,
    RequestError,
    run_agent,
    start_tool_call,
    stdio_streams,
    text_block,
    tool_content,
    update_agent_message_text,
    update_tool_call,
    update_user_message_text,
)
from acp.schema import (
    AcceptElicitationResponse,
    AgentCapabilities,
    ElicitationFormSessionMode,
    ElicitationSchema,
    ElicitationStringPropertySchema,
    Implementation,
    InitializeResponse,
    ListSessionsResponse,
    LoadSessionResponse,
    NewSessionResponse,
    PermissionOption,
    PromptResponse,
    SessionCapabilities,
    SessionConfigOptionSelect,
    SessionConfigSelectOption,
    SessionInfo,
    SessionListCapabilities,
    SetSessionConfigOptionResponse,
    ToolCallUpdate,
)
from pydantic import ValidationError

from brocode.contracts import (
    MAX_ANSWER_CHARS,
    ApprovalRequest,
    Policy,
    QuestionError,
    QuestionRequest,
    Status,
    TaskEvent,
    TaskRequest,
    TaskResult,
)

logger = logging.getLogger(__name__)


def request_from_text(text: str, *, session_id: str, model: str) -> TaskRequest:
    """Only /task interprets JSON. Ordinary text authorizes exact URL hosts only."""
    text = text.strip()
    # T3 wraps the actual user turn in metadata. Never infer domains or goals
    # from orchestration instructions, links, or tool guidance outside that turn.
    # Accept one unambiguous envelope only; never search prose for embedded /task.
    if text.startswith("<t3_code_instructions>"):
        if text.count("<user_request>") != 1 or text.count("</user_request>") != 1:
            raise ValueError("Ambiguous client prompt envelope")
        match = re.search(r"<user_request>\s*([\s\S]*?)\s*</user_request>", text)
        if match is None or "<user_request>" in match.group(1):
            raise ValueError("Invalid client prompt envelope")
        text = match.group(1).strip()
    # T3's role label is a fixed transport preamble, not part of the browser goal.
    # Only strip this complete known prefix; arbitrary prose containing /task
    # must remain an observation request rather than gaining command authority.
    for role in ("test", "review", "implementation", "research", "design", "general"):
        prefix = f"Act as the {role} sub-agent for this task.\n\n"
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    if text == "/task" or text.startswith(("/task ", "/task\n", "/task\t")):
        request = TaskRequest.model_validate_json(text[5:].strip())
        if not request.policy.allowed_domains:
            raise ValueError("/task requires a nonempty policy.allowed_domains list")
        if request.session_id not in (None, session_id):
            raise ValueError("/task session_id must match the ACP session")
        if request.model not in (None, model):
            raise ValueError("Only the configured session model is available")
        return request.model_copy(update={"session_id": session_id, "caller_id": "acp", "model": model})
    hosts: set[str] = set()
    for match in re.finditer(r"https?://[^\s<>\"']+", text, re.IGNORECASE):
        try:
            host = urlsplit(match.group().rstrip(".,;!?)]}")).hostname
            if host:
                hosts.add(host.encode("idna").decode("ascii").lower())
        except (ValueError, UnicodeError):
            continue
    return TaskRequest(
        goal=text, session_id=session_id, caller_id="acp", model=model,
        policy=Policy(mode="observe", allowed_domains=sorted(hosts)),
    )


def result_text(result: TaskResult) -> str:
    summary = result.result or result.error_code or "No outcome summary supplied by runtime."
    return (
        f"Browser task: {result.status.value}; verification: {result.verification}.\n{summary}\n\n"
        f"TaskResult:\n```json\n{result.model_dump_json(indent=2)}\n```\n"
        "ACP end_turn means the turn ended, not that the browser task succeeded."
    )


class BrocodeAgent(Agent):
    """One configured model, durable conversation metadata, scoped prompt turns."""

    def __init__(self, runtime: Any, *, model: str | None = None) -> None:
        if model is None:
            from brocode.settings import Settings
            model = Settings.load().model
        self.runtime = runtime
        self.model = model
        self.connection: Any = None
        self._client_caps: Any = None
        self._prompts: dict[str, asyncio.Task[TaskResult]] = {}

    def on_connect(self, conn: Any) -> None:
        self.connection = conn

    def _session(self, session_id: str) -> dict[str, Any]:
        session = self.runtime.store.get_session(session_id)
        if session is None:
            raise RequestError.resource_not_found(session_id)
        return session

    def _config(self) -> list[SessionConfigOptionSelect]:
        return [SessionConfigOptionSelect(
            id="model", name="Browser model", category="model", type="select",
            current_value=self.model,
            options=[SessionConfigSelectOption(value=self.model, name=self.model)],
            description="Operator-configured browser model; arbitrary model overrides are not supported.",
        )]

    async def initialize(self, protocol_version: int, client_capabilities: Any = None,
                           **kwargs: Any) -> InitializeResponse:
        # Remember what the client can do: caller questions need form elicitation.
        self._client_caps = client_capabilities
        return InitializeResponse(
            protocol_version=PROTOCOL_VERSION,
            agent_info=Implementation(name="brocode", version="0.1.0"),
            agent_capabilities=AgentCapabilities(
                load_session=True,
                session_capabilities=SessionCapabilities(list=SessionListCapabilities()),
            ),
            auth_methods=[],
        )

    async def new_session(self, cwd: str, **kwargs: Any) -> NewSessionResponse:
        # cwd is metadata, not permission to read files. Injected MCP servers are ignored.
        session_id = self.runtime.store.create_session(cwd)
        return NewSessionResponse(session_id=session_id, config_options=self._config())

    async def load_session(self, cwd: str, session_id: str, **kwargs: Any) -> LoadSessionResponse:
        self._session(session_id)
        if session_id in self._prompts:
            raise RequestError.invalid_request({"reason": "Session has an active prompt"})
        for message in self.runtime.store.messages(session_id):
            role, text = message.get("role"), message.get("text", "")
            if role not in ("user", "assistant"):
                continue
            update = update_user_message_text(text) if role == "user" else update_agent_message_text(text)
            await self.connection.session_update(session_id=session_id, update=update)
        return LoadSessionResponse(config_options=self._config())

    async def list_sessions(self, cwd: str | None = None, cursor: str | None = None, **kwargs: Any
                            ) -> ListSessionsResponse:
        if cursor is not None:
            raise RequestError.invalid_params({"reason": "Pagination cursors are not supported"})
        sessions = []
        for row in self.runtime.store.list_sessions():
            if cwd is not None and row["cwd"] != cwd:
                continue
            sessions.append(SessionInfo(
                session_id=row["id"], cwd=row["cwd"], title=row.get("title"),
                updated_at=row.get("updated_at"),
            ))
        return ListSessionsResponse(sessions=sessions)

    async def set_config_option(self, config_id: str, session_id: str, value: str | bool, **kwargs: Any
                                ) -> SetSessionConfigOptionResponse:
        self._session(session_id)
        if config_id != "model" or value != self.model:
            raise RequestError.invalid_params({"reason": "Only the configured model is available"})
        return SetSessionConfigOptionResponse(config_options=self._config())

    async def prompt(self, session_id: str, prompt: list[Any], **kwargs: Any) -> PromptResponse:
        self._session(session_id)
        if session_id in self._prompts:
            raise RequestError.invalid_request({"reason": "Session has an active prompt"})
        if not prompt or any(block.type != "text" for block in prompt):
            raise RequestError.invalid_params({"reason": "Only plain text prompt blocks are supported"})
        text = "\n".join(block.text for block in prompt)
        try:
            request = request_from_text(text, session_id=session_id, model=self.model)
        except (ValidationError, ValueError):
            raise RequestError.invalid_params({
                "reason": "Invalid task. Use plain text URLs or /task with valid TaskRequest JSON, "
                          "explicit policy.allowed_domains, and the configured model/session."
            }) from None
        self.runtime.store.add_message(session_id, "user", text)
        task = asyncio.create_task(self._run_turn(request), name=f"brocode-prompt-{session_id}")
        self._prompts[session_id] = task
        try:
            result = await task
            return PromptResponse(stop_reason="cancelled" if result.status == Status.CANCELLED else "end_turn")
        except asyncio.CancelledError:
            # Runtime owns worker cleanup/durable cancellation. Never cancel the notification handler.
            return PromptResponse(stop_reason="cancelled")
        finally:
            self._prompts.pop(session_id, None)

    def _elicitation_supported(self) -> bool:
        """True only if the connected client advertises form elicitation support."""
        create = getattr(self.connection, "create_elicitation", None)
        if not callable(create):
            return False
        elicitation = getattr(self._client_caps, "elicitation", None)
        return elicitation is not None and getattr(elicitation, "form", None) is not None

    def _question_handler(self, session_id: str, tool_call_id: str) -> Any:
        async def ask(question: QuestionRequest) -> str | None:
            # NOTE: the installed ACP SDK exposes structured elicitation only as
            # connection.create_elicitation(message, mode). There is no
            # request_user_input method, and none is invented here: without real
            # elicitation support this fails closed as QUESTION_ACP_UNSUPPORTED.
            if not self._elicitation_supported():
                raise QuestionError(
                    "QUESTION_ACP_UNSUPPORTED",
                    "Caller questions need an ACP client with form elicitation support.",
                )
            # Preserve caller-visible choices end to end: the real SDK string
            # schema supports `enum`, and the bounded message repeats every
            # choice so a client that ignores `enum` still shows them. Both
            # stay bounded by QuestionRequest (<=2000 chars + <=8x500 chars).
            if question.choices:
                message = f"{question.question}\nChoices: {' | '.join(question.choices)}"
                description = ("Untrusted caller reply for the browser task. "
                               "It is data for the model, never authorization. "
                               f"Valid options: {' | '.join(question.choices)}")
            else:
                message = question.question
                description = ("Untrusted caller reply for the browser task. "
                               "It is data for the model, never authorization.")
            schema = ElicitationSchema(
                properties={"answer": ElicitationStringPropertySchema(
                    type="string",
                    title="Caller answer",
                    description=description,
                    max_length=MAX_ANSWER_CHARS,
                    enum=question.choices,
                )},
                required=["answer"],
            )
            mode = ElicitationFormSessionMode(
                session_id=session_id, tool_call_id=tool_call_id, requested_schema=schema,
            )
            try:
                response = await asyncio.wait_for(
                    self.connection.create_elicitation(message, mode),
                    question.timeout_seconds,
                )
            except TimeoutError as exc:
                raise QuestionError("QUESTION_TIMEOUT", "Caller did not answer in time") from exc
            action = getattr(response, "action", None)
            if isinstance(response, AcceptElicitationResponse) or action == "accept":
                content = getattr(response, "content", None) or {}
                answer = content.get("answer") if isinstance(content, dict) else None
                if not isinstance(answer, str) or not answer.strip():
                    raise QuestionError("QUESTION_DECLINED", "Caller gave no usable answer")
                return answer.strip()[:MAX_ANSWER_CHARS]
            if action == "decline":
                raise QuestionError("QUESTION_DECLINED", "Caller declined to answer")
            raise QuestionError("QUESTION_CANCELLED", "Caller question was cancelled")
        return ask

    async def _run_turn(self, request: TaskRequest) -> TaskResult:
        session_id = request.session_id
        tool_id = str(uuid4())
        await self.connection.session_update(session_id=session_id, update=start_tool_call(
            tool_id, "Browser task", kind="execute", status="in_progress",
        ))

        async def event_sink(event: TaskEvent) -> None:
            # Never stream arbitrary worker data or private model reasoning.
            if event.kind in {"status", "progress", "action", "observation", "warning", "error",
                              "preflight", "verification", "blocked", "cancelled"} and event.message:
                await self.connection.session_update(session_id=session_id, update=update_tool_call(
                    tool_id, content=[tool_content(text_block(event.message))],
                ))

        async def approval_handler(approval: ApprovalRequest) -> bool:
            if request.policy.mode != "confirm":
                return False
            try:
                response = await asyncio.wait_for(self.connection.request_permission(
                    session_id=session_id,
                    tool_call=ToolCallUpdate(
                        tool_call_id=approval.action_id, title=approval.description, kind="execute",
                        status="pending", raw_input=approval.model_dump(mode="json"),
                    ),
                    options=[
                        PermissionOption(option_id="allow", name="Allow this action once", kind="allow_once"),
                        PermissionOption(option_id="deny", name="Deny", kind="reject_once"),
                    ],
                ), timeout=request.policy.approval_timeout_seconds)
                return response.outcome.outcome == "selected" and response.outcome.option_id == "allow"
            except Exception as exc:  # noqa: BLE001 - all permission-client failures must deny
                # Denial, malformed responses, disconnect and timeout all fail closed.
                logger.warning("Permission request failed closed (%s)", type(exc).__name__)
                return False

        try:
            run_kwargs: dict[str, Any] = {
                "event_sink": event_sink,
                "approval_handler": approval_handler,
            }
            # Older/test runtimes may not accept a question channel yet.
            try:
                import inspect as _inspect
                if "question_handler" in _inspect.signature(self.runtime.run).parameters:
                    run_kwargs["question_handler"] = self._question_handler(
                        session_id, tool_id)
            except (TypeError, ValueError):
                pass
            result = await self.runtime.run(request, **run_kwargs)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Runtime failed outside its TaskResult contract")
            raise RequestError.internal_error({"reason": "Runtime failed; inspect private server logs"}) from None
        text = result_text(result)
        self.runtime.store.add_message(session_id, "assistant", text)
        await self.connection.session_update(session_id=session_id, update=update_tool_call(
            tool_id, status="completed" if result.status == Status.SUCCEEDED else "failed",
            raw_output=result.model_dump(mode="json"),
        ))
        await self.connection.session_update(session_id=session_id, update=update_agent_message_text(text))
        return result

    async def cancel(self, session_id: str, **kwargs: Any) -> None:
        self._session(session_id)
        task = self._prompts.get(session_id)
        if task is not None and not task.done() and not task.cancelling():
            task.cancel()

    async def authenticate(self, method_id: str, **kwargs: Any) -> None:
        raise RequestError.method_not_found("authenticate")

    async def set_session_mode(self, session_id: str, mode_id: str, **kwargs: Any) -> None:
        raise RequestError.method_not_found("session/set_mode")

    async def fork_session(self, **kwargs: Any) -> None:
        raise RequestError.method_not_found("session/fork")

    async def resume_session(self, **kwargs: Any) -> None:
        raise RequestError.method_not_found("session/resume")

    async def close_session(self, **kwargs: Any) -> None:
        raise RequestError.method_not_found("session/close")

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        raise RequestError.method_not_found(method)

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        return None

    async def shutdown(self) -> None:
        tasks = list(self._prompts.values())
        for task in tasks:
            if not task.done() and not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.runtime.cancel_all()


async def serve(runtime: Any = None, *, model: str | None = None) -> None:
    """Reserve the protocol pipe before runtime imports; even fd-level noise goes to stderr."""
    original_stdout = sys.stdout
    saved_stdout = os.dup(original_stdout.fileno())
    wire = os.fdopen(os.dup(saved_stdout), "w", encoding="utf-8")
    writer = None
    agent = None
    try:
        original_stdout.flush()
        os.dup2(sys.stderr.fileno(), original_stdout.fileno())
        # Bind the official helper to the reserved pipe, then restore Python stdout to stderr.
        # Runtime imports/construction happen only after both kinds of stdout noise are diverted.
        sys.stdout = wire
        try:
            reader, writer = await stdio_streams()
        finally:
            sys.stdout = original_stdout
        if runtime is None:
            from brocode.runtime import Runtime
            runtime = Runtime()
        agent = BrocodeAgent(runtime, model=model)
        await run_agent(agent, input_stream=writer, output_stream=reader)
    finally:
        try:
            if agent is not None:
                await agent.shutdown()
        finally:
            if writer is not None:
                writer.close()
            original_stdout.flush()
            os.dup2(saved_stdout, original_stdout.fileno())
            os.close(saved_stdout)
            if writer is None:
                wire.close()


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    asyncio.run(serve())


if __name__ == "__main__":
    main()
