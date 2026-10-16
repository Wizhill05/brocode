import asyncio
import base64
import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from brocode import worker
from brocode.contracts import ApprovalRequest, Policy, TaskRequest
from brocode.policy import ActionPolicy


class Channel:
    closed = False
    def __init__(self, allow=True):
        self.allow = allow
        self.events = []
        self.approvals = []
    async def event(self, *args, **kwargs):
        self.events.append((args, kwargs))
    async def approve(self, approval):
        self.approvals.append(approval)
        return self.allow


class Browser:
    def __init__(self, url="https://example.com", text="Confirmation received", title="Confirmed"):
        self.url, self.text, self.title = url, text, title
        self.closed = False
        self.form_controls = [{"type": "hidden", "name": "nonce", "value": "synthetic-nonce"}]
        self.destinations = ["https://example.com/submit"]
        self.live_ancestors = []
        self.mutations = []
        self.mutation_response = {"success": True}
        self.agent_focus_target_id = "target"
        self.nodes = {1: SimpleNamespace(tag_name="button", attributes={"type": "submit"}, backend_node_id=42,
                                         parent_node=None, frame_id="frame", session_id="sid")}
        self.evaluate = AsyncMock(side_effect=self._evaluate)
        self.resolve = AsyncMock(return_value={"object": {"objectId": "node"}})
        self.call = AsyncMock(side_effect=self._call)
        self.frame_tree = AsyncMock(return_value={"frameTree": {"frame": {
            "id": "frame", "url": url, "loaderId": "loader"}}})
        self.world = AsyncMock(return_value={"executionContextId": 7})
        self.screenshot = AsyncMock(return_value={"data": base64.b64encode(b"png").decode()})
        self.session = SimpleNamespace(session_id="sid", cdp_client=SimpleNamespace(send=SimpleNamespace(
            Runtime=SimpleNamespace(evaluate=self.evaluate, callFunctionOn=self.call, releaseObject=AsyncMock()),
            DOM=SimpleNamespace(resolveNode=self.resolve), Page=SimpleNamespace(
                captureScreenshot=self.screenshot, getFrameTree=self.frame_tree, createIsolatedWorld=self.world))))
        self.cdp_client = self.session.cdp_client
    async def get_current_page_url(self):
        return self.url
    async def _evaluate(self, params, session_id):
        assert not self.closed, "verification after cleanup is invalid"
        assert params["contextId"] == 7
        return {"result": {"value": {"url": self.url, "title": self.title, "text": self.text}}}
    async def _call(self, params, session_id):
        assert self.resolve.call_args.kwargs["params"]["executionContextId"] == 7
        if "arguments" in params:
            self.mutations.append(params)
            return {"result": {"value": self.mutation_response}}
        attrs = self.nodes[1].attributes
        return {"result": {"value": {"url": self.url, "tag": self.nodes[1].tag_name,
                                      "type": attrs.get("type", ""), "role": attrs.get("role", ""),
                                      "label": "Submit application", "attributes": list(attrs.items()),
                                      "forms": [{"controls": self.form_controls}],
                                      "ancestors": self.live_ancestors,
                                      "activationAncestor": bool(self.live_ancestors),
                                      "destinations": self.destinations + [
                                          a["href"] for a in self.live_ancestors if a.get("href")]}}}
    async def cdp_client_for_node(self, node):
        return self.session
    async def get_or_create_cdp_session(self):
        return self.session
    async def get_selector_map(self):
        return self.nodes


def tools(tmp_path, channel=None, mode="observe", verification=True):
    channel = channel or Channel()
    req = TaskRequest(goal="read", operation_key="op", policy=Policy(mode=mode, allowed_domains=["example.com"]),
                      verification=[{"kind": "page_text_contains", "value": "Confirmation received"}] if verification else [])
    policy = ActionPolicy(req, [], channel.approve)
    return worker.guarded_tools_class()(policy, req, channel, tmp_path), policy, req


@pytest.mark.asyncio
async def test_direct_verification_ignores_model_success(tmp_path):
    t, policy, _req = tools(tmp_path)
    browser = Browser(text="not completed")
    result = await t.registry.execute_action("done", {"text": "Succeeded!", "success": True}, browser)
    assert result.is_done and not result.success
    assert not t.outcome.checks_passed
    assert t.outcome.evidence[0].kind == "screenshot"
    assert (tmp_path / "final.png").is_file()
    browser.closed = True
    assert policy.actions == 1


@pytest.mark.asyncio
async def test_direct_verification_before_cleanup_and_all_checks(tmp_path):
    t, _policy, req = tools(tmp_path)
    from brocode.contracts import VerificationCheck
    req.verification += [VerificationCheck(kind="title_contains", value="Confirmed"),
                         VerificationCheck(kind="url_contains", value="example.com")]
    result = await t.registry.execute_action("done", {"text": "ok", "success": False}, Browser())
    assert result.success
    assert t.outcome.checks_passed
    assert len(t.outcome.data["verification_checks"]) == 3


@pytest.mark.asyncio
async def test_no_declared_checks_never_verified(tmp_path):
    t, _, _ = tools(tmp_path, verification=False)
    result = await t.registry.execute_action("done", {"text": "ok", "success": True}, Browser())
    assert result.is_done and not result.success
    assert not t.outcome.checks_passed


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["evaluate", "shell", "read_file", "write_file", "save_as_pdf", "unknown"])
async def test_direct_registry_dispatch_cannot_bypass_policy(tmp_path, action):
    t, policy, _ = tools(tmp_path)
    assert action not in t.registry.registry.actions
    result = await t.registry.execute_action(action, {}, Browser())
    assert result.is_done and result.error == "ACTION_NOT_ALLOWED"
    assert policy.actions == 0


@pytest.mark.asyncio
async def test_observe_click_and_done_attachments_blocked(tmp_path):
    t, _policy, _ = tools(tmp_path)
    result = await t.registry.execute_action("click", {"index": 1}, Browser())
    assert result.error == "OBSERVE_ONLY"
    t, _, _ = tools(tmp_path)
    result = await t.registry.execute_action("done", {"text": "ok", "files_to_display": ["/etc/passwd"]}, Browser())
    assert result.error == "FILE_ACTION_NOT_ALLOWED"


@pytest.mark.asyncio
async def test_page_redirect_after_approval_blocks_dispatch(tmp_path):
    browser = Browser()
    class MovingChannel(Channel):
        async def approve(self, approval):
            browser.url = "https://evil.test"
            return True
    t, policy, _ = tools(tmp_path, MovingChannel(), "confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "DOMAIN_OUT_OF_SCOPE"
    assert not policy.mutated
    assert policy.actions == 0


@pytest.mark.asyncio
async def test_element_change_after_approval_blocks_dispatch(tmp_path):
    browser = Browser()
    class MovingChannel(Channel):
        async def approve(self, approval):
            browser.nodes[1].attributes["type"] = "button"
            return True
    t, policy, _ = tools(tmp_path, MovingChannel(), "confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "ELEMENT_CHANGED_DURING_APPROVAL"
    assert not policy.mutated


@pytest.mark.asyncio
async def test_action_batch_is_denied(tmp_path):
    t, policy, _ = tools(tmp_path)
    batch = SimpleNamespace(model_dump=lambda **_: {"navigate": {"url": "https://example.com"}, "click": {"index": 1}})
    result = await t.act(batch, Browser())
    assert result.error == "ACTION_BATCH_NOT_ALLOWED"
    assert policy.actions == 0


@pytest.mark.asyncio
async def test_cross_domain_link_and_frame_denied(tmp_path):
    for attrs in ({"href": "https://evil.test"}, {}):
        t, policy, _ = tools(tmp_path, mode="confirm")
        browser = Browser()
        if attrs:
            browser.nodes[1].attributes = attrs
        else:
            browser.nodes[1].parent_node = SimpleNamespace(tag_name="iframe", attributes={"src": "https://evil.test"}, parent_node=None)
        result = await t.registry.execute_action("click", {"index": 1}, browser)
        assert result.error == "DOMAIN_OUT_OF_SCOPE"
        assert not policy.mutated


@pytest.mark.asyncio
async def test_live_ancestor_href_overrides_benign_cached_ancestor(tmp_path):
    browser = Browser()
    browser.nodes[1].tag_name = "span"
    browser.nodes[1].parent_node = SimpleNamespace(tag_name="a", attributes={
        "href": "https://example.com/cached"}, parent_node=None)
    browser.live_ancestors = [{"tag": "a", "href": "https://evil.test/live"}]
    t, policy, _ = tools(tmp_path, mode="confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "DOMAIN_OUT_OF_SCOPE"
    assert not policy.mutated and not t.channel.approvals and not browser.mutations


@pytest.mark.asyncio
async def test_descendant_activation_conservatively_disabled_even_same_scope(tmp_path):
    browser = Browser()
    browser.nodes[1].tag_name = "span"
    browser.live_ancestors = [{"tag": "a", "href": "https://example.com/live"}]
    t, policy, _ = tools(tmp_path, mode="confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "DESCENDANT_ACTIVATION_DISABLED"
    assert not policy.mutated and not t.channel.approvals and not browser.mutations


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["no_frame", "wrong_frame", "wrong_session", "context", "world_error", "owner"])
async def test_unverified_isolated_node_context_fails_closed(tmp_path, failure):
    browser = Browser()
    if failure == "no_frame":
        browser.nodes[1].frame_id = None
    elif failure == "wrong_frame":
        browser.nodes[1].frame_id = "unknown"
    elif failure == "wrong_session":
        browser.nodes[1].session_id = "other"
    elif failure in {"context", "world_error"}:
        original_world = browser.world
        calls = 0

        async def world(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:  # page_identity can observe; node context cannot be obtained
                return await original_world(**kwargs)
            if failure == "context":
                return {"executionContextId": None}
            raise RuntimeError("isolated world unavailable")

        browser.session.cdp_client.send.Page.createIsolatedWorld = world
    else:
        browser.call.return_value = {"result": {"value": None}}
        browser.call.side_effect = None
    t, policy, _ = tools(tmp_path, mode="confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "ELEMENT_CONTEXT_UNAVAILABLE"
    assert not policy.mutated and not t.channel.approvals and not browser.mutations
    assert all(c.kwargs["params"]["contextId"] == 7 for c in browser.evaluate.call_args_list)
    if failure == "owner":
        browser.session.cdp_client.send.Runtime.releaseObject.assert_awaited_once()


@pytest.mark.asyncio
async def test_frame_document_replacement_during_approval_is_bound(tmp_path):
    browser = Browser()

    class ChangingChannel(Channel):
        async def approve(self, approval):
            browser.frame_tree.return_value["frameTree"]["frame"]["loaderId"] = "new-document"
            return True

    t, policy, _ = tools(tmp_path, ChangingChannel(), mode="confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "ELEMENT_CHANGED_DURING_APPROVAL"
    assert not policy.mutated and not browser.mutations


@pytest.mark.asyncio
async def test_isolated_context_selected_from_node_frame_not_focus(tmp_path):
    browser = Browser()
    browser.frame_tree.return_value["frameTree"]["childFrames"] = [{"frame": {
        "id": "child", "loaderId": "child-loader", "url": browser.url}}]
    browser.nodes[1].frame_id = "child"
    snapshot = await worker.live_element_snapshot(browser, browser.nodes[1])
    assert snapshot["cdp_binding"] == {
        "frame_id": "child", "execution_context_id": 7, "loader_id": "child-loader",
        "frame_url": browser.url, "ancestor_urls": [browser.url]}
    browser.world.assert_awaited_once_with(params={"frameId": "child", "worldName": worker._ISOLATED_WORLD,
                                                 "grantUniveralAccess": False}, session_id="sid")
    browser.resolve.assert_awaited_once_with(params={"backendNodeId": 42, "executionContextId": 7},
                                           session_id="sid")


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing_frame", "missing_loader", "missing_context", "exception"])
async def test_observation_never_falls_back_to_main_world(failure):
    browser = Browser()
    if failure == "missing_frame":
        browser.frame_tree.return_value = {}
    elif failure == "missing_loader":
        browser.frame_tree.return_value["frameTree"]["frame"].pop("loaderId")
    elif failure == "missing_context":
        browser.world.return_value = {}
    else:
        browser.evaluate.return_value = {"exceptionDetails": {"text": "synthetic"}}
        browser.evaluate.side_effect = None
    with pytest.raises(RuntimeError):
        await worker.page_identity(browser)
    assert browser.evaluate.await_count == (1 if failure == "exception" else 0)
    assert all("contextId" in c.kwargs["params"] for c in browser.evaluate.call_args_list)


@pytest.mark.asyncio
async def test_socket_channel_matches_concurrent_responses_and_denies_disconnect():
    a, b = socket.socketpair()
    b.setblocking(False)
    channel = await worker.EventChannel.from_fd(a.detach())
    reader, writer = await asyncio.open_connection(sock=b)
    try:
        one, two = ApprovalRequest(action="click", description="one"), ApprovalRequest(action="input", description="two")
        first, second = asyncio.create_task(channel.approve(one)), asyncio.create_task(channel.approve(two))
        frames = [json.loads(await reader.readline()), json.loads(await reader.readline())]
        assert {f["approval"]["action_id"] for f in frames} == {one.action_id, two.action_id}
        writer.write((json.dumps({"type": "approval_response", "action_id": two.action_id, "allow": True}) + "\n").encode())
        writer.write((json.dumps({"type": "approval_response", "action_id": one.action_id, "allow": False}) + "\n").encode())
        await writer.drain()
        assert await asyncio.wait_for(second, 1) is True
        assert await asyncio.wait_for(first, 1) is False
        pending = asyncio.create_task(channel.approve(ApprovalRequest(action="click", description="pending")))
        await reader.readline()
        writer.close()
        await writer.wait_closed()
        assert await asyncio.wait_for(pending, 1) is False
    finally:
        await channel.close()


@pytest.mark.asyncio
async def test_channel_non_bool_and_unknown_response_never_approve():
    a, b = socket.socketpair()
    b.setblocking(False)
    channel = await worker.EventChannel.from_fd(a.detach())
    reader, writer = await asyncio.open_connection(sock=b)
    try:
        approval = ApprovalRequest(action="click", description="one")
        task = asyncio.create_task(channel.approve(approval))
        await reader.readline()
        writer.write((json.dumps({"type": "approval_response", "action_id": approval.action_id, "allow": "true"}) + "\n").encode())
        await writer.drain()
        assert not await asyncio.wait_for(task, 1)
    finally:
        writer.close()
        await writer.wait_closed()
        await channel.close()


def test_inherited_tokens_and_credentials_removed(monkeypatch):
    for name in ("T3_AUTH", "T3_ACP_MCP_TOKEN", "MCP_SECRET", "OTHER_TOKEN", "OPENAI_API_KEY", "BROCODE_WORKER_API_KEY"):
        monkeypatch.setenv(name, "sensitive-value")
    monkeypatch.setenv("NOCAPTCHA_API_KEY", "solver-secret")
    disable = worker.logging.root.manager.disable
    try:
        worker.sanitize_environment()
        assert not any(name in os.environ for name in ("T3_AUTH", "T3_ACP_MCP_TOKEN", "OTHER_TOKEN", "OPENAI_API_KEY", "BROCODE_WORKER_API_KEY"))
        assert os.environ["NOCAPTCHA_API_KEY"] == "solver-secret"
        assert os.environ["PYTHON_DOTENV_DISABLED"] == "1"
    finally:
        worker.logging.disable(disable)


@pytest.mark.asyncio
async def test_synthetic_entrypoint_protocol_no_secret_stdout(tmp_path):
    # Invalid request stops before importing or starting any live browser.
    envelope = tmp_path / "request.json"
    envelope.write_text(json.dumps({"request": {"goal": ""}, "api_key": "super-secret"}))
    a, b = socket.socketpair()
    a.setblocking(False)
    proc = await asyncio.create_subprocess_exec(
        os.sys.executable, "-m", "brocode.worker", "--request", str(envelope), "--events-fd", str(b.fileno()),
        pass_fds=(b.fileno(),), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    b.close()
    reader, writer = await asyncio.open_connection(sock=a)
    try:
        message = json.loads(await asyncio.wait_for(reader.readline(), 5))
        out, err = await asyncio.wait_for(proc.communicate(), 5)
        assert out == b""
        assert b"super-secret" not in err
        assert message["type"] == "outcome"
        assert message["outcome"]["error_code"] == "WORKER_ERROR"
        assert message["outcome"]["data"]["diagnostic"]["type"] == "ValidationError"
        assert "super-secret" not in json.dumps(message)
    finally:
        writer.close()
        await writer.wait_closed()
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


def test_sanitized_diagnostics_exclude_message_source_and_locals():
    try:
        raise ValueError("private-api-key-do-not-log")
    except ValueError as exc:
        diagnostic = worker.error_diagnostic(exc)
    assert diagnostic["type"] == "ValueError"
    assert "private-api-key" not in str(diagnostic)
    assert diagnostic["frames"][-1]["module"] == "test_worker.py"
    assert isinstance(diagnostic["frames"][-1]["line"], int)


@pytest.mark.asyncio
async def test_browser_start_failure_owns_cleanup_and_diagnostic(tmp_path, monkeypatch):
    # Full worker lifecycle with synthetic Agent/Browser: no live browser, network,
    # or actual profile. Verifies the exact 0-step failure regression.
    import browser_use
    from browser_use import llm

    from brocode.infra import browser as infra_browser
    run_dir, profile = tmp_path / "run", tmp_path / "profile"
    run_dir.mkdir()
    profile.mkdir()
    fake_browser = SimpleNamespace(kill=AsyncMock())
    seen = {}
    def browser_factory(**kwargs):
        seen["browser"] = kwargs
        return fake_browser
    class FailingAgent:
        def __init__(self, **kwargs):
            seen["agent"] = kwargs
            self.multi_act = AsyncMock()
        async def run(self, **kwargs):
            raise RuntimeError("sensitive-error-text")
    cleanup = AsyncMock()
    # Resolve lazy Agent annotations while Browser is still the real class.
    assert browser_use.Agent is not None
    monkeypatch.setattr(browser_use, "Browser", browser_factory)
    monkeypatch.setattr(browser_use, "Agent", FailingAgent)
    monkeypatch.setattr(llm, "ChatOpenAI", lambda **kwargs: seen.update(llm=kwargs))
    monkeypatch.setattr(infra_browser, "browser_kwargs", lambda **kwargs: {})
    monkeypatch.setattr(infra_browser, "cleanup_owned_processes", cleanup)
    monkeypatch.setattr(worker, "sanitize_environment", lambda: None)
    monkeypatch.setattr(worker, "capture_screenshot", AsyncMock())
    monkeypatch.setenv("BROCODE_WORKER_API_KEY", "transient-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile
    old_tmp = tempfile.tempdir
    try:
        result = await worker.run_browser({"request": {"goal": "read", "policy": {"allowed_domains": ["example.com"]}},
            "run_dir": str(run_dir), "profile_dir": str(profile), "model": "test-model", "base_url": "https://api.example.test/v1",
            "proxy_url": "http://127.0.0.1:1088", "egress_mode": "warp"}, Channel())
    finally:
        tempfile.tempdir = old_tmp
    assert result.error_code == "WORKER_ERROR"
    assert result.steps == result.actions == 0
    assert result.data["diagnostic"]["type"] == "RuntimeError"
    assert "sensitive-error-text" not in result.model_dump_json()
    assert not result.checks_passed
    assert result.usage["cost_usd"] is None
    assert seen["llm"]["api_key"] == "transient-key"
    assert "BROCODE_WORKER_API_KEY" not in os.environ
    assert seen["agent"]["max_actions_per_step"] == 1
    assert seen["agent"]["directly_open_url"] is False
    assert Path(seen["agent"]["file_system_path"]).is_relative_to(run_dir)
    assert Path(seen["browser"]["downloads_path"]).is_relative_to(run_dir)
    fake_browser.kill.assert_awaited_once()
    cleanup.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("field,before,after", [
    ("value", "synthetic-old", "synthetic-new"),
    ("checked", False, True),
    ("options", [{"value": "a", "selected": True}], [{"value": "b", "selected": True}]),
    ("files", [{"name": "a.txt", "size": 1}], [{"name": "b.txt", "size": 2}]),
    ("disabled", False, True),
])
async def test_same_button_changed_form_payload_blocks_without_exposing_values(tmp_path, field, before, after):
    browser = Browser()
    browser.form_controls[0][field] = before

    class ChangingChannel(Channel):
        async def approve(self, approval):
            self.approvals.append(approval)
            browser.form_controls[0][field] = after
            return True

    channel = ChangingChannel()
    t, policy, _ = tools(tmp_path, channel, "confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "ELEMENT_CHANGED_DURING_APPROVAL"
    assert not policy.mutated and not browser.mutations
    assert browser.nodes[1].backend_node_id == 42
    preview = channel.approvals[0].model_dump_json()
    assert "synthetic-nonce" not in preview and "synthetic-old" not in preview
    assert "form_controls" not in preview
    assert len(channel.approvals[0].payload["element"]["element_fingerprint"]) == 64


@pytest.mark.asyncio
async def test_same_scope_submit_override_change_is_bound(tmp_path):
    browser = Browser()

    class ChangingChannel(Channel):
        async def approve(self, approval):
            browser.destinations = ["https://example.com/other-submit"]
            return True

    t, policy, _ = tools(tmp_path, ChangingChannel(), "confirm")
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "ELEMENT_CHANGED_DURING_APPROVAL"
    assert not policy.mutated and not browser.mutations


@pytest.mark.asyncio
async def test_live_out_of_scope_submit_override_is_denied(tmp_path):
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    browser.destinations = ["https://evil.test/submit"]
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "DOMAIN_OUT_OF_SCOPE"
    assert not policy.mutated and not t.channel.approvals


@pytest.mark.asyncio
@pytest.mark.parametrize("focus,override", [
    (42, "https://example.com/submit"),
    (43, "https://example.com/submit"),
    (43, "https://evil.test/submit"),
])
async def test_global_send_keys_never_dispatches_even_with_same_shape_focus(tmp_path, focus, override):
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    # Same tag/type/role but different backend node, or implicit submit override.
    browser.nodes[1] = SimpleNamespace(tag_name="input", attributes={"type": "text"},
                                     backend_node_id=focus, parent_node=None)
    browser.destinations = [override]
    result = await t.registry.execute_action("send_keys", {"keys": "Enter"}, browser)
    assert result.is_done and result.error == "UNBOUND_KEY_DISPATCH_DISABLED"
    assert not policy.mutated and not t.channel.approvals
    assert not browser.mutations and not browser.call.await_count
    assert browser.evaluate.await_count == 1  # page identity only, no weak activeElement authorization


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["raise", "cancel", "error", "unsuccessful", "unspecified", "none"])
async def test_mutation_side_effect_then_failure_latches_terminal_and_prevents_retry(tmp_path, failure):
    from browser_use.agent.views import ActionResult

    from brocode.policy import PolicyBlocked
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    effects = []

    async def original(**kwargs):
        effects.append("remote side effect")
        if failure == "raise":
            raise RuntimeError("synthetic-private-error")
        if failure == "cancel":
            raise asyncio.CancelledError()
        if failure == "error":
            return ActionResult(error="synthetic-private-error")
        if failure == "unsuccessful":
            return ActionResult(success=False)
        if failure == "unspecified":
            return ActionResult(extracted_content="Maybe completed")
        return None

    with pytest.raises(PolicyBlocked, match="UNCERTAIN_MUTATION"):
        await t.dispatch(original, "click", {"index": 1}, browser)
    assert effects == ["remote side effect"]
    assert policy.mutated and policy.actions == 1
    assert t.outcome.error_code == policy.error_code == "UNCERTAIN_MUTATION"
    assert "synthetic-private-error" not in t.outcome.model_dump_json()
    await_count = browser.evaluate.await_count
    for action, params in (("click", {"index": 1}), ("done", {"text": "ok"}), ("wait", {}),
                           ("solve_captcha", {}), ("navigate", {"url": "https://example.com"})):
        result = await t.registry.execute_action(action, params, browser)
        assert result.is_done and result.error == "UNCERTAIN_MUTATION"
    with pytest.raises(PolicyBlocked, match="UNCERTAIN_MUTATION"):
        await t.audit_captcha(browser)
    # Retry does not even observe the page or inspect/solve a CAPTCHA.
    assert browser.evaluate.await_count == await_count
    assert len(t.channel.approvals) == 1 and effects == ["remote side effect"]
    batch = SimpleNamespace(model_dump=lambda **_: {"click": {}, "input": {}})
    assert (await t.act(batch, browser)).error == "UNCERTAIN_MUTATION"
    assert policy.actions == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("name,attrs,params", [
    ("click", {"type": "submit"}, {"index": 1}),
    ("input", {"type": "text"}, {"index": 1, "text": "synthetic-value"}),
    ("select_dropdown", {}, {"index": 1, "text": "a"}),
])
async def test_registered_mutations_replace_dependency_retry_handlers(tmp_path, name, attrs, params):
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    browser.nodes[1].tag_name = {"input": "input", "select_dropdown": "select"}.get(name, "button")
    browser.nodes[1].attributes = attrs
    # Agent construction re-registers click when toggling coordinate support.
    t.set_coordinate_clicking(True)
    result = await t.registry.execute_action(name, params, browser)
    assert not result.error and result.metadata == {"brocode_single_attempt": True}
    assert policy.mutated and len(browser.mutations) == 1
    source = browser.mutations[0]["functionDeclaration"]
    assert "JSON.stringify(snapshot)!==JSON.stringify(expected)" in source
    assert "dispatchKeyEvent" not in source
    if name == "input":
        assert "set(protos[tag],'value',this,intended)" in source and "this.focus" not in source
    if name == "click":
        assert "invoke(HTMLElement.prototype.click,this)" in source


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [{"success": False}, {"changed": True}, None])
async def test_single_attempt_adapter_failure_never_falls_back(tmp_path, response):
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    browser.mutation_response = response
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.is_done and result.error == "UNCERTAIN_MUTATION"
    assert policy.actions == 1 and len(browser.mutations) == 1
    assert (await t.registry.execute_action("click", {"index": 1}, browser)).error == "UNCERTAIN_MUTATION"
    assert len(browser.mutations) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "javascript_exception"])
async def test_adapter_cdp_error_after_side_effect_is_terminal_without_fallback(tmp_path, failure):
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    original_call = browser._call

    async def call(params, session_id):
        if "arguments" not in params:
            return await original_call(params, session_id)
        browser.mutations.append(params)  # side effect may already have reached the server
        if failure == "exception":
            raise RuntimeError("synthetic-sensitive-cdp-error")
        return {"exceptionDetails": {"text": "synthetic-sensitive-javascript-error"}}

    browser.call.side_effect = call
    result = await t.registry.execute_action("click", {"index": 1}, browser)
    assert result.error == "UNCERTAIN_MUTATION"
    assert policy.mutated and policy.actions == 1
    assert len(browser.mutations) == 1
    assert "synthetic-sensitive" not in t.outcome.model_dump_json()
    assert (await t.registry.execute_action("click", {"index": 1}, browser)).error == "UNCERTAIN_MUTATION"
    assert len(browser.mutations) == 1


@pytest.mark.asyncio
async def test_registered_file_upload_is_disabled_before_approval_or_dispatch(tmp_path):
    upload = tmp_path / "synthetic-upload.txt"
    upload.write_text("synthetic content")
    t, policy, _ = tools(tmp_path, mode="confirm")
    policy.upload_paths.add(upload)
    browser = Browser()
    browser.nodes[1].tag_name = "input"
    browser.nodes[1].attributes = {"type": "file"}
    set_files = AsyncMock()
    browser.session.cdp_client.send.DOM.setFileInputFiles = set_files
    result = await t.registry.execute_action("upload_file", {"index": 1, "path": str(upload)}, browser)
    assert result.error == "ATOMIC_UPLOAD_DISABLED"
    assert not policy.mutated and policy.actions == 0 and not t.channel.approvals
    set_files.assert_not_awaited()
    browser.resolve.assert_not_awaited()
    assert not browser.mutations and upload in policy.upload_paths
    # Even direct invocation of the replacement handler cannot escape the ban.
    from brocode.policy import PolicyBlocked
    with pytest.raises(PolicyBlocked, match="ATOMIC_UPLOAD_DISABLED"):
        await t.mutate_once("upload_file", {"index": 1, "path": str(upload)}, browser)
    set_files.assert_not_awaited()


@pytest.mark.asyncio
async def test_unsafe_captcha_injector_is_disabled(tmp_path, monkeypatch):
    from brocode.infra import captcha
    from brocode.policy import PolicyBlocked
    t, policy, _ = tools(tmp_path, mode="confirm")
    browser = Browser()
    monkeypatch.setattr(worker, "cdp_value", AsyncMock(return_value={"kind": "recaptcha-v2"}))
    solve = AsyncMock()
    monkeypatch.setattr(captcha, "solve_if_present", solve)
    with pytest.raises(PolicyBlocked, match="CAPTCHA_AUTOMATION_DISABLED"):
        await t.audit_captcha(browser)
    solve.assert_not_awaited()
    assert not policy.mutated


@pytest.mark.asyncio
async def test_direct_captcha_dispatch_is_disabled_before_approval(tmp_path):
    t, policy, _ = tools(tmp_path, mode="confirm")
    result = await t.registry.execute_action("solve_captcha", {}, Browser())
    assert result.is_done and result.error == "CAPTCHA_AUTOMATION_DISABLED"
    assert not policy.mutated and not t.channel.approvals


@pytest.mark.asyncio
async def test_single_attempt_scripts_against_synthetic_dom_only():
    # Synthetic JS realms only: no browser, network, profile, or Playwright.
    # WeakMap-backed native descriptors model the DOM internal slots; public own
    # properties can lie/throw without changing those slots.
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the synthetic JavaScript contract check")
    script = "const scripts=" + json.dumps({
        name: worker.SINGLE_MUTATION_JS.replace("__MUTATION__", body)
        for name, body in worker.MUTATION_JS.items()
    }) + ";const snapshotSource=" + json.dumps(worker.ELEMENT_SNAPSHOT_JS) + ";" + r"""
      const assert=require('assert/strict'),vm=require('vm');
      const setup=`
        const slots=new WeakMap(), state=o=>slots.get(o);
        class EventTarget {dispatchEvent(e){events.push(e.type);if(onEvent)onEvent(this,e);return true;}}
        class Node extends EventTarget {getRootNode(){return state(this).root||document;}}
        class Element extends Node {
          getAttribute(k){return state(this).attrs?.[k]??null;}
          getAttributeNames(){return Object.keys(state(this).attrs||{});}
        }
        class HTMLElement extends Element {click(){clicks++;}}
        class Document extends Node {}
        class HTMLInputElement extends HTMLElement {}
        class HTMLTextAreaElement extends HTMLElement {}
        class HTMLSelectElement extends HTMLElement {}
        class HTMLOptionElement extends HTMLElement {}
        class HTMLButtonElement extends HTMLElement {}
        class HTMLFormElement extends HTMLElement {}
        class HTMLAnchorElement extends HTMLElement {}
        class HTMLAreaElement extends HTMLElement {}
        class HTMLFieldSetElement extends HTMLElement {}
        class HTMLOutputElement extends HTMLElement {}
        class HTMLObjectElement extends HTMLElement {}
        class HTMLCollection {item(i){return state(this)[i];}}
        class FileList extends HTMLCollection {}
        class Blob {}
        class File extends Blob {}
        class Event {constructor(type){this.type=type;}}
        const define=(p,k)=>Object.defineProperty(p,k,{configurable:true,
          get(){return state(this)[k]??null;},set(v){state(this)[k]=v;}});
        for(const k of ['isConnected','ownerDocument','parentElement','baseURI','textContent']) define(Node.prototype,k);
        define(Element.prototype,'tagName');
        for(const k of ['URL','title','body','forms']) define(Document.prototype,k);
        define(HTMLElement.prototype,'innerText');
        define(HTMLCollection.prototype,'length');define(FileList.prototype,'length');
        for(const C of [HTMLInputElement,HTMLTextAreaElement,HTMLSelectElement,HTMLOptionElement,
            HTMLButtonElement,HTMLFormElement,HTMLAnchorElement,HTMLAreaElement,HTMLFieldSetElement,
            HTMLOutputElement,HTMLObjectElement])
          for(const k of ['type','name','form','value','checked','disabled','selectedIndex','selected',
              'options','files','text','index','elements','action','method','enctype','target','noValidate',
              'formAction','formMethod','formEnctype','formTarget','formNoValidate','href']) define(C.prototype,k);
        for(const k of ['name','lastModified','webkitRelativePath']) define(File.prototype,k);
        for(const k of ['size','type']) define(Blob.prototype,k);
        const make=(C,s)=>{const o=new C();slots.set(o,s);return o;};
        const collection=(a,C=HTMLCollection)=>make(C,Object.assign([...a],{length:a.length}));
        let clicks=0,events=[],onEvent=null;
        const document=make(Document,{URL:'https://example.com/',title:'Confirmed',forms:collection([])});
        const element=(C,tag,type='',value='')=>make(C,{tagName:tag.toUpperCase(),type,value,
          attrs:{type},isConnected:true,ownerDocument:document,baseURI:'https://example.com/',
          parentElement:null,textContent:'synthetic label',name:'test',checked:false,disabled:false});
        const form=element(HTMLFormElement,'form');
        Object.assign(state(form),{action:'https://example.com/submit',method:'post',
          enctype:'multipart/form-data',target:'_self',noValidate:false});
        const hidden=element(HTMLInputElement,'input','hidden','old');
        const input=element(HTMLInputElement,'input','text','old');
        const button=element(HTMLButtonElement,'button','submit');
        const select=element(HTMLSelectElement,'select','select-one','a');
        const a=element(HTMLOptionElement,'option'),b=element(HTMLOptionElement,'option');
        Object.assign(state(a),{value:'a',text:'A',index:0,selected:true});
        Object.assign(state(b),{value:'b',text:'B',index:1,selected:false});
        state(select).options=collection([a,b]);state(select).selectedIndex=0;
        // Native select setter changes option state as the browser would.
        Object.defineProperty(HTMLSelectElement.prototype,'selectedIndex',{
          get(){return state(this).selectedIndex;},set(i){state(this).selectedIndex=i;
            state(a).selected=i===0;state(b).selected=i===1;}});
        const file=element(HTMLInputElement,'input','file');
        const f=make(File,{name:'synthetic.txt',size:3,type:'text/plain',lastModified:1,webkitRelativePath:''});
        state(file).files=collection([f],FileList);
        for(const e of [hidden,input,button,select,file]) state(e).form=form;
        state(form).elements=collection([hidden,input,button,select,file]);
        state(document).forms=collection([form]);
      `;
      const isolated=vm.createContext({});vm.runInContext(setup,isolated);
      const page=vm.createContext({});vm.runInContext(setup,page);
      // Host-page globals/prototypes are a different realm. In production CDP
      // createIsolatedWorld + resolveNode(executionContextId) enforce that split.
      vm.runInContext(`JSON.stringify=()=> 'same';Array.from=()=>[];
        Object.getOwnPropertyDescriptor=()=>({get:()=> 'forged'});
        HTMLElement.prototype.click=()=>{throw Error('page click')};
        Object.defineProperty(HTMLInputElement.prototype,'value',{get:()=> 'forged'});`,page);
      isolated.source=snapshotSource;isolated.scripts=scripts;
      isolated.identitySource=""" + json.dumps(worker.PAGE_IDENTITY_JS) + r""";
      isolated.verificationSource=""" + json.dumps(worker.PAGE_VERIFICATION_JS) + r""";
      vm.runInContext(`
        const snapshot=eval('('+source+')'),click=eval('('+scripts.click+')');
        const type=eval('('+scripts.input+')'),choose=eval('('+scripts.select_dropdown+')');
        const ok=(condition)=>{if(!condition)throw Error('synthetic assertion failed');};
        const equals=(a,b)=>ok(JSON.stringify(a)===JSON.stringify(b));
        // Even hostile own properties in the trusted realm cannot intercept DOM
        // reads/operations. This also models native named-property shadowing.
        const poison=(o,k)=>Object.defineProperty(o,k,{configurable:true,
          get(){throw Error('untrusted own '+k);},set(){throw Error('untrusted setter');}});
        for(const k of ['value','form','type','tagName','ownerDocument','isConnected','getRootNode',
            'dispatchEvent','click','getAttribute','attributes']) poison(input,k);
        for(const k of ['action','method','elements']) poison(form,k);
        poison(button,'click');
        for(const k of ['URL','title','body']) poison(document,k);
        const body=element(HTMLElement,'body');state(body).innerText='Confirmation received';
        state(document).body=body;poison(body,'innerText');
        equals(eval(identitySource),{url:'https://example.com/',title:'Confirmed'});
        equals(eval(verificationSource),{url:'https://example.com/',title:'Confirmed',text:'Confirmation received'});
        const before=snapshot.call(button);
        for(const change of [()=>state(hidden).value='changed',()=>state(b).selected=true,
            ()=>state(f).size=4,()=>state(form).action='https://example.com/other']) {
          const old=JSON.stringify(snapshot.call(button));change();
          ok(old!==JSON.stringify(snapshot.call(button)));
        }
        equals(click.call(button,before,{}),{changed:true});ok(clicks===0);
        equals(click.call(button,snapshot.call(button),{}),{success:true});ok(clicks===1);
        state(button).attrs.formaction='https://evil.test/submit';
        state(button).formAction='https://evil.test/submit';
        ok(snapshot.call(button).destinations.includes('https://evil.test/submit'));
        equals(type.call(input,snapshot.call(input),{text:'new text'}),{success:true});
        ok(state(input).value==='new text');equals(events,['input','change']);
        onEvent=e=>{state(e).value='reverted';};
        equals(type.call(input,snapshot.call(input),{text:'replacement'}),{success:false});
        ok(events.length===4);onEvent=null;
        equals(choose.call(select,snapshot.call(select),{text:'B'}),{success:true});
        ok(state(select).selectedIndex===1);
        // Current parent href and descendant activation are part of the FINAL
        // atomic snapshot, not the dependency's cached ancestor attributes.
        const anchor=element(HTMLAnchorElement,'a');state(anchor).href='https://example.com/old';
        const span=element(HTMLElement,'span');state(span).parentElement=anchor;
        const spanBefore=snapshot.call(span);ok(spanBefore.activationAncestor);
        state(anchor).href='https://evil.test/new';
        ok(snapshot.call(span).destinations.includes('https://evil.test/new'));
        equals(click.call(span,spanBefore,{}),{changed:true});ok(clicks===1);
        equals(click.call(span,snapshot.call(span),{}),{success:false});ok(clicks===1);
        state(button).ownerDocument=make(Document,{});ok(snapshot.call(button)===null);
      `,isolated);
      assert.equal(vm.runInContext('JSON.stringify({actual:true})',page),'same');
      console.log('synthetic JavaScript contracts passed');
    """
    process = await asyncio.create_subprocess_exec(node, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(script.encode()), 10)
    assert process.returncode == 0, stderr.decode()
    assert b"synthetic JavaScript contracts passed" in stdout
