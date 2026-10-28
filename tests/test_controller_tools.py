"""Synthetic tests for bounded registered controller tools; no live network or browser."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from brocode.contracts import Status, TaskRequest
from brocode.controller_tools import TOOL_NAMES, list_tools, run_tool


class StubStore:
    def __init__(self, results):
        self._results = results

    def get(self, run_id):
        return self._results.get(run_id)


class StubRuntime:
    def __init__(self, results=None, mode="tailscale", proxy="http://127.0.0.1:1088"):
        self.settings = SimpleNamespace(egress_mode=mode, proxy_url=proxy, api_key="super-secret")
        self.store = StubStore(results or {})


@pytest.fixture
def local_state(tmp_path, monkeypatch):
    monkeypatch.setenv("BROCODE_ROOT", str(tmp_path))
    monkeypatch.setenv("BROCODE_STATE_DIR", str(tmp_path / "var"))
    return tmp_path


@pytest.fixture
def stub(monkeypatch):
    from brocode.infra import preflight as pf
    monkeypatch.setattr(pf, "listener_matches", lambda *a: True)
    # Offline guarantee: fail loudly if any live probe is attempted.
    monkeypatch.setattr(pf, "proxy_health", _forbidden)
    monkeypatch.setattr(pf, "route_probe", _forbidden)
    return StubRuntime()


async def _forbidden(*args, **kwargs):
    raise AssertionError("live network probe must not run in controller tools")


def test_allowlist_names_and_read_only(stub):
    assert set(TOOL_NAMES) == {"egress_status", "capabilities", "challenge_summary"}
    described = list_tools()
    assert [t["name"] for t in described] == list(TOOL_NAMES)
    assert all(t["read_only"] for t in described)
    assert "shell" not in json.dumps(described) and "eval" not in json.dumps(described)


def test_egress_status_offline_valid(stub):
    from brocode.infra.egress import EGRESS_MODES
    out = run_tool(stub, "egress_status")
    assert out["mode_supported"] is True
    assert out["supported_modes"] == sorted(EGRESS_MODES)
    assert out["supported_modes"] >= ["tailscale", "tailscale-relay", "warp"]
    assert out["proxy_config_ok"] is True
    assert out["proxy_port"] == 1088
    assert out["live_probes"] == "not_run"
    assert "super-secret" not in json.dumps(out)


def test_egress_status_uses_shared_modes_not_hardcoded(stub, monkeypatch):
    from brocode.infra import egress
    monkeypatch.setattr(egress, "EGRESS_MODES", {"tailscale", "warp", "tailscale-relay", "future"})
    stub.settings.egress_mode = "future"
    out = run_tool(stub, "egress_status")
    assert out["mode_supported"] is True
    assert "future" in out["supported_modes"]


def test_egress_status_rejects_bad_config(stub):
    stub.settings.egress_mode = "direct"
    stub.settings.proxy_url = "socks5://127.0.0.1:1088"
    out = run_tool(stub, "egress_status")
    assert out["mode_supported"] is False
    assert out["proxy_config_ok"] is False
    assert "socks5" not in json.dumps(out)


def test_capabilities_disables_sensitive_helpers(stub):
    out = run_tool(stub, "capabilities")
    disabled = {d["name"] for d in out["disabled"]}
    assert {"automatic_captcha_solving", "live_pause_resume", "approval_escalation",
            "browser_launch", "arbitrary_shell_scripts_paths_eval"} <= disabled
    assert "pause" in out["pause_resume"].lower() and "not implemented" in out["pause_resume"]
    assert "reconcile" in out["pause_resume"].lower()
    assert "no live captcha handoff" in json.dumps(out).lower()


def test_capabilities_distinguishes_questions_from_resume(stub):
    out = run_tool(stub, "capabilities")
    assert "ask_caller" in out["questions"]["in_flight_ask_caller"]
    assert "elicitation" in out["questions"]["in_flight_ask_caller"]
    assert "not supported" in out["questions"]["restart_or_resume"].lower()


def test_run_tool_rejects_unknown_and_bad_args(stub):
    with pytest.raises(ValueError):
        run_tool(stub, "arbitrary")
    with pytest.raises(ValueError):
        run_tool(stub, "egress_status", {"unexpected": True})
    with pytest.raises(ValueError):
        run_tool(stub, "capabilities", ["not-a-dict"])
    with pytest.raises(ValueError):
        run_tool(stub, "challenge_summary", {})
    for bad in ("../evil", "a/b", "", "x" * 129):
        with pytest.raises(ValueError):
            run_tool(stub, "challenge_summary", {"run_id": bad})
    with pytest.raises(KeyError):
        run_tool(stub, "challenge_summary", {"run_id": "missing"})


def test_challenge_summary_states(stub):
    from brocode.contracts import TaskResult
    waiting = TaskResult(status=Status.NEEDS_INPUT, result="Supply exact allowed domains")
    approval = TaskResult(status=Status.AWAITING_APPROVAL)
    stub.store = StubStore({"w": waiting, "a": approval})
    needs = run_tool(stub, "challenge_summary", {"run_id": "w"})
    assert needs["needs_input"] is True and needs["terminal"] is True
    assert "new scoped task" in needs["guidance"]
    assert needs["result_preview"] == "Supply exact allowed domains"
    pending = run_tool(stub, "challenge_summary", {"run_id": "a"})
    assert pending["awaiting_approval"] is True
    assert "cannot approve" in pending["guidance"]


def test_challenge_summary_terminated_challenge_has_no_handoff(stub):
    from brocode.contracts import TaskResult
    blocked = TaskResult(status=Status.BLOCKED, error_code="CAPTCHA_REQUIRED",
                         result="A challenge appeared")
    stub.store = StubStore({"c": blocked})
    out = run_tool(stub, "challenge_summary", {"run_id": "c"})
    assert "no live captcha handoff" in out["guidance"]
    assert "owned browser" not in out["guidance"]
    assert "reconcile" in out["guidance"]


def test_challenge_summary_pairs_new_task_with_reconciliation(stub):
    from brocode.contracts import TaskResult
    partial = TaskResult(status=Status.PARTIAL, result="Uncertain write")
    stub.store = StubStore({"p": partial})
    out = run_tool(stub, "challenge_summary", {"run_id": "p"})
    assert "reconcile" in out["guidance"]
    assert "before retrying" in out["guidance"]


async def test_cli_tools_list_and_run(local_state, capsys):
    import os
    os.environ["BROCODE_PROXY_URL"] = "http://127.0.0.1:1088"
    os.environ["BROCODE_EGRESS_MODE"] = "tailscale"
    from brocode.cli import dispatch, parser
    from brocode.store import Store
    assert await dispatch(parser().parse_args(["tools", "list"])) == 0
    assert set(json.loads(capsys.readouterr().out)[0]) >= {"name", "description"}
    result, _ = Store(local_state / "var").create_task(TaskRequest(goal="read"))
    assert await dispatch(parser().parse_args(
        ["tools", "run", "challenge_summary", "--args", json.dumps({"run_id": result.run_id})])) == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == result.run_id
    with pytest.raises(ValueError):
        await dispatch(parser().parse_args(["tools", "run", "nope"]))
    with pytest.raises(ValueError):
        await dispatch(parser().parse_args(["tools", "run", "egress_status", "--args", "[1]"]))
