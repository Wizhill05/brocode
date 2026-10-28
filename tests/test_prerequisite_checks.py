"""Synthetic validation of live acceptance diagnostics; no public requests."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import test_live_prerequisites as checks


@pytest.mark.parametrize("failure", [None, "upstream", "proxy", "host", "mismatch", "isolation"])
async def test_route_diagnostics_probe_every_path_and_never_save_ips(tmp_path, monkeypatch, failure):
    settings = SimpleNamespace(egress_mode="tailscale-relay", proxy_url="http://127.0.0.1:1089")
    monkeypatch.setattr(checks.Settings, "load", lambda: settings)
    monkeypatch.setattr(checks, "proxy_health", AsyncMock(return_value={
        "mode": "tailscale-relay", "relay_host": "127.0.0.1", "relay_port": 8080,
    }))
    seen = []

    async def route_probe(proxy_url=None):
        name = "host" if proxy_url is None else "proxy" if ":1089" in proxy_url else "upstream"
        seen.append(name)
        if name == failure:
            raise TimeoutError("DO_NOT_LEAK private details")
        address = "198.51.100.9" if name == "host" else "203.0.113.7"
        if failure == "mismatch" and name == "proxy":
            address = "192.0.2.6"
        if failure == "isolation":
            address = "203.0.113.7"
        return {"ip": address}

    monkeypatch.setattr(checks, "route_probe", route_probe)
    if failure is None:
        await checks.test_live_relay_route_paths(tmp_path)
    else:
        with pytest.raises(AssertionError):
            await checks.test_live_relay_route_paths(tmp_path)
    assert sorted(seen) == ["host", "proxy", "upstream"]
    path = tmp_path / "relay-route-paths.json"
    raw = path.read_text()
    report = json.loads(raw)
    assert "DO_NOT_LEAK" not in raw
    assert all(address not in raw for address in ("198.51.100.9", "203.0.113.7", "192.0.2.6"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert report["browser_opened"] is False
    if failure in {"upstream", "proxy", "host"}:
        assert report["selected_route_equal"] is None
        assert report["host_isolated"] is None
    else:
        assert report["selected_route_equal"] is (failure != "mismatch")
        assert report["host_isolated"] is (failure != "isolation")


@pytest.mark.parametrize("host,port", [("external.test", 8080), ("127.0.0.1", True), ("127.0.0.1", 0)])
async def test_route_diagnostics_refuse_invalid_upstream(tmp_path, monkeypatch, host, port):
    monkeypatch.setattr(checks.Settings, "load", lambda: SimpleNamespace(
        egress_mode="tailscale-relay", proxy_url="http://127.0.0.1:1089",
    ))
    monkeypatch.setattr(checks, "proxy_health", AsyncMock(return_value={
        "mode": "tailscale-relay", "relay_host": host, "relay_port": port,
    }))
    probe = AsyncMock()
    monkeypatch.setattr(checks, "route_probe", probe)
    with pytest.raises(AssertionError):
        await checks.test_live_relay_route_paths(tmp_path)
    probe.assert_not_called()
