from types import SimpleNamespace

import pytest

from brocode.contracts import TaskRequest
from brocode.infra import egress
from brocode.infra import preflight as pf

SOURCE_IP = "100.64.0.10"  # Synthetic CGNAT fixture, never an installed host address.


def settings(tmp_path, mode="tailscale"):
    return SimpleNamespace(root=tmp_path, state_dir=tmp_path / "var", profile_dir=tmp_path / "profile",
                           proxy_url="http://127.0.0.1:1088", egress_mode=mode, model="test-model",
                           base_url="https://api.example.test/v1", api_key="very-secret-key", chrome_path="/chrome",
                           display=":99")


def rules():
    return [{"priority": 0, "src": "all", "table": "local"},
            {"priority": 5200, "src": SOURCE_IP, "table": 52},
            {"priority": 5260, "src": "all", "table": "main"}]


def mock_diagnostics(monkeypatch, mode="tailscale", mismatch=False):
    import json
    async def command(*args):
        if args[0] == "/chrome":
            return "Google Chrome 123"
        if args[0] == "xdpyinfo":
            assert args[-1] == ":99"
            return "display responsive"
        if args[0] == "tailscale":
            return json.dumps({"BackendState": "Running", "ExitNodeStatus": {"Online": True}})
        if "rule" in args:
            return json.dumps(rules())
        return json.dumps([{"dst": "default", "dev": "tailscale0"}])
    async def health(url):
        return {"service": "brocode-egress-v1", "mode": mode, "source_ip": SOURCE_IP,
                "warp_host": "127.0.0.1", "warp_port": 40000}
    async def probe(proxy_url=None, source_ip=None):
        return {"ip": "203.0.113.1" if not (proxy_url or source_ip) else
                "203.0.113.3" if mismatch and proxy_url and "1088" in proxy_url else "203.0.113.2",
                "warp": "on" if mode == "warp" and proxy_url else "off"}
    monkeypatch.setattr(pf, "command", command)
    monkeypatch.setattr(pf, "proxy_health", health)
    monkeypatch.setattr(pf, "route_probe", probe)
    monkeypatch.setattr(pf, "listener_matches", lambda *_: True)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["tailscale", "warp"])
async def test_healthy_explicit_route_without_captcha_key(tmp_path, monkeypatch, mode):
    monkeypatch.delenv("NOCAPTCHA_API_KEY", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    mock_diagnostics(monkeypatch, mode)
    checks = await pf.preflight(settings(tmp_path, mode), TaskRequest(goal="read", policy={"allowed_domains": ["example.com"]}))
    assert all(c["ok"] for c in checks), checks
    assert "very-secret-key" not in str(checks)


@pytest.mark.asyncio
async def test_different_ip_alone_does_not_prove_selected_provider(tmp_path, monkeypatch):
    mock_diagnostics(monkeypatch, mismatch=True)
    checks = await pf.preflight(settings(tmp_path))
    assert any(c["name"] == "selected route IP" and not c["ok"] for c in checks)


@pytest.mark.asyncio
async def test_provider_mismatch_and_legacy_proxy_block(tmp_path, monkeypatch):
    mock_diagnostics(monkeypatch, "warp")
    checks = await pf.preflight(settings(tmp_path, "tailscale"))
    assert any(c["name"] == "egress proxy mode" and not c["ok"] for c in checks)
    async def legacy(url):
        raise ValueError("no health endpoint")
    monkeypatch.setattr(pf, "proxy_health", legacy)
    checks = await pf.preflight(settings(tmp_path))
    assert any(c["name"] == "egress proxy health" and not c["ok"] for c in checks)


@pytest.mark.asyncio
async def test_stale_lock_is_reported_never_repaired(tmp_path, monkeypatch):
    mock_diagnostics(monkeypatch)
    config = settings(tmp_path)
    config.profile_dir.mkdir()
    lock = config.profile_dir / "SingletonLock"
    lock.symlink_to("hostname-99999999")
    checks = await pf.preflight(config)
    assert any(c["name"] == "profile not locked" and not c["ok"] for c in checks)
    assert lock.is_symlink()


@pytest.mark.parametrize("url", ["", "socks5://127.0.0.1:1088", "http://evil.test:1088",
                                      "http://u:secret@127.0.0.1:1088", "http://127.0.0.1", "http://127.0.0.1:1088/path"])
def test_proxy_config_fails_closed(url):
    with pytest.raises(ValueError):
        pf.parse_proxy(url)


def test_tailscale_requires_explicit_source_and_warp_does_not():
    assert egress.EgressConfig("warp").source_ip is None
    with pytest.raises(ValueError, match="explicit --source-ip"):
        egress.EgressConfig("tailscale")
    with pytest.raises(ValueError, match="IPv4"):
        egress.EgressConfig("tailscale", source_ip="::1")


def test_rules_require_exact_order_and_source():
    assert pf.scoped_rules(rules(), SOURCE_IP)
    bad = rules()
    bad[1]["priority"] = 6000
    assert not pf.scoped_rules(bad, SOURCE_IP)
    assert not pf.scoped_rules(rules(), "100.0.0.1")


@pytest.mark.asyncio
async def test_warp_failure_never_dials_tailscale(monkeypatch):
    calls = []
    async def broken(*args, **kwargs):
        calls.append((args, kwargs))
        raise ConnectionError()
    monkeypatch.setattr(egress.asyncio, "open_connection", broken)
    with pytest.raises(ConnectionError):
        await egress.dial("example.com", 443, egress.EgressConfig("warp"))
    assert len(calls) == 1
    assert calls[0][0] == ("127.0.0.1", 40000)


@pytest.mark.asyncio
async def test_tailscale_dial_is_bound_and_never_probes_warp(monkeypatch):
    calls = []
    async def connect(*args, **kwargs):
        calls.append((args, kwargs))
        return (None, None)
    monkeypatch.setattr(egress.asyncio, "open_connection", connect)
    await egress.dial("example.com", 443, egress.EgressConfig("tailscale", source_ip=SOURCE_IP))
    assert calls == [(("example.com", 443), {"local_addr": (SOURCE_IP, 0)})]


@pytest.mark.asyncio
async def test_command_error_does_not_echo_credentials(tmp_path, monkeypatch):
    mock_diagnostics(monkeypatch)
    async def failed(*args):
        raise RuntimeError("secret-key accidental library error")
    monkeypatch.setattr(pf, "command", failed)
    checks = await pf.preflight(settings(tmp_path))
    assert not all(c["ok"] for c in checks)
    assert "secret-key" not in str(checks)
