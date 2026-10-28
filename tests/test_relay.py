"""Synthetic tests for isolated tailscale-relay egress. No network, browser, or host changes."""

import os
import socket as _socket

import pytest

from brocode.infra import browser as bi
from brocode.infra import egress
from brocode.infra import preflight as pf

RELAY_SOCKET = "/tmp/brocode-test/var/tailscaled-relay/tailscaled.sock"
RELAY_STATE_ROOT = "/tmp/brocode-test/var/tailscaled-relay"
RELAY_EXIT = "exit-node-1"
RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8080


def relay_config(**over):
    base = {"mode": "tailscale-relay", "relay_host": RELAY_HOST, "relay_port": RELAY_PORT,
            "relay_socket": RELAY_SOCKET, "relay_exit_node": RELAY_EXIT}
    base.update(over)
    return egress.EgressConfig(**base)


def test_relay_requires_socket_and_exit_identity():
    with pytest.raises(ValueError, match="relay-socket"):
        egress.EgressConfig("tailscale-relay", relay_exit_node=RELAY_EXIT)
    with pytest.raises(ValueError, match="relay-exit-node"):
        egress.EgressConfig("tailscale-relay", relay_socket=RELAY_SOCKET)


@pytest.mark.parametrize("sock", ["/var/run/tailscale/tailscaled.sock",
                                  "/run/tailscale/tailscaled.sock",
                                  "/var/run/tailscale/other.sock",
                                  "relative.sock", ""])
def test_relay_rejects_host_or_nonabsolute_socket(sock):
    with pytest.raises(ValueError, match="[Aa]bsolute|host|explicit|symlink|canonical|private|traversal|alias"):
        relay_config(relay_socket=sock)


@pytest.mark.parametrize("sock", ["/run/../run/tailscale/tailscaled.sock",
                                  "//run/tailscale-relay/tailscaled.sock",
                                  "/tmp/brocode-test/var/tailscaled-relay/../tailscaled-relay/tailscaled.sock",
                                  "/tmp//brocode-test/var/tailscaled-relay/tailscaled.sock"])
def test_relay_rejects_traversal_and_alias_socket(sock):
    with pytest.raises(ValueError, match="traversal|alias|canonical|doubled"):
        relay_config(relay_socket=sock)


def test_relay_rejects_symlink_parent(tmp_path):
    real = tmp_path / "real" / "tailscaled-relay"
    real.mkdir(parents=True)
    link = tmp_path / "link"
    try:
        link.symlink_to(tmp_path / "real", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symlink"):
        egress.validate_relay_socket(str(link / "tailscaled-relay" / "tailscaled.sock"))


def test_relay_socket_canonical_returned_and_used(tmp_path):
    relay_dir = tmp_path / "var" / "tailscaled-relay"
    relay_dir.mkdir(parents=True)
    sock = str(relay_dir / "tailscaled.sock")
    canonical = egress.validate_relay_socket(sock, str(tmp_path / "var"))
    assert canonical == os.path.realpath(sock)
    cfg = egress.EgressConfig("tailscale-relay", relay_host=RELAY_HOST, relay_port=RELAY_PORT,
                              relay_socket=sock, relay_exit_node=RELAY_EXIT)
    assert cfg.relay_socket == canonical
    with pytest.raises(ValueError, match="private|tailscaled-relay"):
        egress.validate_relay_socket(str(tmp_path / "other.sock"), str(tmp_path / "var"))
    with pytest.raises(ValueError, match="private|tailscaled-relay"):
        egress.validate_relay_socket("/tmp/other/tailscaled.sock")


@pytest.mark.parametrize("kwargs", [{"relay_host": "10.0.0.1"}, {"relay_host": "example.test"},
                                    {"relay_port": 0}, {"relay_port": 70000}])
def test_relay_rejects_nonloopback_or_bad_port(kwargs):
    with pytest.raises(ValueError, match="[Ll]oopback|[Pp]ort"):
        relay_config(**kwargs)


def test_positional_compatibility_preserved():
    legacy_tls = egress.EgressConfig("tailscale", "100.64.0.10", "127.0.0.1", 40000)
    assert legacy_tls.source_ip == "100.64.0.10"
    assert legacy_tls.warp_port == 40000
    assert egress.EgressConfig("warp").source_ip is None
    full = egress.EgressConfig("tailscale-relay", None, "127.0.0.1", 40000,
                               RELAY_HOST, RELAY_PORT, RELAY_SOCKET, RELAY_EXIT)
    assert full.relay_socket == RELAY_SOCKET and full.relay_exit_node == RELAY_EXIT


async def test_relay_dial_never_falls_back(monkeypatch):
    calls = []

    async def connect(host, port, **kwargs):
        calls.append((host, port))
        if (host, port) != (RELAY_HOST, RELAY_PORT):
            raise AssertionError("relay must only dial its loopback upstream")

        class W:
            def write(self, b): self.sent = b
            async def drain(self): pass
            def close(self): pass
            async def wait_closed(self): pass
        class R:
            def __init__(self): self.n = 0
            async def readline(self):
                self.n += 1
                return b"HTTP/1.1 200 OK\r\n" if self.n == 1 else b"\r\n"
        return R(), W()

    monkeypatch.setattr(egress.asyncio, "open_connection", connect)
    await egress.dial("example.com", 443, relay_config())
    assert calls == [(RELAY_HOST, RELAY_PORT)]


async def test_relay_upstream_rejection_does_not_dial_direct(monkeypatch):
    calls = []

    async def connect(host, port, **kwargs):
        calls.append((host, port))

        class W:
            def write(self, b): pass
            async def drain(self): pass
            def close(self): pass
            async def wait_closed(self): pass
        class R:
            async def readline(self): return b"HTTP/1.1 403 Forbidden\r\n"
        return R(), W()

    monkeypatch.setattr(egress.asyncio, "open_connection", connect)
    with pytest.raises(ConnectionError, match="Relay upstream"):
        await egress.dial("example.com", 443, relay_config())
    assert calls == [(RELAY_HOST, RELAY_PORT)]


def test_exit_identity_matching():
    running = {"BackendState": "Running",
               "ExitNodeStatus": {"ID": RELAY_EXIT, "Online": True, "TailscaleIPs": ["100.64.0.9/32"]},
               "Peer": {"k": {"ID": RELAY_EXIT, "TailscaleIPs": ["100.64.0.9"],
                              "HostName": "exitbox", "DNSName": "exitbox.tail.test.", "ExitNode": True}}}
    assert pf.relay_exit_matches(running, RELAY_EXIT)
    assert pf.relay_exit_matches(running, "100.64.0.9")
    assert pf.relay_exit_matches(running, "exitbox")
    assert pf.relay_exit_matches(running, "exitbox.tail.test.")
    assert not pf.relay_exit_matches(running, "other-node")
    assert not pf.relay_exit_matches({"BackendState": "Running"}, RELAY_EXIT)
    assert not pf.relay_exit_matches(running, "")


def test_exit_identity_requires_nonempty_id():
    assert not pf.relay_exit_matches(
        {"ExitNodeStatus": {"ID": "", "Online": True, "TailscaleIPs": ["100.64.0.9/32"]},
         "Peer": {"k": {"ID": "", "TailscaleIPs": ["100.64.0.9"], "HostName": "exitbox", "ExitNode": True}}},
        "exitbox")
    assert not pf.relay_exit_matches({"ExitNodeStatus": {}}, RELAY_EXIT)


def test_exit_identity_rejects_mismatch_peer():
    status = {"BackendState": "Running",
              "ExitNodeStatus": {"ID": "node-A", "Online": True, "TailscaleIPs": ["100.64.0.9/32"]},
              "Peer": {
                  "a": {"ID": "node-A", "TailscaleIPs": ["100.64.0.9"], "HostName": "realexit",
                        "DNSName": "realexit.tail.test.", "ExitNode": True},
                  "b": {"ID": "node-B", "TailscaleIPs": ["100.64.0.99"], "HostName": "impostor",
                        "DNSName": "impostor.tail.test.", "ExitNode": True}}}
    assert pf.relay_exit_matches(status, "node-A")
    assert pf.relay_exit_matches(status, "realexit")
    assert not pf.relay_exit_matches(status, "impostor")
    assert not pf.relay_exit_matches(status, "100.64.0.99")
    assert not pf.relay_exit_matches(status, "node-B")


def test_exit_identity_rejects_contradictory_flags():
    status = {"BackendState": "Running",
              "ExitNodeStatus": {"ID": "node-A", "Online": True, "TailscaleIPs": ["100.64.0.9/32"]},
              "Peer": {"a": {"ID": "node-A", "TailscaleIPs": ["100.64.0.9"], "HostName": "realexit",
                             "DNSName": "realexit.tail.test.", "ExitNode": False}}}
    assert not pf.relay_exit_matches(status, "realexit")
    assert not pf.relay_exit_matches(status, "100.64.0.9")
    # Direct StableNodeID match with contradictory same-ID peer must fail closed.
    assert not pf.relay_exit_matches(status, "node-A")


def test_exit_address_requires_matching_peer_identity():
    status = {"ExitNodeStatus": {"ID": "node-A", "Online": True,
                                "TailscaleIPs": ["100.64.0.9/32"]},
              "Peer": {"other": {"ID": "node-B", "ExitNode": True,
                                  "TailscaleIPs": ["100.64.0.9"]}}}
    assert not pf.relay_exit_matches(status, "100.64.0.9")
    status["Peer"] = {}
    assert not pf.relay_exit_matches(status, "100.64.0.9")


@pytest.mark.parametrize("failed_route", ["upstream", "proxy", "host"])
async def test_online_relay_with_unreachable_route_blocks(tmp_path, monkeypatch, failed_route):
    def probe(proxy_url):
        route = "host" if proxy_url is None else "proxy" if ":1089" in proxy_url else "upstream"
        if route == failed_route:
            raise TimeoutError("private network details")
        return {"ip": "198.51.100.9" if route == "host" else "203.0.113.7", "warp": "off"}

    _mock_relay(monkeypatch, probe=probe)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert any(c["name"] == "selected route health" and not c["ok"] for c in checks)
    assert "private network details" not in str(checks)


def _relay_settings(tmp_path, relay_socket=RELAY_SOCKET):
    from pathlib import Path
    from types import SimpleNamespace
    # Keep the socket under <state_dir>/tailscaled-relay so private-root checks pass.
    state_dir = Path(relay_socket).parent.parent
    return SimpleNamespace(root=tmp_path, state_dir=state_dir, profile_dir=tmp_path / "profile",
                           proxy_url="http://127.0.0.1:1089", egress_mode="tailscale-relay",
                           model="m", base_url="https://api.example.test/v1", api_key="k",
                           chrome_path="/chrome", display=":99")


def _mock_relay(monkeypatch, *, status=None, probe=None, process_ok=True, listener=True,
                relay_socket=RELAY_SOCKET):
    import json as _json
    status = status if status is not None else {
        "BackendState": "Running",
        "ExitNodeStatus": {"ID": RELAY_EXIT, "Online": True, "TailscaleIPs": ["100.64.0.9/32"]}}
    seen = {"bare_host_status": False, "socket_scoped": False}

    async def command(*args):
        if args[0] == "/chrome":
            return "Google Chrome 123"
        if args[0] == "xdpyinfo":
            return "ok"
        if args[:2] == ("tailscale", "status"):
            seen["bare_host_status"] = True
            raise AssertionError("relay must never use bare host tailscale status")
        if args[:2] == ("tailscale", "--socket"):
            assert args[2] == relay_socket, args
            seen["socket_scoped"] = True
            return _json.dumps(status)
        raise AssertionError(args)

    async def health(url):
        return {"service": "brocode-egress-v1", "mode": "tailscale-relay",
                "relay_host": RELAY_HOST, "relay_port": RELAY_PORT,
                "relay_socket": relay_socket, "relay_exit_node": RELAY_EXIT}

    async def route(proxy_url=None, source_ip=None):
        assert source_ip is None, "relay must not bind a host source IP"
        if probe:
            return probe(proxy_url)
        if proxy_url is None:
            return {"ip": "198.51.100.9", "warp": "off"}
        return {"ip": "203.0.113.7", "warp": "off"}

    monkeypatch.setattr(pf, "command", command)
    monkeypatch.setattr(pf, "proxy_health", health)
    monkeypatch.setattr(pf, "route_probe", route)
    monkeypatch.setattr(pf, "listener_matches", lambda *_: listener)
    monkeypatch.setattr(pf, "relay_process_check", lambda *a: (process_ok, "ok" if process_ok else "no owner"))
    return seen


async def test_relay_healthy_and_socket_scoped(tmp_path, monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    seen = _mock_relay(monkeypatch)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert all(c["ok"] for c in checks), checks
    assert seen["socket_scoped"] and not seen["bare_host_status"]


async def test_relay_isolation_failure_blocks(tmp_path, monkeypatch):
    def probe(proxy_url=None, source_ip=None):
        return {"ip": "203.0.113.7", "warp": "off"}  # host equals proxy: no isolation
    _mock_relay(monkeypatch, probe=probe)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert any(c["name"] == "per-process isolation" and not c["ok"] for c in checks)


@pytest.mark.parametrize("status", [
    {"BackendState": "Running"},  # exit missing
    {"BackendState": "Running", "ExitNodeStatus": {"ID": RELAY_EXIT, "Online": False}},  # offline
    {"BackendState": "NeedsLogin", "ExitNodeStatus": {"ID": RELAY_EXIT, "Online": True}},
    {"BackendState": "Running",
     "ExitNodeStatus": {"ID": "someone-else", "Online": True, "TailscaleIPs": ["100.64.0.99/32"]}},  # mismatch
])
async def test_relay_exit_missing_offline_mismatch_blocks(tmp_path, monkeypatch, status):
    _mock_relay(monkeypatch, status=status)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert not all(c["ok"] for c in checks), checks
    names = {c["name"] for c in checks if not c["ok"]}
    assert names & {"relay exit node", "relay exit identity", "selected route health"}


async def test_relay_wrong_listener_or_process_blocks(tmp_path, monkeypatch):
    _mock_relay(monkeypatch, listener=False)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert any(c["name"] == "egress proxy listener" and not c["ok"] for c in checks)
    _mock_relay(monkeypatch, process_ok=False)
    checks = await pf.preflight(_relay_settings(tmp_path))
    assert any(c["name"] == "relay tailscaled" and not c["ok"] for c in checks)


class _FakeConns:
    def __init__(self, unix_sock, host, port, *, unix_ok=True, inet_ok=True):
        self._unix = unix_sock
        self._host = host
        self._port = port
        self._unix_ok = unix_ok
        self._inet_ok = inet_ok

    def __call__(self, kind="all"):
        from collections import namedtuple
        S = namedtuple("sconn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])
        out = []
        if self._unix_ok:
            out.append(S(-1, 1, 1, self._unix, "", "NONE", 1234))
        if self._inet_ok:
            out.append(S(-1, 2, 1, (self._host, self._port), (), "LISTEN", 1234))
        elif self._inet_ok is False and kind in ("all", "inet"):
            out.append(S(-1, 2, 1, (self._host, self._port + 1), (), "LISTEN", 1234))
        return out


class _FakeProc:
    def __init__(self, argv, *, exe="/usr/sbin/tailscaled", uid=None, conns=None):
        self.info = {"cmdline": argv}
        self._exe = exe
        self._uid = uid
        self._conns = conns if conns is not None else []
        self.pid = 1234

    def exe(self):
        if self._exe is None:
            raise OSError("no exe")
        return self._exe

    def uids(self):
        from collections import namedtuple
        U = namedtuple("uids", ["real", "effective", "saved"])
        if self._uid is None:
            raise OSError("no uids")
        return U(self._uid, self._uid, self._uid)

    def net_connections(self, kind="all"):
        if callable(self._conns):
            return self._conns(kind)
        return self._conns


def _setup_relay_daemon(monkeypatch, tmp_path, *, argv_style="equals", extra=None):
    """Create a real private relay dir + UNIX socket and mock exe/which/procs."""
    relay_dir = tmp_path / "var" / "tailscaled-relay"
    relay_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(relay_dir, 0o700)
        os.chmod(tmp_path / "var", 0o700)
    except OSError:
        pass
    sock = str(relay_dir / "tailscaled.sock")
    try:
        os.unlink(sock)
    except FileNotFoundError:
        pass
    srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    srv.bind(sock)
    try:
        os.chmod(sock, 0o600)
    except OSError:
        pass
    state_dir = str(tmp_path / "var")
    state_file = str(relay_dir / "tailscaled.state")
    statedir = str(relay_dir)
    if argv_style == "equals":
        argv = ["tailscaled", f"--socket={sock}", "--tun=userspace-networking",
                f"--outbound-http-proxy-listen={RELAY_HOST}:{RELAY_PORT}",
                f"--state={state_file}", f"--statedir={statedir}"]
    else:
        argv = ["tailscaled", "--socket", sock, "--tun", "userspace-networking",
                "--outbound-http-proxy-listen", f"{RELAY_HOST}:{RELAY_PORT}",
                "--state", state_file, "--statedir", statedir]
    if extra:
        argv = argv + extra
    uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    conns = _FakeConns(sock, RELAY_HOST, RELAY_PORT)
    proc = _FakeProc(argv, exe="/usr/sbin/tailscaled", uid=uid, conns=conns)
    import shutil

    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: [proc])
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/sbin/tailscaled" if name == "tailscaled" else None)
    # psutil.Process().exe realpath check uses os.path.realpath; keep exe stable.
    monkeypatch.setattr(os.path, "realpath", _realpath_no_symlink_wrap(sock, statedir, state_file))
    return sock, state_dir, srv, proc


def _realpath_no_symlink_wrap(*stable):
    real = os.path.realpath
    stable_set = {os.path.normpath(s) for s in stable}
    stable_set |= {"/usr/sbin/tailscaled"}

    def _wrap(p):
        try:
            rp = real(p)
        except OSError:
            return p
        return rp
    return _wrap


def test_relay_process_check_parses_flags(monkeypatch, tmp_path):
    sock, state_dir, srv, _ = _setup_relay_daemon(monkeypatch, tmp_path, argv_style="equals")
    try:
        ok, _ = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert ok
    finally:
        srv.close()
    sock2, state_dir2, srv2, _ = _setup_relay_daemon(monkeypatch, tmp_path, argv_style="space")
    try:
        ok, _ = pf.relay_process_check(sock2, RELAY_HOST, RELAY_PORT, state_dir2)
        assert ok
    finally:
        srv2.close()


def test_relay_process_check_rejects_bad_tun(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path, argv_style="space")
    try:
        proc.info["cmdline"] = [a if a != "userspace-networking" else "tailscale0" for a in proc.info["cmdline"]]
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "userspace" in detail
    finally:
        srv.close()


def test_relay_process_check_rejects_listener_mismatch(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        proc._conns = _FakeConns(sock, RELAY_HOST, RELAY_PORT, unix_ok=True, inet_ok=False)
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "proxy listen" in detail
    finally:
        srv.close()


def test_relay_process_check_rejects_fake_executable(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        proc._exe = "/tmp/evil/tailscaled"
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "executable" in detail
    finally:
        srv.close()


def test_relay_process_check_rejects_wrong_uid(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        proc._uid = uid + 1 if uid + 1 < 60000 else uid - 1
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "UID" in detail
    finally:
        srv.close()


def test_relay_process_check_rejects_host_state(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        argv = list(proc.info["cmdline"])
        out = []
        skip_next = False
        for i, a in enumerate(argv):
            if skip_next:
                skip_next = False
                continue
            if a.startswith("--statedir="):
                out.append("--statedir=/var/lib/tailscale")
            elif a == "--statedir":
                out.append("--statedir=/var/lib/tailscale")
                skip_next = True
            elif a.startswith("--state="):
                out.append("--state=/var/lib/tailscale/tailscaled.state")
            elif a == "--state":
                out.append("--state=/var/lib/tailscale/tailscaled.state")
                skip_next = True
            else:
                out.append(a)
        proc.info["cmdline"] = out
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "state" in detail.lower()
    finally:
        srv.close()


def test_relay_process_check_rejects_alias_socket(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        alias = sock.replace("/tailscaled-relay/", "/tailscaled-relay/../tailscaled-relay/")
        argv = list(proc.info["cmdline"])
        proc.info["cmdline"] = [alias if a == sock or a == f"--socket={sock}" else a for a in argv]
        # Normalize the equals form if present.
        fixed = []
        for a in proc.info["cmdline"]:
            if a.startswith("--socket="):
                fixed.append(f"--socket={alias}")
            else:
                fixed.append(a)
        proc.info["cmdline"] = fixed
        ok, _ = pf.relay_process_check(alias, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok
    finally:
        srv.close()


def test_relay_process_check_rejects_duplicate_flags(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path, argv_style="space")
    try:
        proc.info["cmdline"] = proc.info["cmdline"] + ["--socket", sock]
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "duplicate" in detail
    finally:
        srv.close()
    sock2, state_dir2, srv2, proc2 = _setup_relay_daemon(monkeypatch, tmp_path, argv_style="equals")
    try:
        proc2.info["cmdline"] = proc2.info["cmdline"] + ["--socket", sock2]
        ok, detail = pf.relay_process_check(sock2, RELAY_HOST, RELAY_PORT, state_dir2)
        assert not ok and "duplicate" in detail
    finally:
        srv2.close()


def test_relay_process_check_rejects_missing_unix_owner(monkeypatch, tmp_path):
    sock, state_dir, srv, proc = _setup_relay_daemon(monkeypatch, tmp_path)
    try:
        proc._conns = _FakeConns(sock, RELAY_HOST, RELAY_PORT, unix_ok=False, inet_ok=True)
        ok, detail = pf.relay_process_check(sock, RELAY_HOST, RELAY_PORT, state_dir)
        assert not ok and "owns" in detail
    finally:
        srv.close()


def test_browser_accepts_relay_mode(monkeypatch):
    monkeypatch.setenv("DISPLAY", ":99")
    kwargs = bi.browser_kwargs(proxy_url="http://127.0.0.1:1089", egress_mode="tailscale-relay",
                               chrome_path="/chrome")
    assert kwargs["proxy"] == {"server": "http://127.0.0.1:1089"}
    with pytest.raises(ValueError):
        bi.browser_kwargs(proxy_url="http://127.0.0.1:1089", egress_mode="socks", chrome_path="/chrome")
