"""Explicit, per-browser CONNECT/HTTP proxy. Never adjusts host routes or falls back.

Launch separately: python -m brocode.infra.egress --mode tailscale
(with an explicit --source-ip), --mode warp, or --mode tailscale-relay
(with explicit --relay-host/--relay-port/--relay-socket/--relay-exit-node
pointing at a SEPARATE userspace tailscaled outbound proxy; never the host
tailscaled socket/state). Switch the service explicitly; doctor refuses
unrecognized services or provider-fallback behaviour.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1088
WARP_HOST = "127.0.0.1"
WARP_PORT = 40000
RELAY_HOST = "127.0.0.1"
RELAY_PORT = 8080
HEALTH_PATH = "/__brocode_health__"

# Sockets/state owned by the host tailscaled. A relay must never reuse these.
HOST_SOCKET_PREFIXES = ("/var/run/tailscale", "/run/tailscale")
HOST_SOCKET_EXACT = {
    "/var/run/tailscale/tailscaled.sock",
    "/run/tailscale/tailscaled.sock",
}

EGRESS_MODES = {"tailscale", "warp", "tailscale-relay"}
LOOPBACK_HOSTS = {"127.0.0.1", "::1"}


def _check_port(name: str, port: int) -> None:
    if not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError(f"Invalid {name} port")


def validate_relay_socket(value: str, state_dir: str | None = None) -> str:
    """Validate an isolated relay socket path and return its canonical form.

    Fail-closed rules: absolute, no traversal (``.``/``..``), no ``//``
    aliases (including doubled leading slash), no symlink components, and
    canonical exclusion of the host tailscaled socket/state. The socket must
    live under the private ``tailscaled-relay`` state root: when ``state_dir``
    is given, under ``<state_dir>/tailscaled-relay``; otherwise the canonical
    path must still contain a ``tailscaled-relay`` component. Callers must use
    the returned canonical value for all later checks. Never reads file data.
    """
    import os
    from pathlib import Path
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Relay socket must be an absolute path")
    if value.startswith("//"):
        raise ValueError("Relay socket must not use doubled leading slash")
    if "//" in value:
        raise ValueError("Relay socket must be canonical (no alias)")
    if not Path(value).is_absolute():
        raise ValueError("Relay socket must be an absolute path")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Relay socket must not contain traversal")
    if value.endswith("/"):
        raise ValueError("Relay socket must be canonical (no alias)")
    normalized = os.path.normpath(value)
    if normalized != value:
        raise ValueError("Relay socket must be canonical (no traversal/alias)")
    for part_index in range(1, len(Path(value).parts)):
        prefix = str(Path(*Path(value).parts[: part_index + 1]))
        try:
            if os.path.islink(prefix):
                raise ValueError("Relay socket path must not contain symlinks")
        except OSError:
            raise ValueError("cannot inspect relay socket path")
    try:
        if os.path.lexists(value) and os.path.islink(value):
            raise ValueError("Relay socket path must not contain symlinks")
    except OSError:
        raise ValueError("cannot inspect relay socket path")
    canonical = os.path.realpath(value)
    if canonical.startswith("//") or canonical != os.path.normpath(canonical):
        raise ValueError("Relay socket must be canonical (no traversal/alias)")
    host_prefixes = set()
    for raw in HOST_SOCKET_PREFIXES:
        host_prefixes.add(raw)
        try:
            host_prefixes.add(os.path.realpath(raw))
        except OSError:
            pass
    host_exact = set(HOST_SOCKET_EXACT)
    for raw in HOST_SOCKET_EXACT:
        try:
            host_exact.add(os.path.realpath(raw))
        except OSError:
            pass
    if canonical in host_exact:
        raise ValueError("Relay socket must not reuse the host tailscaled socket")
    if any(canonical == hp or canonical.startswith(hp.rstrip("/") + "/") for hp in host_prefixes):
        raise ValueError("Relay socket must not reuse host tailscale state")
    if state_dir is not None:
        if not isinstance(state_dir, str) or not state_dir or "\x00" in state_dir:
            raise ValueError("Relay state dir must be an absolute path")
        if state_dir.startswith("//") or "//" in state_dir:
            raise ValueError("Relay state dir must be canonical (no alias)")
        if not os.path.isabs(state_dir):
            raise ValueError("Relay state dir must be an absolute path")
        if any(part in {".", ".."} for part in state_dir.split("/")):
            raise ValueError("Relay state dir must not contain traversal")
        expected_root = os.path.realpath(os.path.join(os.path.normpath(state_dir), "tailscaled-relay"))
        if not (canonical == expected_root or canonical.startswith(expected_root.rstrip("/") + "/")):
            raise ValueError("Relay socket must live under <state_dir>/tailscaled-relay")
    else:
        if "tailscaled-relay" not in Path(canonical).parts:
            raise ValueError("Relay socket must live under private tailscaled-relay state")
    return canonical


@dataclass(frozen=True)
class EgressConfig:
    mode: str
    source_ip: str | None = None
    warp_host: str = WARP_HOST
    warp_port: int = WARP_PORT
    relay_host: str = RELAY_HOST
    relay_port: int = RELAY_PORT
    relay_socket: str | None = None
    relay_exit_node: str | None = None

    def __post_init__(self):
        import ipaddress
        if self.mode not in EGRESS_MODES:
            raise ValueError("Explicit tailscale, warp, or tailscale-relay mode required")
        if self.mode == "tailscale":
            if not self.source_ip:
                raise ValueError("Tailscale mode requires an explicit --source-ip")
            if ipaddress.ip_address(self.source_ip).version != 4:
                raise ValueError("Tailscale source must be an IPv4 address")
        if self.warp_host not in LOOPBACK_HOSTS:
            raise ValueError("WARP upstream must be loopback")
        _check_port("WARP", self.warp_port)
        if self.mode == "tailscale-relay":
            if self.relay_host not in LOOPBACK_HOSTS:
                raise ValueError("Relay upstream must be loopback")
            _check_port("Relay", self.relay_port)
            if not self.relay_socket:
                raise ValueError("tailscale-relay mode requires an explicit --relay-socket")
            canonical_socket = validate_relay_socket(self.relay_socket)
            object.__setattr__(self, "relay_socket", canonical_socket)
            if not self.relay_exit_node or not self.relay_exit_node.strip():
                raise ValueError("tailscale-relay mode requires an explicit --relay-exit-node")
            expected = self.relay_exit_node.strip()
            if len(expected) > 253 or any(c.isspace() for c in expected):
                raise ValueError("Invalid relay exit-node identity")


async def dial_warp_connect(host: str, port: int, config: EgressConfig):
    reader, writer = await asyncio.open_connection(config.warp_host, config.warp_port)
    try:
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        await writer.drain()
        status = await reader.readline()
        parts = status.split()
        if len(parts) < 2 or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"} or parts[1] != b"200":
            raise ConnectionError("WARP upstream rejected tunnel")
        while (line := await reader.readline()) not in {b"\r\n", b"\n"}:
            if not line:
                raise ConnectionError("WARP upstream closed tunnel")
        return reader, writer
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise


async def dial_relay_connect(host: str, port: int, config: EgressConfig):
    reader, writer = await asyncio.open_connection(config.relay_host, config.relay_port)
    try:
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        await writer.drain()
        status = await reader.readline()
        parts = status.split()
        if len(parts) < 2 or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"} or parts[1] != b"200":
            raise ConnectionError("Relay upstream rejected tunnel")
        while (line := await reader.readline()) not in {b"\r\n", b"\n"}:
            if not line:
                raise ConnectionError("Relay upstream closed tunnel")
        return reader, writer
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise


async def dial(host: str, port: int, config: EgressConfig):
    if config.mode == "warp":
        # No probe-and-fallback: failure is a 502, never a different provider.
        return await dial_warp_connect(host, port, config)
    if config.mode == "tailscale-relay":
        # No fallback to direct or another provider: failure is a 502.
        return await dial_relay_connect(host, port, config)
    return await asyncio.open_connection(host, port, local_addr=(config.source_ip, 0))


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def handle_client(reader, writer, config: EgressConfig):
    remote = None
    try:
        line = await asyncio.wait_for(reader.readline(), 10)
        parts = line.decode("latin1").strip().split()
        if len(parts) != 3:
            return
        method, target, _ = parts
        headers = []
        for _ in range(100):
            h = await asyncio.wait_for(reader.readline(), 10)
            if h in {b"\r\n", b"\n", b""}:
                break
            if len(h) > 8192:
                return
            # Hop-specific headers must not leak into the origin tunnel.
            if not h.lower().startswith((b"proxy-authorization:", b"proxy-connection:")):
                headers.append(h)
        else:
            return
        if method == "GET" and target == HEALTH_PATH:
            data = json.dumps({"service": "brocode-egress-v1", **config.__dict__}).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                         + f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
            await writer.drain()
            return
        if method == "CONNECT":
            p = urlsplit("//" + target)
            host, port = p.hostname, p.port or 443
            path = None
        else:
            p = urlsplit(target)
            if p.scheme != "http" or p.username or p.password:
                raise ValueError("Absolute plain HTTP URL required")
            host, port = p.hostname, p.port or 80
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
        if not host:
            raise ValueError("Missing host")
        upstream, remote = await asyncio.wait_for(dial(host, port, config), 15)
        if method == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            remote.write(f"{method} {path} HTTP/1.1\r\n".encode("latin1") + b"".join(headers) + b"\r\n")
            await remote.drain()
        await asyncio.gather(pipe(reader, remote), pipe(upstream, writer))
    except (ValueError, OSError, TimeoutError, ConnectionError):
        try:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except (OSError, ConnectionError):
            pass
    finally:
        if remote:
            remote.close()
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def serve(config: EgressConfig, host: str = LISTEN_HOST, port: int = LISTEN_PORT):
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("Proxy must listen on loopback")
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), host, port)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(EGRESS_MODES), required=True)
    parser.add_argument("--host", default=LISTEN_HOST)
    parser.add_argument("--port", type=int, default=LISTEN_PORT)
    parser.add_argument("--source-ip", help="Required IPv4 source for tailscale mode")
    parser.add_argument("--warp-host", default=WARP_HOST)
    parser.add_argument("--warp-port", type=int, default=WARP_PORT)
    parser.add_argument("--relay-host", default=RELAY_HOST, help="Loopback outbound proxy of the isolated userspace tailscaled")
    parser.add_argument("--relay-port", type=int, default=RELAY_PORT)
    parser.add_argument("--relay-socket", default=None, help="Absolute socket of the isolated userspace tailscaled (never host socket)")
    parser.add_argument("--relay-exit-node", default=None, help="Expected exit-node identity for tailscale-relay mode")
    args = parser.parse_args()
    asyncio.run(serve(EgressConfig(args.mode, args.source_ip, args.warp_host, args.warp_port,
                                   args.relay_host, args.relay_port, args.relay_socket,
                                   args.relay_exit_node), args.host, args.port))


if __name__ == "__main__":
    main()
