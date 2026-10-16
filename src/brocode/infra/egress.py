"""Explicit, per-browser CONNECT/HTTP proxy. Never adjusts host routes or falls back.

Launch separately: python -m brocode.infra.egress --mode tailscale
(with an explicit --source-ip) or --mode warp. Switch the service explicitly;
doctor refuses unrecognized services or provider-fallback behaviour.
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
HEALTH_PATH = "/__brocode_health__"


@dataclass(frozen=True)
class EgressConfig:
    mode: str
    source_ip: str | None = None
    warp_host: str = WARP_HOST
    warp_port: int = WARP_PORT

    def __post_init__(self):
        import ipaddress
        if self.mode not in {"tailscale", "warp"}:
            raise ValueError("Explicit tailscale or warp mode required")
        if self.mode == "tailscale":
            if not self.source_ip:
                raise ValueError("Tailscale mode requires an explicit --source-ip")
            if ipaddress.ip_address(self.source_ip).version != 4:
                raise ValueError("Tailscale source must be an IPv4 address")
        if self.warp_host not in {"127.0.0.1", "::1"}:
            raise ValueError("WARP upstream must be loopback")
        if not 0 < self.warp_port < 65536:
            raise ValueError("Invalid WARP port")


async def dial_warp_connect(host: str, port: int, config: EgressConfig):
    reader, writer = await asyncio.open_connection(config.warp_host, config.warp_port)
    try:
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
        await writer.drain()
        status = await reader.readline()
        if len(status.split()) < 2 or status.split()[1] != b"200":
            raise ConnectionError("WARP upstream rejected tunnel")
        while (line := await reader.readline()) not in {b"\r\n", b"\n"}:
            if not line:
                raise ConnectionError("WARP upstream closed tunnel")
        return reader, writer
    except BaseException:
        writer.close()
        await writer.wait_closed()
        raise


async def dial(host: str, port: int, config: EgressConfig):
    if config.mode == "warp":
        # No probe-and-fallback: failure is a 502, never a different provider.
        return await dial_warp_connect(host, port, config)
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
    parser.add_argument("--mode", choices=["tailscale", "warp"], required=True)
    parser.add_argument("--host", default=LISTEN_HOST)
    parser.add_argument("--port", type=int, default=LISTEN_PORT)
    parser.add_argument("--source-ip", help="Required IPv4 source for tailscale mode")
    parser.add_argument("--warp-host", default=WARP_HOST)
    parser.add_argument("--warp-port", type=int, default=WARP_PORT)
    args = parser.parse_args()
    asyncio.run(serve(EgressConfig(args.mode, args.source_ip, args.warp_host, args.warp_port), args.host, args.port))


if __name__ == "__main__":
    main()
