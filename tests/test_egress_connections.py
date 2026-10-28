"""Real loopback sockets; no public network, browser, or installed service changes."""

import asyncio
import json
import socket as _socket
from contextlib import asynccontextmanager

import pytest

from brocode.infra import egress
from brocode.infra.preflight import proxy_health


def free_loopback_port():
    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@asynccontextmanager
async def listening(handler):
    tasks = []

    async def connected(reader, writer):
        try:
            await handler(reader, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(
        lambda r, w: tasks.append(asyncio.create_task(connected(r, w))), "127.0.0.1", 0,
    )
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                raise result


async def exchange(port, request):
    async with asyncio.timeout(3):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(request)
            await writer.drain()
            return await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()


def relay_config(port, tmp_path):
    return egress.EgressConfig(
        "tailscale-relay", relay_port=port,
        relay_socket=str(tmp_path / "tailscaled-relay" / "tailscaled.sock"),
        relay_exit_node="synthetic-exit",
    )


async def test_connect_relays_bytes_and_does_not_leak_proxy_credentials(tmp_path):
    observed = []

    async def upstream(reader, writer):
        observed.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await writer.drain()
        observed.append(await reader.readexactly(4))
        writer.write(b"pong")
        await writer.drain()

    async with listening(upstream) as upstream_port:
        config = relay_config(upstream_port, tmp_path)
        async with listening(lambda r, w: egress.handle_client(r, w, config)) as proxy_port:
            result = await exchange(proxy_port, b"CONNECT example.test:443 HTTP/1.1\r\n"
                                    b"Proxy-Authorization: synthetic-secret\r\n\r\nping")
    assert result == b"HTTP/1.1 200 Connection Established\r\n\r\npong"
    assert observed == [b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n", b"ping"]


async def test_plain_http_uses_relay_tunnel_and_preserves_path_query_body(tmp_path):
    observed = []

    async def upstream(reader, writer):
        observed.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await writer.drain()
        observed.append(await reader.readuntil(b"\r\n\r\n"))
        observed.append(await reader.readexactly(4))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone")
        await writer.drain()

    async with listening(upstream) as upstream_port:
        config = relay_config(upstream_port, tmp_path)
        async with listening(lambda r, w: egress.handle_client(r, w, config)) as proxy_port:
            result = await exchange(proxy_port, b"POST http://example.test/check?x=1 HTTP/1.1\r\n"
                                    b"Host: example.test\r\nContent-Length: 4\r\n"
                                    b"Proxy-Authorization: synthetic-secret\r\n"
                                    b"Proxy-Connection: keep-alive\r\n\r\ndata")
    assert result.endswith(b"\r\n\r\ndone")
    assert observed == [b"CONNECT example.test:80 HTTP/1.1\r\nHost: example.test:80\r\n\r\n",
                        b"POST /check?x=1 HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n",
                        b"data"]


@pytest.mark.parametrize("response", [b"HTTP/1.1 403 Forbidden\r\n\r\n",
                                      b"HTTP/1.1 200 OK\r\n", b"garbage 200\r\n\r\n"])
async def test_bad_upstream_returns_502_without_direct_fallback(tmp_path, response):
    direct_connections = []

    async def origin(reader, writer):
        direct_connections.append(True)

    async def upstream(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(response)
        await writer.drain()

    async with listening(origin) as origin_port, listening(upstream) as upstream_port:
        config = relay_config(upstream_port, tmp_path)
        async with listening(lambda r, w: egress.handle_client(r, w, config)) as proxy_port:
            result = await exchange(proxy_port, f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n\r\n".encode())
    assert result.startswith(b"HTTP/1.1 502 Bad Gateway\r\n")
    assert direct_connections == []


async def test_cancelling_relay_handshake_closes_upstream_connection(tmp_path):
    received = asyncio.Event()
    closed = asyncio.Event()

    async def upstream(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        received.set()
        assert await reader.read() == b""
        closed.set()

    async with listening(upstream) as port:
        task = asyncio.create_task(egress.dial("example.test", 443, relay_config(port, tmp_path)))
        try:
            await asyncio.wait_for(received.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(closed.wait(), 3)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("response, match", [
    (b"HTTP/1.1 503 nope\r\n\r\n", "service health"),
    (b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 8193, "too large"),
])
async def test_proxy_health_rejects_non_200_and_oversized(response, match):
    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(response)
        await writer.drain()

    async with listening(handler) as port:
        with pytest.raises(ValueError, match=match):
            await proxy_health(f"http://127.0.0.1:{port}")


async def test_refused_relay_upstream_returns_502_without_direct_fallback(tmp_path):
    touched = []

    async def origin(reader, writer):
        touched.append(True)

    async with listening(origin) as origin_port:
        config = relay_config(free_loopback_port(), tmp_path)
        async with listening(lambda r, w: egress.handle_client(r, w, config)) as proxy_port:
            result = await exchange(proxy_port, f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n\r\n".encode())
    assert result.startswith(b"HTTP/1.1 502 Bad Gateway\r\n")
    assert touched == []


async def test_timed_out_relay_dial_returns_502_without_retry(tmp_path, monkeypatch):
    attempts = []

    async def slow(*args, **kwargs):
        attempts.append((args, kwargs))
        raise TimeoutError("relay dial exceeded budget")

    monkeypatch.setattr(egress, "dial", slow)
    config = relay_config(free_loopback_port(), tmp_path)
    async with listening(lambda r, w: egress.handle_client(r, w, config)) as proxy_port:
        result = await exchange(proxy_port, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
    assert result.startswith(b"HTTP/1.1 502 Bad Gateway\r\n")
    assert len(attempts) == 1
    assert attempts[0][0][:2] == ("example.test", 443)


async def test_relay_dial_brackets_ipv6_authority(monkeypatch, tmp_path):
    dialed, observed = [], []
    port = free_loopback_port()

    async def connect(host, port_, **kwargs):
        dialed.append((host, port_))

        class W:
            def write(self, b): observed.append(b)
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
    _, writer = await egress.dial("::1", 443, relay_config(port, tmp_path))
    writer.close()
    assert dialed == [("127.0.0.1", port)]
    assert observed == [b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"]


async def test_health_response_can_arrive_in_separate_tcp_reads():
    body = json.dumps({"service": "brocode-egress-v1", "mode": "tailscale-relay"}).encode()

    async def upstream(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        await writer.drain()
        await asyncio.sleep(0.02)
        writer.write(body)
        await writer.drain()

    async with listening(upstream) as port:
        health = await proxy_health(f"http://127.0.0.1:{port}")
    assert health["mode"] == "tailscale-relay"
