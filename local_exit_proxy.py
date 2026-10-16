#!/usr/bin/env python3
"""
Per-process egress proxy for brocode.

Listens on 127.0.0.1:1088 and binds every outbound socket to 100.122.152.101,
this host's Tailscale address. Linux ip rule 5200 matches that source address
and looks up table 52, whose default route is dev tailscale0, so the traffic
leaves through the configured Tailscale exit node (relay-1).

Everything else on the host keeps using rule 5260 / lookup main and exits over
Azure eth0. The scoping is per-socket, not host-wide, which is the whole point.

Chrome is pointed here with --proxy-server=http://127.0.0.1:1088.

Run:  python3 local_exit_proxy.py
"""

import asyncio
import sys

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1088
BIND_SOURCE_IP = "100.122.152.101"
WARP_HOST = "127.0.0.1"
WARP_PORT = 40000


def is_warp_available():
    import socket
    try:
        with socket.create_connection((WARP_HOST, WARP_PORT), timeout=0.5):
            return True
    except Exception:
        return False


async def dial_warp_connect(host, port):
    """Establish a CONNECT tunnel through local WARP proxy."""
    remote_reader, remote_writer = await asyncio.open_connection(WARP_HOST, WARP_PORT)
    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("latin1")
    remote_writer.write(req)
    await remote_writer.drain()
    status_line = await remote_reader.readline()
    if not status_line or b" 200 " not in status_line and not status_line.startswith(b"HTTP/1.1 200") and not status_line.startswith(b"HTTP/1.0 200"):
        remote_writer.close()
        await remote_writer.wait_closed()
        raise RuntimeError(f"WARP proxy rejected CONNECT: {status_line.decode(errors='ignore').strip()}")
    while True:
        line = await remote_reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    return remote_reader, remote_writer


async def pipe(reader, writer):
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def dial(host, port):
    """Open an outbound connection pinned to the Tailscale source address."""
    return await asyncio.open_connection(
        host, port, local_addr=(BIND_SOURCE_IP, 0), family=0
    )


async def handle_client(client_reader, client_writer):
    peer = client_writer.get_extra_info("peername")
    try:
        line = await client_reader.readline()
        if not line:
            client_writer.close()
            return

        parts = line.decode("latin1", errors="ignore").strip().split()
        if len(parts) < 2:
            client_writer.close()
            return

        method, target = parts[0], parts[1]

        headers = []
        while True:
            h = await client_reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            headers.append(h)

        if method.upper() == "CONNECT":
            host, _, port_str = target.partition(":")
            port = int(port_str or "443")
            remote_reader = remote_writer = None
            via = ""
            if is_warp_available():
                try:
                    remote_reader, remote_writer = await dial_warp_connect(host, port)
                    via = f"WARP:{WARP_PORT}"
                except Exception as e:
                    print(f"[{peer}] WARP CONNECT {host}:{port} failed: {e}, falling back to Tailscale")

            if remote_reader is None:
                try:
                    remote_reader, remote_writer = await dial(host, port)
                    via = BIND_SOURCE_IP
                except Exception as e:
                    print(f"[{peer}] CONNECT {host}:{port} failed to bind/dial: {e}")
                    client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await client_writer.drain()
                    client_writer.close()
                    return

            print(f"[{peer}] CONNECT {host}:{port} -> via {via}")
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await asyncio.gather(
                pipe(client_reader, remote_writer),
                pipe(remote_reader, client_writer),
            )
            return

        # Plain HTTP proxy request: absolute-form target, forward and relay.
        if target.startswith("http://"):
            rest = target[len("http://"):]
            hostport, _, path = rest.partition("/")
            host, _, port_str = hostport.partition(":")
            port = int(port_str or "80")
            path = "/" + path
        else:
            host_header = next(
                (h.decode("latin1", errors="ignore").split(":", 1)[1].strip()
                 for h in headers if h.lower().startswith(b"host:")),
                "",
            )
            host, _, port_str = host_header.partition(":")
            port = int(port_str or "80")
            path = target

        remote_reader = remote_writer = None
        via = ""
        if is_warp_available():
            try:
                remote_reader, remote_writer = await asyncio.open_connection(WARP_HOST, WARP_PORT)
                via = f"WARP:{WARP_PORT}"
                # For plain HTTP through proxy, send full target
                full_target = target if target.startswith("http://") else f"http://{host}:{port}{path}"
                remote_writer.write(
                    f"{method} {full_target} HTTP/1.1\r\n".encode("latin1")
                    + b"".join(headers)
                    + b"\r\n"
                )
                await remote_writer.drain()
            except Exception as e:
                print(f"[{peer}] WARP HTTP {host}:{port} failed: {e}, falling back to Tailscale")
                remote_reader = remote_writer = None

        if remote_reader is None:
            try:
                remote_reader, remote_writer = await dial(host, port)
                via = BIND_SOURCE_IP
                remote_writer.write(
                    f"{method} {path} HTTP/1.1\r\n".encode("latin1")
                    + b"".join(headers)
                    + b"\r\n"
                )
                await remote_writer.drain()
            except Exception as e:
                print(f"[{peer}] {method} {host}:{port} failed: {e}")
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
                client_writer.close()
                return

        print(f"[{peer}] {method} {host}:{port}{path} -> via {via}")
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
        )
    except Exception as e:
        print(f"[{peer}] handler error: {e}")
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(
        handle_client, LISTEN_HOST, LISTEN_PORT, reuse_address=True
    )
    print(f"brocode egress proxy on {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"binding outbound sockets to {BIND_SOURCE_IP} (Tailscale)")
    print("traffic exits via the configured Tailscale exit node (relay-1)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
