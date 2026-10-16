"""Async, read-only doctor. No repair, launches, route changes, or secret echoes."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .egress import HEALTH_PATH


def parse_proxy(value: str) -> tuple[str, int]:
    try:
        p = urlsplit(value)
        if (p.scheme != "http" or p.hostname not in {"127.0.0.1", "::1"}
                or not p.port or p.username or p.password or p.path not in {"", "/"}
                or p.query or p.fragment):
            raise ValueError
        return p.hostname, p.port
    except (ValueError, TypeError):
        raise ValueError("HTTP loopback proxy with explicit port, no credentials, required") from None


async def command(*args: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), 10)
    except BaseException:
        proc.kill()
        await proc.wait()
        raise
    if proc.returncode:
        raise RuntimeError("Diagnostic command failed")
    return out.decode(errors="replace")


async def proxy_health(proxy_url: str) -> dict:
    host, port = parse_proxy(proxy_url)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 3)
    try:
        writer.write(f"GET {HEALTH_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), 5)
        head, body = data.split(b"\r\n\r\n", 1)
        if head.split(b"\r\n")[0].split()[1] != b"200":
            raise ValueError("No service health response")
        result = json.loads(body)
        if result.get("service") != "brocode-egress-v1":
            raise ValueError("Unrecognized proxy service")
        return result
    finally:
        writer.close()
        await writer.wait_closed()


def listener_matches(host: str, port: int, mode: str) -> bool:
    import psutil
    for c in psutil.net_connections(kind="inet"):
        if (c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.ip == host
                and c.laddr.port == port and c.pid):
            argv = psutil.Process(c.pid).cmdline()
            return ("brocode.infra.egress" in argv and "--mode" in argv
                    and argv[argv.index("--mode") + 1] == mode)
    return False


async def route_probe(proxy_url: str | None = None, source_ip: str | None = None) -> dict:
    import httpx
    transport = httpx.AsyncHTTPTransport(local_address=source_ip) if source_ip else None
    async with httpx.AsyncClient(
        proxy=proxy_url, transport=transport, trust_env=False, timeout=10,
    ) as client:
        # The same endpoint makes IP equality meaningful across all three paths.
        response = await client.get("https://www.cloudflare.com/cdn-cgi/trace")
        response.raise_for_status()
        result = dict(line.split("=", 1) for line in response.text.splitlines() if "=" in line)
        ipaddress.ip_address(result["ip"])
        return {"ip": result["ip"], "warp": result.get("warp", "off")}


def scoped_rules(rules: list[dict], source_ip: str) -> bool:
    def table(rule, name, number):
        return rule.get("table") in {name, number, str(number)}
    return (
        any(r.get("priority") == 5200 and r.get("src") in {source_ip, source_ip + "/32"}
            and table(r, "52", 52) for r in rules)
        and any(r.get("priority") == 5260 and r.get("src", "all") in {"all", "0.0.0.0/0"}
                and table(r, "main", 254) and not r.get("fwmark") for r in rules)
        and not any(0 < r.get("priority", 0) < 5200 and r.get("src", "all") == "all"
                    and not table(r, "local", 255) for r in rules)
    )


def profile_checks(profile_dir: Path) -> list[dict]:
    def row(name, ok, detail):
        return {"name": name, "ok": bool(ok), "detail": detail}
    out = []
    safe = profile_dir.is_absolute() and not any(p.is_symlink() for p in (profile_dir, *profile_dir.parents))
    out.append(row("profile path", safe, "absolute non-symlink profile" if safe else "unsafe profile path"))
    locked = any(os.path.lexists(profile_dir / n) for n in ("SingletonLock", "SingletonCookie", "SingletonSocket"))
    out.append(row("profile not locked", not locked,
                   "lock present; inspect owner and repair explicitly" if locked else "no Chrome singleton locks"))
    import psutil
    busy = False
    try:
        for proc in psutil.process_iter(["cmdline"]):
            args = proc.info.get("cmdline") or []
            if any(a == f"--user-data-dir={profile_dir}" for a in args):
                busy = True
            if "--user-data-dir" in args:
                i = args.index("--user-data-dir")
                busy |= len(args) > i + 1 and args[i + 1] == str(profile_dir)
        out.append(row("profile process ownership", not busy, "profile already used" if busy else "no profile process"))
    except (psutil.Error, OSError):
        out.append(row("profile process ownership", False, "cannot inspect process ownership"))
    return out


async def preflight(settings, request=None) -> list[dict]:
    """Return {name, ok, detail} checks. All failures are blocking to the caller.

    Network probes prove selected-route IP equality, not just host/proxy inequality.
    No CAPTCHA key is required for observations. Optional solver failures do not
    enable automatic solving or silently weaken action authorization.
    """
    results: list[dict] = []

    def record(name, ok, detail):
        results.append({"name": name, "ok": bool(ok), "detail": detail})

    mode = settings.egress_mode
    record("egress mode", mode in {"tailscale", "warp"},
           mode if mode in {"tailscale", "warp"} else "explicit tailscale or warp required")
    try:
        host, port = parse_proxy(settings.proxy_url)
        record("egress proxy config", True, f"HTTP loopback port {port}")
        matches = await asyncio.to_thread(listener_matches, host, port, mode)
        record("egress proxy listener", matches, "owned explicit-mode proxy" if matches else "missing or unrecognized proxy process")
        health = await proxy_health(settings.proxy_url)
        selected = health.get("mode") == mode and mode in {"tailscale", "warp"}
        record("egress proxy mode", selected, "mode matches" if selected else "proxy mode mismatch")
    except Exception:  # noqa: BLE001 - failed diagnostic must fail closed without secret text
        health = None
        record("egress proxy health", False, "cannot verify explicit-mode listener; legacy fallback proxy is not accepted")

    if health and health.get("mode") == mode and mode in {"tailscale", "warp"}:
        try:
            if mode == "tailscale":
                source = str(ipaddress.ip_address(health["source_ip"]))
                rules = json.loads(await command("ip", "-j", "rule", "show"))
                record("ip rule scoping", scoped_rules(rules, source), "requires exact 5200 source and 5260 main rules")
                routes = json.loads(await command("ip", "-j", "route", "show", "table", "52"))
                record("tailscale route", any(r.get("dst") == "default" and r.get("dev") == "tailscale0" for r in routes),
                       "table 52 default must use tailscale0")
                status = json.loads(await command("tailscale", "status", "--json"))
                record("tailscale exit node", status.get("BackendState") == "Running"
                       and bool(status.get("ExitNodeStatus", {}).get("Online")), "selected exit node must be online")
                expected = await route_probe(source_ip=source)
            else:
                if health.get("warp_host") not in {"127.0.0.1", "::1"}:
                    raise ValueError("Non-local WARP upstream")
                port = int(health["warp_port"])
                if not 0 < port < 65536:
                    raise ValueError("Invalid WARP port")
                warp_host = health["warp_host"]
                authority = f"[{warp_host}]" if ":" in warp_host else warp_host
                expected = await route_probe(proxy_url=f"http://{authority}:{port}")
                record("warp route", expected.get("warp") in {"on", "plus"}, "upstream must report WARP active")
            host_route, proxied = await asyncio.gather(route_probe(), route_probe(proxy_url=settings.proxy_url))
            record("selected route IP", expected["ip"] == proxied["ip"], "proxy IP must equal selected provider route IP")
            record("per-process isolation", host_route["ip"] != proxied["ip"], "host IP must differ from browser proxy IP")
        except Exception:  # noqa: BLE001 - external diagnostic failure is blocking
            record("selected route health", False, "route/IP health could not be independently verified")

    try:
        version = await command(str(settings.chrome_path), "--version")
        record("chrome binary", "Google Chrome" in version, "Google Chrome required")
    except Exception:  # noqa: BLE001 - external diagnostic failure is blocking
        record("chrome binary", False, "Google Chrome binary unavailable")
    display = getattr(settings, "display", os.environ.get("DISPLAY", ""))
    try:
        # X socket presence alone does not establish authentication or a responsive server.
        await command("xdpyinfo", "-display", display)
        record("display", bool(display), "existing responsive display required")
    except Exception:  # noqa: BLE001 - external diagnostic failure is blocking
        record("display", False, "start/authenticate an X display explicitly before running")
    results.extend(await asyncio.to_thread(profile_checks, Path(settings.profile_dir)))
    for name, value in (("root", settings.root), ("state", settings.state_dir)):
        p = Path(value)
        safe = p.is_absolute() and not any(q.is_symlink() for q in (p, *p.parents))
        record(f"{name} path", safe, "absolute non-symlink directory required")
    record("model credentials", bool(settings.model and settings.base_url and settings.api_key), "model endpoint and key must be configured")
    if request is not None:
        record("domain scope", bool(request.policy.allowed_domains), "explicit exact domain allowlist required")
        model = request.model or settings.model
        weak = "flash" in model.lower()
        record("model fit for goal", not (weak and request.policy.mode == "confirm"),
               "interaction goals require a non-flash model")
    # The legacy callback injector is not safe for single-attempt writes.
    record("captcha policy", True, "automatic solving disabled; challenges fail closed")
    return results
