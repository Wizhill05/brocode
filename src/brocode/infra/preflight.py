"""Async, read-only doctor. No repair, launches, route changes, or secret echoes."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from .egress import HEALTH_PATH, LOOPBACK_HOSTS, validate_relay_socket


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
        data = bytearray()
        async with asyncio.timeout(5):
            while chunk := await reader.read(8193 - len(data)):
                data.extend(chunk)
                if len(data) > 8192:
                    raise ValueError("Proxy health response too large")
        head, body = data.split(b"\r\n\r\n", 1)
        if head.split(b"\r\n")[0].split()[1] != b"200":
            raise ValueError("No service health response")
        result = json.loads(body)
        if not isinstance(result, dict) or result.get("service") != "brocode-egress-v1":
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


def _strip_prefix(value: str) -> str:
    return str(value).split("/")[0].strip().lower()


def relay_exit_matches(status: dict, expected: str) -> bool:
    """Match expected exit identity against socket-scoped status.

    Schema per ipn/ipnstate/ipnstate.go: Status.ExitNodeStatus carries
    {ID: StableNodeID, Online, TailscaleIPs: []Prefix}, while Peer entries
    (keyed by node public key) carry {ID, TailscaleIPs: []Addr, HostName,
    DNSName, ExitNode}. TailscaleIPs entries may be Prefix ("100.x/32") or
    Addr ("100.x"); compare the address part case-insensitively.

    Strict rules: ExitNodeStatus.ID must be nonempty; peer names/IPs only
    count from peers whose ID equals that ExitNodeStatus.ID; any matching
    name/IP from a different-ID peer, or from a peer with ExitNode != True,
    is rejected (including contradictory same-ID peers with ExitNode False).
    """
    want = (expected or "").strip().lower().rstrip(".")
    if not want:
        return False
    exit_status = (status or {}).get("ExitNodeStatus") or {}
    if not isinstance(exit_status, dict):
        return False
    exit_id = str(exit_status.get("ID") or "").strip()
    if not exit_id:
        return False
    exit_id_norm = exit_id.lower()
    if want == exit_id_norm:
        peers = (status or {}).get("Peer") or {}
        if isinstance(peers, dict):
            for peer in peers.values():
                if not isinstance(peer, dict):
                    continue
                peer_id = str(peer.get("ID") or "").strip().lower()
                if peer_id == exit_id_norm and peer.get("ExitNode") is not True:
                    return False
        return True
    peers = (status or {}).get("Peer") or {}
    if not isinstance(peers, dict):
        return False
    same_id_candidates: set[str] = set()
    same_id_saw_false = False
    for peer in peers.values():
        if not isinstance(peer, dict):
            continue
        peer_id = str(peer.get("ID") or "").strip().lower()
        if peer_id != exit_id_norm:
            # A different-ID peer claiming the wanted name/IP contradicts
            # the selected exit; reject outright.
            for ip in peer.get("TailscaleIPs") or []:
                if _strip_prefix(ip) == want:
                    return False
            for name in (peer.get("HostName"), peer.get("DNSName")):
                if name and str(name).strip().lower().rstrip(".") == want:
                    return False
            continue
        if peer.get("ExitNode") is not True:
            same_id_saw_false = True
            continue
        for ip in peer.get("TailscaleIPs") or []:
            same_id_candidates.add(_strip_prefix(ip))
        for name in (peer.get("HostName"), peer.get("DNSName")):
            if name:
                same_id_candidates.add(str(name).strip().lower().rstrip("."))
    if want in same_id_candidates:
        return not same_id_saw_false
    return False


def _proxy_listen_matches(flag_value: str, host: str, port: int) -> bool:
    value = (flag_value or "").strip()
    if value.startswith("["):  # [::1]:8080
        try:
            h, _, p = value.rpartition(":")
            return h.strip("[]").lower() == host.lower() and int(p) == port
        except ValueError:
            return False
    if ":" in value and value.count(":") > 1:  # bare IPv6 without port is not a valid listen flag
        return False
    try:
        h, _, p = value.rpartition(":")
        return h.lower() == host.lower() and int(p) == port
    except ValueError:
        return False


_TAILSCALED_VALUE_FLAGS = {"socket", "tun", "state", "statedir", "outbound-http-proxy-listen", "port"}


def _parse_tailscaled_flags(argv: list) -> tuple[dict, str | None]:
    """Parse known tailscaled value flags in both --key=value and --key value forms.

    Returns (values, error). Any duplicate flag, regardless of form, is an
    error; missing or empty values are errors. Unknown flags are ignored.
    Never reads file data.
    """
    found: dict[str, str] = {}
    counts: dict[str, int] = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if not isinstance(arg, str) or not arg.startswith("--"):
            i += 1
            continue
        if "=" in arg:
            key, val = arg.split("=", 1)
            name = key[2:]
            if name not in _TAILSCALED_VALUE_FLAGS:
                i += 1
                continue
            if val == "":
                return {}, f"empty value for --{name}"
            counts[name] = counts.get(name, 0) + 1
            if counts[name] > 1:
                return {}, f"duplicate --{name} flags"
            found[name] = val
            i += 1
        else:
            name = arg[2:]
            if name not in _TAILSCALED_VALUE_FLAGS:
                i += 1
                continue
            if i + 1 >= len(argv):
                return {}, f"missing value for --{name}"
            nxt = argv[i + 1]
            if not isinstance(nxt, str) or nxt.startswith("--") or nxt == "":
                return {}, f"missing value for --{name}"
            counts[name] = counts.get(name, 0) + 1
            if counts[name] > 1:
                return {}, f"duplicate --{name} flags"
            found[name] = nxt
            i += 2
    return found, None


def _relay_dir_for(expected_canonical: str, state_dir: str | None) -> str | None:
    import os
    from pathlib import Path
    if state_dir is not None:
        return os.path.realpath(os.path.join(os.path.normpath(str(state_dir)), "tailscaled-relay"))
    parts = Path(expected_canonical).parts
    if "tailscaled-relay" in parts:
        idx = parts.index("tailscaled-relay")
        return str(Path(*parts[: idx + 1]))
    return None


def _validate_relay_state_path(value: str, relay_dir: str) -> str:
    """Validate --state/--statedir as explicit private canonical paths.

    Must be absolute, canonical (no traversal, no // alias, no symlinks),
    under the relay dir, and not under host tailscale state. Returns the
    canonical path. Never reads file contents.
    """
    import os
    from pathlib import Path
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Relay state path must be an absolute path")
    if value.startswith("//") or "//" in value:
        raise ValueError("Relay state path must be canonical (no alias)")
    if not Path(value).is_absolute():
        raise ValueError("Relay state path must be an absolute path")
    if any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("Relay state path must not contain traversal")
    if value.endswith("/"):
        raise ValueError("Relay state path must be canonical (no alias)")
    if os.path.normpath(value) != value:
        raise ValueError("Relay state path must be canonical (no traversal/alias)")
    for part_index in range(1, len(Path(value).parts)):
        prefix = str(Path(*Path(value).parts[: part_index + 1]))
        try:
            if os.path.islink(prefix):
                raise ValueError("Relay state path must not contain symlinks")
        except OSError:
            raise ValueError("cannot inspect relay state path")
    canonical = os.path.realpath(value)
    if canonical.startswith("//") or canonical != os.path.normpath(canonical):
        raise ValueError("Relay state path must be canonical (no traversal/alias)")
    for hp in ("/var/lib/tailscale", "/var/run/tailscale", "/run/tailscale"):
        try:
            hp_c = os.path.realpath(hp)
        except OSError:
            hp_c = hp
        if canonical == hp_c or canonical.startswith(hp_c.rstrip("/") + "/"):
            raise ValueError("Relay state must not reuse host tailscale state")
    if not (canonical == relay_dir or canonical.startswith(relay_dir.rstrip("/") + "/")):
        raise ValueError("Relay state must live under the private relay dir")
    return canonical


def relay_process_check(relay_socket: str, relay_host: str, relay_port: int,
                        state_dir: str | None = None) -> tuple[bool, str]:
    """Require an owned userspace tailscaled bound to the exact relay socket.

    The relay daemon must run with --tun=userspace-networking (no host TUN
    changes), explicit private --state/--statedir under the relay dir, and
    --outbound-http-proxy-listen on the configured loopback proxy.
    Association requires: resolved exe equals installed tailscaled, expected
    UID, socket stat is a UID-owned socket, and the same PID owns the exact
    UNIX socket and the loopback TCP listener (via psutil). Any incomplete
    inspection fails closed. The host socket is never consulted.
    """
    import os
    import shutil
    import stat as statmod

    import psutil
    try:
        from .egress import validate_relay_socket as _validate_socket
    except ImportError:  # pragma: no cover
        from brocode.infra.egress import validate_relay_socket as _validate_socket
    try:
        expected_canonical = _validate_socket(relay_socket, state_dir)
    except ValueError as exc:
        return False, f"invalid relay socket: {exc}"
    try:
        expected_uid = os.geteuid()
    except AttributeError:
        expected_uid = os.getuid()
    installed = shutil.which("tailscaled")
    if not installed:
        return False, "cannot verify relay tailscaled executable"
    try:
        installed_real = os.path.realpath(installed)
    except OSError:
        return False, "cannot verify relay tailscaled executable"
    try:
        st = os.stat(expected_canonical)
    except FileNotFoundError:
        return False, "no tailscaled process owns the relay socket"
    except OSError:
        return False, "cannot inspect relay tailscaled ownership"
    if not statmod.S_ISSOCK(st.st_mode):
        return False, "relay socket is not a UNIX socket"
    if st.st_uid != expected_uid:
        return False, "relay socket UID mismatch"
    relay_dir = _relay_dir_for(expected_canonical, state_dir)
    if not relay_dir:
        return False, "relay socket must live under private tailscaled-relay state"
    try:
        parent = os.path.dirname(expected_canonical)
        root_norm = os.path.normpath(relay_dir)
        cur = os.path.realpath(parent)
        while True:
            try:
                pst = os.stat(cur)
            except OSError:
                return False, "cannot inspect relay tailscaled ownership"
            if pst.st_uid != expected_uid:
                return False, "relay state dir UID mismatch"
            if pst.st_mode & 0o077:
                return False, "relay state dirs must be owner-only"
            if os.path.normpath(cur) == root_norm:
                break
            nxt = os.path.dirname(os.path.normpath(cur))
            if nxt == os.path.normpath(cur):
                break
            cur = nxt
    except OSError:
        return False, "cannot inspect relay tailscaled ownership"
    try:
        procs = list(psutil.process_iter(["cmdline"]))
    except (psutil.Error, OSError):
        return False, "cannot inspect relay tailscaled ownership"
    saw_socket_owner = False
    for proc in procs:
        try:
            argv = proc.info.get("cmdline")
            if argv is None:
                argv = proc.cmdline()
        except (psutil.Error, OSError):
            continue
        if not argv or not any("tailscaled" in (a or "") for a in argv):
            continue
        flags, parse_error = _parse_tailscaled_flags(list(argv))
        if parse_error:
            return False, f"relay tailscaled {parse_error}"
        sock_raw = flags.get("socket")
        if sock_raw is None:
            continue
        try:
            sock_canonical = _validate_socket(sock_raw, state_dir)
        except ValueError:
            continue
        if sock_raw != sock_canonical or sock_canonical != expected_canonical:
            continue
        saw_socket_owner = True
        tun = flags.get("tun")
        if tun != "userspace-networking":
            return False, "relay tailscaled must use --tun=userspace-networking"
        proxy_raw = flags.get("outbound-http-proxy-listen")
        if not proxy_raw or not _proxy_listen_matches(proxy_raw, relay_host, relay_port):
            return False, "relay tailscaled proxy listen must match configured loopback proxy"
        state_raw = flags.get("state")
        statedir_raw = flags.get("statedir")
        if not state_raw or not statedir_raw:
            return False, "relay tailscaled must set explicit private --state and --statedir"
        try:
            state_c = _validate_relay_state_path(state_raw, relay_dir)
            statedir_c = _validate_relay_state_path(statedir_raw, relay_dir)
        except ValueError as exc:
            return False, f"invalid relay state: {exc}"
        if statedir_c != relay_dir and not state_c.startswith(relay_dir.rstrip("/") + "/"):
            return False, "invalid relay state: must live under the private relay dir"
        try:
            exe = proc.exe() if hasattr(proc, "exe") else None
        except (psutil.Error, OSError):
            return False, "cannot inspect relay tailscaled ownership"
        if not exe:
            try:
                exe = proc.info.get("exe")
            except (psutil.Error, OSError, AttributeError):
                exe = None
        if not exe:
            return False, "cannot verify relay tailscaled executable"
        try:
            if os.path.realpath(exe) != installed_real:
                return False, "relay tailscaled executable mismatch"
        except OSError:
            return False, "cannot verify relay tailscaled executable"
        try:
            uids = proc.uids() if hasattr(proc, "uids") else None
        except (psutil.Error, OSError):
            return False, "cannot inspect relay tailscaled ownership"
        if uids is None:
            try:
                uids = proc.info.get("uids")
            except (psutil.Error, OSError, AttributeError):
                uids = None
        uid_real = getattr(uids, "real", None) if uids is not None else None
        if uid_real is None and isinstance(uids, (list, tuple)) and uids:
            uid_real = uids[0]
        if uid_real is None:
            return False, "cannot inspect relay tailscaled ownership"
        if uid_real != expected_uid:
            return False, "relay tailscaled UID mismatch"
        try:
            if hasattr(proc, "net_connections"):
                try:
                    conns = proc.net_connections(kind="all")
                except TypeError:
                    conns = list(proc.net_connections(kind="inet")) + list(proc.net_connections(kind="unix"))
            else:
                all_conns = psutil.net_connections(kind="all")
                pid = getattr(proc, "pid", None)
                conns = [c for c in all_conns if getattr(c, "pid", None) == pid]
        except (psutil.Error, OSError):
            return False, "cannot inspect relay tailscaled ownership"
        has_unix = False
        has_inet = False
        for conn in conns:
            try:
                laddr = getattr(conn, "laddr", None)
            except (psutil.Error, OSError):
                return False, "cannot inspect relay tailscaled ownership"
            if laddr is None:
                continue
            if isinstance(laddr, str):
                try:
                    if os.path.realpath(laddr) == expected_canonical or laddr == expected_canonical:
                        has_unix = True
                except OSError:
                    if laddr == expected_canonical:
                        has_unix = True
                continue
            if isinstance(laddr, (list, tuple)) and len(laddr) == 2:
                ip, port = laddr[0], laddr[1]
                try:
                    if str(ip).lower() == str(relay_host).lower() and int(port) == int(relay_port):
                        status = str(getattr(conn, "status", "")).upper()
                        if "LISTEN" in status or getattr(conn, "status", None) == psutil.CONN_LISTEN:
                            has_inet = True
                except (ValueError, TypeError):
                    continue
                continue
            ip = getattr(laddr, "ip", None)
            port = getattr(laddr, "port", None)
            path = getattr(laddr, "path", None)
            if path and isinstance(path, str):
                try:
                    if os.path.realpath(path) == expected_canonical or path == expected_canonical:
                        has_unix = True
                except OSError:
                    if path == expected_canonical:
                        has_unix = True
            if ip is not None and port is not None:
                try:
                    if str(ip).lower() == str(relay_host).lower() and int(port) == int(relay_port):
                        status = str(getattr(conn, "status", "")).upper()
                        if "LISTEN" in status or getattr(conn, "status", None) == psutil.CONN_LISTEN:
                            has_inet = True
                except (ValueError, TypeError):
                    continue
        if not has_unix:
            return False, "no tailscaled process owns the relay socket"
        if not has_inet:
            return False, "relay tailscaled proxy listen must match configured loopback proxy"
        return True, "isolated userspace tailscaled with loopback proxy"
    if saw_socket_owner:
        return False, "cannot inspect relay tailscaled ownership"
    return False, "no tailscaled process owns the relay socket"


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
    record("egress mode", mode in {"tailscale", "warp", "tailscale-relay"},
           mode if mode in {"tailscale", "warp", "tailscale-relay"} else "explicit tailscale, warp, or tailscale-relay required")
    try:
        host, port = parse_proxy(settings.proxy_url)
        record("egress proxy config", True, f"HTTP loopback port {port}")
        matches = await asyncio.to_thread(listener_matches, host, port, mode)
        record("egress proxy listener", matches, "owned explicit-mode proxy" if matches else "missing or unrecognized proxy process")
        health = await proxy_health(settings.proxy_url)
        selected = health.get("mode") == mode and mode in {"tailscale", "warp", "tailscale-relay"}
        record("egress proxy mode", selected, "mode matches" if selected else "proxy mode mismatch")
    except Exception:  # noqa: BLE001 - failed diagnostic must fail closed without secret text
        health = None
        record("egress proxy health", False, "cannot verify explicit-mode listener; legacy fallback proxy is not accepted")

    if health and health.get("mode") == mode and mode in {"tailscale", "warp", "tailscale-relay"}:
        route_stage = "selected provider"
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
                       and bool((status.get("ExitNodeStatus") or {}).get("Online")), "selected exit node must be online")
                expected = await route_probe(source_ip=source)
            elif mode == "tailscale-relay":
                relay_host = health.get("relay_host")
                if relay_host not in LOOPBACK_HOSTS:
                    raise ValueError("Non-local relay upstream")
                relay_port = int(health.get("relay_port"))
                if not 0 < relay_port < 65536:
                    raise ValueError("Invalid relay port")
                relay_socket = health.get("relay_socket")
                if not relay_socket:
                    raise ValueError("Missing relay socket")
                relay_state_dir = str(getattr(settings, "state_dir", ""))
                relay_socket = validate_relay_socket(relay_socket, relay_state_dir)
                relay_exit = (health.get("relay_exit_node") or "").strip()
                if not relay_exit:
                    raise ValueError("Missing expected relay exit-node identity")
                ok, detail = await asyncio.to_thread(relay_process_check, relay_socket, relay_host,
                                                     relay_port, relay_state_dir)
                record("relay tailscaled", ok, detail)
                if not ok:
                    raise ValueError("Isolated relay tailscaled not verified")
                # Socket-scoped status only: never consult the host tailscaled for relay mode.
                status = json.loads(await command("tailscale", "--socket", relay_socket, "status", "--json"))
                online = status.get("BackendState") == "Running" and bool((status.get("ExitNodeStatus") or {}).get("Online"))
                record("relay exit node", online, "selected relay exit node must be online")
                if not online:
                    raise ValueError("Relay exit node offline")
                record("relay exit identity", relay_exit_matches(status, relay_exit),
                       "socket-scoped exit identity must match expected")
                if not relay_exit_matches(status, relay_exit):
                    raise ValueError("Relay exit identity mismatch")
                authority = f"[{relay_host}]" if ":" in relay_host else relay_host
                route_stage = "relay upstream"
                expected = await route_probe(proxy_url=f"http://{authority}:{relay_port}")
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
            route_stage = "host/browser proxy"
            host_route, proxied = await asyncio.gather(route_probe(), route_probe(proxy_url=settings.proxy_url))
            record("selected route IP", expected["ip"] == proxied["ip"], "proxy IP must equal selected provider route IP")
            record("per-process isolation", host_route["ip"] != proxied["ip"], "host IP must differ from browser proxy IP")
        except Exception as exc:  # noqa: BLE001 - external diagnostic failure is blocking
            from httpx import TimeoutException
            reason = "probe timed out" if isinstance(exc, (TimeoutError, TimeoutException)) else "verification failed"
            record("selected route health", False, f"{route_stage}: {reason}; route/IP health unverified")

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
