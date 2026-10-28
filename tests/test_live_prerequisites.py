"""Opt-in installed relay and solver authentication checks. No browser or paid solve."""

import asyncio
import json
import os
import time
from datetime import UTC, datetime

import pytest
from dotenv import dotenv_values

from brocode.infra.captcha import NoCaptchaAIClient
from brocode.infra.egress import LOOPBACK_HOSTS
from brocode.infra.preflight import preflight, proxy_health, route_probe
from brocode.settings import Settings, private_dir

pytestmark = pytest.mark.skipif(
    os.environ.get("BROCODE_LIVE_PREREQUISITES") != "1",
    reason="Explicit live prerequisite opt-in required",
)


@pytest.fixture(scope="module")
def report_dir():
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return private_dir(Settings.load().state_dir / "acceptance" / f"indeed-prerequisites-{timestamp}")


def save_report(report_dir, name, result):
    path = report_dir / f"{name}.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    path.chmod(0o600)


async def test_live_indeed_relay_preflight(report_dir):
    settings = Settings.load()
    assert settings.egress_mode == "tailscale-relay", "Explicit tailscale-relay settings required"
    checks = await preflight(settings)
    save_report(report_dir, "relay", checks)
    failures = [{"name": check["name"], "detail": check["detail"]} for check in checks if not check["ok"]]
    assert not failures, failures


async def test_live_relay_route_paths(report_dir):
    """Probe both proxy hops independently, even if shared preflight stops early.

    No IPs or upstream response bodies are persisted. This is a diagnostic, not
    permission to launch a browser when any shared preflight check fails.
    """
    settings = Settings.load()
    assert settings.egress_mode == "tailscale-relay", "Explicit tailscale-relay settings required"
    health = await proxy_health(settings.proxy_url)
    assert health.get("mode") == "tailscale-relay", "Relay proxy mode required"
    host, port = health.get("relay_host"), health.get("relay_port")
    assert host in LOOPBACK_HOSTS, "Loopback relay upstream required"
    assert type(port) is int and 0 < port < 65536, "Valid relay port required"
    authority = f"[{host}]" if ":" in host else host

    async def probe(name, proxy):
        started = time.monotonic()
        try:
            result = await route_probe(proxy_url=proxy)
            return name, result, {
                "ok": True, "detail": "HTTPS trace received",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        except Exception as exc:  # noqa: BLE001 - never persist network exception text
            from httpx import TimeoutException
            timed_out = isinstance(exc, (TimeoutError, TimeoutException))
            return name, None, {
                "ok": False, "detail": "probe timed out" if timed_out else "probe failed",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }

    results = await asyncio.gather(
        probe("relay_upstream", f"http://{authority}:{port}"),
        probe("browser_proxy", settings.proxy_url),
        probe("host_direct", None),
    )
    paths = {name: summary for name, _, summary in results}
    routes = {name: result for name, result, _ in results}
    all_reachable = all(summary["ok"] for summary in paths.values())
    # None means unverified, not a passed equality/isolation check.
    equality = isolation = None
    if all_reachable:
        equality = routes["relay_upstream"]["ip"] == routes["browser_proxy"]["ip"]
        isolation = routes["host_direct"]["ip"] != routes["browser_proxy"]["ip"]
    report = {
        "paths": paths, "selected_route_equal": equality,
        "host_isolated": isolation, "browser_opened": False,
    }
    save_report(report_dir, "relay-route-paths", report)
    assert all_reachable, paths
    assert equality, "Browser proxy did not use the selected relay route"
    assert isolation, "Host and browser proxy routes are not isolated"


async def test_live_solver_authentication(report_dir):
    values = {**dotenv_values(Settings.load().root / ".env"), **os.environ}
    client = NoCaptchaAIClient(
        api_key=values.get("NOCAPTCHA_API_KEY") or "",
        base_url=values.get("NOCAPTCHA_API_BASE") or "https://api.nocaptchaai.com",
    )
    ok, detail = await client.validate()
    save_report(report_dir, "captcha-authentication", {
        "ok": ok, "detail": detail, "paid_solve_attempted": False, "browser_delivery_tested": False,
    })
    assert ok, detail
    assert detail != "Solver key accepted; zero balance", "Solver authenticated but has no balance for solving"
