"""Preserved stealth configuration, without implicit display/lock/proxy repair.

Preserves the prior stealth configuration in the supported package. Preflight is
read-only; the worker requires an existing display and an unlocked profile.
"""
from __future__ import annotations

import os
from pathlib import Path

_OWNED_PROCESSES = []

TELL_FLAGS = [
    "--disable-component-update", "--disable-default-apps", "--headless=new",
    "--enable-automation", "--disable-blink-features=AutomationControlled",
]
EXTRA_ARGS = [
    "--use-gl=angle", "--use-angle=swiftshader", "--enable-webgl",
    "--ignore-gpu-blocklist", "--enable-unsafe-swiftshader",
    "--disable-quic",  # QUIC must not bypass the HTTP proxy.
]


def patch() -> None:
    from browser_use.browser import profile as bp

    def _use_profile_in_place(self, __context=None):
        return None

    bp.BrowserProfile._copy_profile = _use_profile_in_place
    # 0.13.10 otherwise silently retries a locked profile using a temporary one.
    from browser_use.browser.watchdogs.local_browser_watchdog import LocalBrowserWatchdog
    original = LocalBrowserWatchdog._launch_browser
    if not getattr(original, "_brocode_no_fallback", False):
        async def launch_once(self, max_retries=1):
            return await original(self, max_retries=1)
        launch_once._brocode_no_fallback = True
        LocalBrowserWatchdog._launch_browser = launch_once
    wait_original = LocalBrowserWatchdog._wait_for_cdp_url
    if not getattr(wait_original, "_brocode_owned", False):
        async def track_owned_process(port, timeout=30, process=None):
            # Installed browser-use sets _subprocess only AFTER CDP startup.
            # Remember the exact Process instance before that wait can fail.
            if process is not None:
                _OWNED_PROCESSES.append(process)
            return await wait_original(port, timeout=timeout, process=process)
        track_owned_process._brocode_owned = True
        LocalBrowserWatchdog._wait_for_cdp_url = staticmethod(track_owned_process)


async def wait_owned_processes(timeout: float = 3) -> None:
    """Bounded wait for Chrome's orderly exit before termination fallback."""
    import asyncio

    import psutil
    if _OWNED_PROCESSES:
        await asyncio.to_thread(psutil.wait_procs, list(_OWNED_PROCESSES), timeout=timeout)


async def cleanup_owned_processes() -> None:
    """Terminate only exact processes launched by this worker, including failed CDP starts."""
    import asyncio

    import psutil
    processes = []
    for process in _OWNED_PROCESSES:
        try:
            processes.extend(process.children(recursive=True))
            processes.append(process)
        except psutil.Error:
            continue
    for process in reversed(processes):
        try:
            process.terminate()
        except psutil.Error:
            pass
    if processes:
        _, alive = await asyncio.to_thread(psutil.wait_procs, processes, timeout=2)
        for process in alive:
            try:
                process.kill()
            except psutil.Error:
                pass
    _OWNED_PROCESSES.clear()


def browser_kwargs(
    *, proxy_url: str, egress_mode: str, chrome_path: str | Path,
    record_video_dir: str | Path | None = None,
) -> dict:
    from .preflight import parse_proxy
    parse_proxy(proxy_url)
    if egress_mode not in {"tailscale", "warp", "tailscale-relay"}:
        raise ValueError("Explicit egress mode required")
    if not os.environ.get("DISPLAY"):
        raise ValueError("A preflight-checked display is required")
    patch()
    kwargs = {
        "executable_path": str(chrome_path), "headless": False, "no_viewport": True,
        "ignore_default_args": list(TELL_FLAGS), "args": list(EXTRA_ARGS),
        "proxy": {"server": proxy_url}, "enable_default_extensions": False,
        "captcha_solver": False, "permissions": [], "keep_alive": False,
    }
    if record_video_dir:
        kwargs.update(record_video_dir=str(record_video_dir), record_video_size={"width": 1280, "height": 720},
                      record_video_framerate=15)
    return kwargs
