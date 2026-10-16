#!/usr/bin/env python3
"""
Stealth browser configuration for brocode.

The obvious plan here was to swap Playwright for Patchright. That does not work
on this stack, and it is worth knowing why. browser-use launches Chrome as a raw
subprocess (asyncio.create_subprocess_exec) and then speaks CDP. Patchright is a
patched Playwright whose stealth applies at launch_persistent_context time, so
its patches never run. browser-use also calls Runtime.evaluate in a dozen places,
which is the Runtime.enable leak Patchright exists to close.

So the detectable surface we actually control is smaller and more concrete:

  1. Which binary runs. Anti-bot detects Chromium versus real Google Chrome.
  2. Which flags it gets. Patchright removes --disable-component-update and
     --disable-default-apps precisely because they read as a stealth driver.
  3. Whether inner and outer window sizes agree. A 1279x719 outer with a 1920x1080
     inner is physically impossible and is an instant fingerprint tell.
  4. Whether the profile is used in place, so logins persist.

This module pins all four.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

CHROME_BIN = os.getenv("BROCODE_CHROME_PATH", shutil.which("google-chrome") or "/usr/bin/google-chrome")
DISPLAY = os.getenv("BROCODE_DISPLAY", ":99")
SCREEN = os.getenv("BROCODE_SCREEN", "1280x720x24")

# browser-use adds these by default. Patchright strips the first two because they
# are the fingerprint of a stealth driver rather than a person with Chrome.
TELL_FLAGS = [
    "--disable-component-update",
    "--disable-default-apps",
    "--headless=new",
    "--enable-automation",
    "--disable-blink-features=AutomationControlled",
]

# A browser with no WebGL at all is itself a tell. Xvfb has no GPU, so we ask
# for SwiftShader, which is what Chrome uses for software rendering.
EXTRA_ARGS = [
    "--use-gl=angle",
    "--use-angle=swiftshader",
    "--enable-webgl",
    "--ignore-gpu-blocklist",
    "--enable-unsafe-swiftshader",
]


def chrome_version() -> str | None:
    """Version string of the Chrome we will run, or None if not installed."""
    if not Path(CHROME_BIN).exists():
        return None
    try:
        out = subprocess.run([CHROME_BIN, "--version"], capture_output=True, text=True, timeout=15)
        return (out.stdout or out.stderr).strip() or None
    except Exception:
        return None


def is_real_chrome() -> bool:
    """True when the binary is Google Chrome, not Playwright's Chromium."""
    version = chrome_version() or ""
    return "Google Chrome" in version


def patch() -> None:
    """Stop browser-use from relocating the profile to a throwaway temp dir.

    BrowserProfile._copy_profile copies .chrome_profile to /tmp whenever the
    path or executable contains "chrome", then points user_data_dir at the copy.
    That copy is one-way, so anything the run does, including a new login, is
    discarded. Using the profile in place is what persistence means.
    """
    from browser_use.browser import profile as bp

    def _use_profile_in_place(self, __context=None):
        return None

    bp.BrowserProfile._copy_profile = _use_profile_in_place


def ensure_display() -> str:
    """Make sure an Xvfb display exists and return the DISPLAY to use.

    We run headful because headless is its own detection category. On a server
    with no monitor, Xvfb is the display.
    """
    existing = os.environ.get("DISPLAY")
    if existing:
        return existing

    import psutil

    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or "")
            if cmd.startswith("Xvfb") and DISPLAY in cmd.split():
                os.environ["DISPLAY"] = DISPLAY
                return DISPLAY
        except Exception:
            continue

    subprocess.Popen(
        ["Xvfb", DISPLAY, "-screen", "0", SCREEN, "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    for _ in range(30):
        time.sleep(0.2)
        if Path(f"/tmp/.X11-unix/X{DISPLAY.lstrip(':')}").exists():
            break

    os.environ["DISPLAY"] = DISPLAY
    return DISPLAY


def clear_stale_lock(user_data_dir: str) -> bool:
    """Remove a SingletonLock left by a Chrome that is already dead.

    A run that gets killed hard leaves the lock behind, and the next launch dies
    with "Browser process exited before CDP became available", which reads like
    a missing Chrome rather than a stale lock. Only clears when the owning pid is
    gone, so a live Chrome is never stolen from.
    """
    lock = Path(user_data_dir) / "SingletonLock"
    if not (lock.exists() or lock.is_symlink()):
        return False

    owner = None
    try:
        owner = os.readlink(lock).rsplit("-", 1)[-1]
    except Exception:
        pass

    if owner and owner.isdigit():
        try:
            import psutil
            if psutil.pid_exists(int(owner)):
                return False
        except Exception:
            pass

    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        try:
            os.unlink(Path(user_data_dir) / name)
        except FileNotFoundError:
            pass
    return True


def browser_kwargs(record_video_dir=None, record_video_size=None, record_video_framerate=15) -> dict:
    """The stealth browser settings, ready to splat into Browser()."""
    patch()
    ensure_display()
    clear_stale_lock(os.getenv("CHROME_USER_DATA_DIR", str(SCRIPT_DIR / ".chrome_profile")))

    kwargs = {
        "executable_path": CHROME_BIN,
        "headless": False,
        "no_viewport": True,
        "ignore_default_args": list(TELL_FLAGS),
        "args": list(EXTRA_ARGS),
        "captcha_solver": True,
    }

    proxy = os.getenv("BROCODE_PROXY_URL", "")
    if proxy:
        kwargs["proxy"] = {"server": proxy}

    if record_video_dir:
        kwargs["record_video_dir"] = str(record_video_dir)
        kwargs["record_video_size"] = record_video_size or {"width": 1280, "height": 720}
        kwargs["record_video_framerate"] = record_video_framerate

    return kwargs


def effective_args(user_data_dir: str) -> list[str]:
    """The launch flags Chrome would actually get, for doctor to inspect."""
    from browser_use.browser.profile import BrowserProfile

    patch()
    profile = BrowserProfile(
        user_data_dir=user_data_dir,
        executable_path=CHROME_BIN,
        headless=False,
        no_viewport=True,
        ignore_default_args=list(TELL_FLAGS),
        args=list(EXTRA_ARGS),
    )
    return profile.get_args()


def checks(user_data_dir: str) -> list[tuple[str, bool, str]]:
    """Preflight assertions, in (name, ok, detail) form for brocode doctor."""
    results = []

    version = chrome_version()
    if version is None:
        results.append(("chrome binary", False, f"not installed at {CHROME_BIN}. Run: .venv/bin/python -m patchright install chrome"))
    elif is_real_chrome():
        results.append(("chrome binary", True, f"{version} ({CHROME_BIN})"))
    else:
        results.append(("chrome binary", False, f"{version} is not Google Chrome. Anti-bot detects Chromium. Run: .venv/bin/python -m patchright install chrome"))

    display = os.environ.get("DISPLAY")
    if display:
        results.append(("display", True, f"DISPLAY={display}"))
    else:
        running = False
        try:
            import psutil
            for proc in psutil.process_iter(["cmdline"]):
                cmd = " ".join(proc.info.get("cmdline") or "")
                if cmd.startswith("Xvfb") and DISPLAY in cmd.split():
                    running = True
                    break
        except Exception:
            pass
        results.append(("display", True, f"Xvfb {DISPLAY} {'running' if running else 'will be started on demand'}"))

    try:
        args = effective_args(user_data_dir)
        leftover = [a for a in args if any(t in a for t in ("disable-component-update", "disable-default-apps", "headless"))]
        results.append(("no driver tell-flags", not leftover,
                        "clean" if not leftover else f"still present: {leftover}"))
    except Exception as e:
        results.append(("no driver tell-flags", False, f"could not read effective args: {e}"))

    results.append(("no_viewport (inner=outer)", True, "window and viewport sizes will agree"))

    lock = Path(user_data_dir) / "SingletonLock"
    if lock.exists() or lock.is_symlink():
        owner = None
        try:
            owner = os.readlink(lock).rsplit("-", 1)[-1]
        except Exception:
            pass
        alive = False
        if owner and owner.isdigit():
            try:
                import psutil
                alive = psutil.pid_exists(int(owner))
            except Exception:
                pass
        if alive:
            results.append(("profile not locked", False,
                            f"a Chrome (pid {owner}) already holds .chrome_profile. Close it first or the new one will refuse to start."))
        elif clear_stale_lock(user_data_dir):
            results.append(("profile not locked", True,
                            f"cleared a stale lock from dead pid {owner}"))
        else:
            results.append(("profile not locked", True, "free"))
    else:
        results.append(("profile not locked", True, "free"))

    return results


def main() -> int:
    patch()
    print(f"chrome: {chrome_version()} at {CHROME_BIN}")
    print(f"real Google Chrome: {is_real_chrome()}")
    print(f"display: {ensure_display()}")
    for name, ok, detail in checks(str(SCRIPT_DIR / ".chrome_profile")):
        print(f"{'✅' if ok else '❌'} {name}: {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
