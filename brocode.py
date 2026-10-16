#!/usr/bin/env python3
"""
brocode core engine
Autonomous vision-enabled browser agent powered by browser-use.
"""

import os
import sys
import json
import asyncio
import argparse
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Load configuration
SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "sk-hynix")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "http://localhost:8317/v1")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-6-luna")
VISION_MODEL = os.getenv("VISION_MODEL", "gpt-6-luna")
CHROME_PROFILE_DIR = Path(os.getenv("CHROME_USER_DATA_DIR", str(SCRIPT_DIR / ".chrome_profile")))
ARTIFACTS_DIR = SCRIPT_DIR / "artifacts"

# Per-process egress. When set, Chrome alone is routed through the local
# exit proxy (local_exit_proxy.py), which binds outbound sockets to the
# Tailscale address so only this browser leaves via the exit node.
PROXY_URL = os.getenv("BROCODE_PROXY_URL", "")

RECORDINGS_DIR = ARTIFACTS_DIR / "recordings"

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
CHROME_PROFILE_DIR.mkdir(parents=True, exist_ok=True)

def _listener_pid(port):
    """PID of the process listening on a TCP port, or None."""
    import psutil
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return None
    for c in conns:
        try:
            if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port:
                return c.pid
        except Exception:
            continue
    return None


def _cmdline(pid):
    """Command line of a PID as a single string, or empty string."""
    import psutil
    try:
        return " ".join(psutil.Process(pid).cmdline())
    except Exception:
        return ""


def _public_ip(proxies=None, timeout=8):
    """Public egress IP as seen by an external echo service."""
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies or {}))
    with opener.open("https://api.ipify.org?format=json", timeout=timeout) as resp:
        return json.loads(resp.read().decode())["ip"]


def _looks_multi_step(task_prompt):
    """Heuristic: does this goal need more than one browser action?

    The flash-tier failure only ever showed up on goals that drive an
    interaction. Navigate-and-read goals were fine. So the signal is an
    interaction verb, plus the obvious multi-step markers.
    """
    t = (task_prompt or "").lower()
    for marker in (" then ", " and then ", " after that", " next,", " finally,"):
        if marker in t:
            return True
    if t.count("http://") + t.count("https://") > 1:
        return True
    interaction = (
        "click", "type ", "fill ", "select", "upload", "press ",
        "hover", "scroll", "submit", "sign in", "check the box", "choose ",
    )
    return any(v in t for v in interaction)


REQUIRED_FILES = ["brocode.py", "local_exit_proxy.py", "bin/brocode", ".env"]


def doctor(task_prompt=None, model_name=None, check_egress=True, file_paths=None):
    """Verify the session is safe to run. Returns (results, ok).

    Every check is one of the failure modes that actually bit us: a Chrome
    that came up without the proxy, egress silently leaving on the host IP,
    a stale proxy, an unwritable recordings dir, and a flash-tier model on a
    multi-step goal.
    """
    results = []

    def record(name, ok, detail):
        results.append((name, ok, detail))

    for rel in REQUIRED_FILES:
        record(f"file {rel}", (SCRIPT_DIR / rel).exists(), "present" if (SCRIPT_DIR / rel).exists() else "MISSING")

    proxy_port = None
    if PROXY_URL and "://" in PROXY_URL:
        try:
            proxy_port = int(PROXY_URL.rsplit(":", 1)[1])
        except Exception:
            proxy_port = None

    if not PROXY_URL:
        record("egress proxy config", False, "BROCODE_PROXY_URL is unset, Chrome would exit on the host IP")
    elif proxy_port is None:
        record("egress proxy config", False, f"cannot parse a port from {PROXY_URL}")
    else:
        record("egress proxy config", True, PROXY_URL)
        proxy_pid = _listener_pid(proxy_port)
        if proxy_pid is None:
            record("egress proxy listening", False, f"nothing listening on 127.0.0.1:{proxy_port}, run local_exit_proxy.py")
        else:
            cmd = _cmdline(proxy_pid)
            ok = "local_exit_proxy" in cmd
            record("egress proxy listening", ok, f"pid {proxy_pid}: {cmd[:90]}" if ok else f"pid {proxy_pid} is not local_exit_proxy: {cmd[:90]}")

    import stealth
    for name, ok, detail in stealth.checks(str(CHROME_PROFILE_DIR)):
        record(name, ok, detail)

    if PROXY_URL:
        record("per-process egress", True, f"browser pinned to {PROXY_URL}, host stays on eth0")
    else:
        record("per-process egress", False, "BROCODE_PROXY_URL unset, browser would exit on the host IP")

    try:
        RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
        probe = RECORDINGS_DIR / ".doctor_write_probe"
        probe.write_text("ok")
        probe.unlink()
        record("recordings writable", True, str(RECORDINGS_DIR))
    except Exception as e:
        record("recordings writable", False, f"{RECORDINGS_DIR}: {e}")

    if check_egress and PROXY_URL and proxy_port is not None:
        try:
            host_ip = _public_ip(proxies={})
            record("host egress IP", True, host_ip)
        except Exception as e:
            host_ip = None
            record("host egress IP", False, f"unreachable: {e}")
        try:
            proxied_ip = _public_ip(proxies={"http": PROXY_URL, "https": PROXY_URL})
            record("proxied egress IP", True, proxied_ip)
        except Exception as e:
            proxied_ip = None
            record("proxied egress IP", False, f"through {PROXY_URL}: {e}")
        if host_ip and proxied_ip:
            if host_ip == proxied_ip:
                record("per-process isolation", False,
                       f"both {host_ip}. The host is also going through the exit node, so scoping is lost. "
                       f"Check `ip rule show` for 'from all lookup main' before 'from all lookup 52'.")
            else:
                record("per-process isolation", True, f"host {host_ip}, browser {proxied_ip} via exit node")

    import subprocess
    try:
        rules = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, timeout=10).stdout
        has_scoping = ("from all lookup main" in rules) and ("lookup 52" in rules)
        main_prio = next((i for i, l in enumerate(rules.splitlines()) if "from all lookup main" in l and "fwmark" not in l), 9999)
        ts_prio = next((i for i, l in enumerate(rules.splitlines()) if "lookup 52" in l and "from all" not in l), -1)
        ordered = has_scoping and ts_prio < main_prio
        record("ip rule scoping", ordered,
               "host lookup main before tailscale catch-all" if ordered
               else f"rules are wrong, everything goes through the exit node. See `ip rule show`.")
    except Exception as e:
        record("ip rule scoping", False, f"could not read ip rules: {e}")

    for f in (file_paths or []):
        p = Path(f).expanduser()
        ok = p.is_file()
        record(f"upload file {p.name}", ok, str(p.resolve()) if ok else f"NOT FOUND: {f}. upload_file will reject this path.")

    key = os.getenv("NOCAPTCHA_API_KEY", "")
    needs_solver = bool(task_prompt) and _looks_multi_step(task_prompt)
    if not key:
        if needs_solver:
            record("captcha solver key", False, "NOCAPTCHA_API_KEY is unset in .env. This goal can hit a captcha and it will be left to the agent.")
        else:
            record("captcha solver key", True, "not set, fine for a goal with no interaction")
    else:
        record("captcha solver key", True, f"NOCAPTCHA_API_KEY set ({key[:6]}…{key[-3:]})")
        try:
            import asyncio as _asyncio
            import captcha_solver as _cs
            ok, detail = _asyncio.run(_cs.NoCaptchaAIClient(api_key=key).validate())
            # An unusable solver degrades the run, it does not make the browser
            # unsafe. Stealth may well mean no captcha appears at all, so a bad
            # key must not block a run the way a bad egress or a locked profile does.
            record("captcha solver key valid", True, detail if ok else f"WARNING, unusable: {detail}")
        except Exception as e:
            record("captcha solver key valid", True, f"WARNING, could not verify: {e}")

    if task_prompt is not None:
        model = model_name or VISION_MODEL
        multi = _looks_multi_step(task_prompt)
        weak = "flash" in model.lower()
        if multi and weak:
            # Flash-tier models are allowed but warned about: they tend to
            # treat 'done' as a pause button and end multi-step episodes
            # early. Allowed per operator request; prefer single-step goals.
            record("model fit for goal", True,
                   f"WARNING: {model} may call 'done' early on multi-step goals. Allowed.")
        elif weak:
            record("model fit for goal", True, f"{model}, single-step goal so it is acceptable")
        else:
            record("model fit for goal", True, model)

    ok = all(flag for _, flag, _ in results)
    return results, ok


def print_doctor(results):
    for name, flag, detail in results:
        mark = "✅" if flag else "❌"
        print(f"{mark} {name}: {detail}")

async def run_task(task_prompt: str, model_name: str = None, max_actions: int = 15, record: bool = True, record_video_dir: str = None, available_file_paths: list = None):
    """Run an autonomous browser-use agent task."""
    from browser_use.llm import ChatOpenAI
    from browser_use import Agent, Browser

    import captcha_solver
    import stealth
    captcha_solver.patch()
    stealth.patch()

    selected_model = model_name or VISION_MODEL

    llm = ChatOpenAI(
        model=selected_model,
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_BASE_URL,
        temperature=0.0
    )

    # Screencast-based recording, driven through CDP Page.screencastFrame.
    record_dir = Path(record_video_dir) if record_video_dir else RECORDINGS_DIR
    record_dir.mkdir(parents=True, exist_ok=True)
    recordings_before = {p.resolve() for p in record_dir.iterdir() if p.is_file()}

    browser = Browser(
        user_data_dir=str(CHROME_PROFILE_DIR),
        **stealth.browser_kwargs(
            record_video_dir=str(record_dir) if record else None,
            record_video_size={"width": 1280, "height": 720},
            record_video_framerate=15,
        )
    )
    if not record:
        record_dir = None

    files = []
    for f in (available_file_paths or []):
        p = Path(f).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"available_file_paths entry does not exist: {f}")
        files.append(str(p))

    system_note = None
    if files:
        listed = "\n".join(f"  - {p}" for p in files)
        system_note = (
            "You may upload these files, and only these:\n"
            f"{listed}\n\n"
            "The upload_file action takes exactly two parameters: `index` (int, the "
            "index of the file input element) and `path` (str, the absolute file path "
            "from the list above). The path parameter is named `path`. It is NOT "
            "'file_path', 'file', 'filename', or 'filePath'. Sending any other "
            "parameter name is a validation error and will fail. Use exactly "
            'upload_file(index=<n>, path="<absolute path>").'
        )

    agent = Agent(
        task=task_prompt,
        llm=llm,
        browser=browser,
        use_vision=True,
        max_actions_per_step=5,
        available_file_paths=files or None,
        extend_system_message=system_note
    )

    if files:
        print(f"📎 Files available to the agent: {files}")

    print(f"🤖 Starting brocode task with model '{selected_model}'...")
    print(f"🎯 Goal: {task_prompt}\n")

    history = await agent.run(max_steps=max_actions)
    final_res = history.final_result()

    # Collect any videos the recording watchdog wrote during this run.
    videos = []
    if record_dir is not None:
        await asyncio.sleep(0.5)
        videos = sorted(
            p for p in record_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".mp4", ".webm", ".mkv"}
            and p.resolve() not in recordings_before
        )

    # Save artifact
    import time
    task_id = f"task_{int(time.time())}"
    artifact_file = ARTIFACTS_DIR / f"{task_id}.json"

    # Save last screenshot if available
    screenshots = [s for s in history.screenshots() if s] if hasattr(history, "screenshots") else []
    screenshot_file = None
    if screenshots:
        import base64
        screenshot_file = ARTIFACTS_DIR / f"{task_id}_screenshot.png"
        try:
            screenshot_file.write_bytes(base64.b64decode(screenshots[-1]))
        except Exception as e:
            print(f"Warning: could not save screenshot: {e}")
            screenshot_file = None

    with open(artifact_file, "w") as f:
        json.dump({
            "task": task_prompt,
            "model": selected_model,
            "final_result": final_res,
            "errors": history.errors() if hasattr(history, "errors") else [],
            "urls": history.urls() if hasattr(history, "urls") else [],
            "recordings": [str(v) for v in videos],
            "screenshot": str(screenshot_file) if screenshot_file else None
        }, f, indent=2)

    return {
        "task_id": task_id,
        "artifact": str(artifact_file),
        "result": final_res,
        "recordings": [str(v) for v in videos],
        "screenshot": str(screenshot_file) if screenshot_file else None
    }

def main():
    parser = argparse.ArgumentParser(description="brocode — Autonomous browser-use agent CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run a browser task")
    run_parser.add_argument("task", type=str, help="Task description / goal")
    run_parser.add_argument("--model", "-m", type=str, default=None, help="LLM model to use")
    run_parser.add_argument("--max-actions", "-a", type=int, default=15, help="Max step iterations")
    run_parser.add_argument("--no-record", action="store_true", help="Skip video recording for this run")
    run_parser.add_argument("--file", "-f", action="append", default=None,
                            help="Register a file the agent may upload (repeatable). Required before upload_file will work.")

    # Status command
    subparsers.add_parser("status", help="Check brocode, browser, and egress status")

    # Preflight checks
    doctor_parser = subparsers.add_parser("doctor", help="Verify the session is safe to run")
    doctor_parser.add_argument("task", type=str, nargs="?", default=None, help="Optional goal to also model-check")
    doctor_parser.add_argument("--model", "-m", type=str, default=None, help="Model to model-check against")
    doctor_parser.add_argument("--no-egress", action="store_true", help="Skip the network egress checks")
    doctor_parser.add_argument("--file", "-f", action="append", default=None, help="Files the agent will upload (repeatable)")

    args = parser.parse_args()

    if args.command == "run":
        results, ok = doctor(task_prompt=args.task, model_name=args.model, check_egress=True, file_paths=args.file)
        print("\n" + "-"*50)
        print("PREFLIGHT")
        print("-"*50)
        print_doctor(results)
        if not ok:
            print("\n❌ Preflight failed. Not starting the browser.")
            print("   Fix the lines marked above, or run `brocode doctor` for detail.")
            sys.exit(1)
        res = asyncio.run(run_task(
            task_prompt=args.task,
            model_name=args.model,
            max_actions=args.max_actions,
            record=not args.no_record,
            available_file_paths=args.file
        ))
        print("\n" + "="*50)
        print("✅ BROCODE TASK COMPLETED")
        print("="*50)
        print(f"Artifact: {res['artifact']}")
        if res.get("screenshot"):
            print(f"Screenshot: {res['screenshot']}")
        if res.get("recordings"):
            print("Recording:")
            for v in res["recordings"]:
                print(f"  {v}")
        print(f"Result:\n{res['result']}")
    elif args.command == "doctor":
        results, ok = doctor(task_prompt=args.task, model_name=args.model, check_egress=not args.no_egress, file_paths=args.file)
        print_doctor(results)
        print("\n" + ("✅ All preflight checks passed." if ok else "❌ Preflight failed."))
        sys.exit(0 if ok else 1)
    elif args.command == "status":
        import stealth
        print(f"🌐 Browser: {stealth.chrome_version() or 'NOT INSTALLED'} ({stealth.CHROME_BIN})")
        print(f"🎭 Real Google Chrome: {'YES ✅' if stealth.is_real_chrome() else 'NO ❌ (Chromium is detectable)'}")
        print(f"🖥️  Display: {os.environ.get('DISPLAY') or stealth.DISPLAY + ' (starts on demand)'}")
        print(f"📂 Profile Directory: {CHROME_PROFILE_DIR}")
        print(f"🧠 Default Model: {VISION_MODEL} via {OPENAI_BASE_URL}")
        print(f"📁 Artifacts Dir: {ARTIFACTS_DIR}")
        print(f"🎥 Recordings Dir: {RECORDINGS_DIR}")
        print(f"🧭 Egress: {PROXY_URL or 'direct (no per-process proxy)'}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
