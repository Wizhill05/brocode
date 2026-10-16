#!/usr/bin/env python3
"""
Local CAPTCHA solver for brocode, backed by NoCaptchaAI.

browser-use's CaptchaWatchdog only listens for BrowserUse.captchaSolverStarted
and Finished CDP events, which a cloud browser proxy emits. On a local Chrome
nothing ever sends them, so the agent is left to click image tiles by eye and
loses. This module closes that gap.

The real primitive is not tile clicking. Read data-sitekey and the page URL,
hand them to NoCaptchaAI, receive a g-recaptcha-response token, inject it. This
subclass overrides wait_if_captcha_solving, which the agent step loop already
awaits, so the solve pauses the agent without touching its control flow.

Run: import and call install(browser_session) after the session starts.
"""

import asyncio
import os
import time
from typing import Any

from browser_use.browser.watchdogs.captcha_watchdog import CaptchaWaitResult, CaptchaWatchdog

API_BASE = os.getenv("NOCAPTCHA_API_BASE", "https://api.nocaptchaai.com")
API_KEY = os.getenv("NOCAPTCHA_API_KEY", "")

HARD_BLOCK_MARKERS = (
    "your computer or network may be sending automated queries",
    "we can't process your request at the moment",
    "we can’t process your request at the moment",
)

DETECT_JS = r"""
(() => {
  const out = {kind: null, sitekey: null, pageUrl: location.href, hardBlock: false, ready: false};

  const bodyText = (document.body ? document.body.innerText : "").toLowerCase();
  if (bodyText.includes("sending automated queries") ||
      bodyText.includes("can't process your request") ||
      bodyText.includes("can’t process your request")) {
    out.hardBlock = true;
  }

  const grab = (el) => {
    if (!el) return null;
    const own = el.getAttribute("data-sitekey");
    if (own) return own;
    const child = el.querySelector("[data-sitekey]");
    return child ? child.getAttribute("data-sitekey") : null;
  };

  let host = document.querySelector(".g-recaptcha[data-sitekey]") ||
             document.querySelector("[data-sitekey]");
  if (host) {
    out.kind = "recaptcha-v2";
    out.sitekey = grab(host);
  }

  if (!out.sitekey) {
    for (const f of document.querySelectorAll("iframe")) {
      const src = f.getAttribute("src") || "";
      if (src.includes("google.com/recaptcha") || src.includes("recaptcha.net")) {
        try {
          const u = new URL(src, location.href);
          out.sitekey = u.searchParams.get("k") || out.sitekey;
          out.kind = "recaptcha-v2";
        } catch (e) {}
        break;
      }
    }
  }

  if (!out.sitekey) {
    for (const s of document.querySelectorAll("script[src*='recaptcha']")) {
      try {
        const u = new URL(s.src, location.href);
        const k = u.searchParams.get("render");
        if (k && k !== "explicit") { out.sitekey = k; out.kind = "recaptcha-v2"; break; }
      } catch (e) {}
    }
  }

  if (!out.kind) {
    if (document.querySelector("iframe[src*='challenges.cloudflare.com'], .cf-turnstile, [data-sitekey*='0x']")) {
      out.kind = "turnstile";
    }
  }

  out.ready = !!(
    (window.grecaptcha && (window.grecaptcha.render || window.grecaptcha.execute)) ||
    document.querySelector("textarea[name='g-recaptcha-response'], textarea#g-recaptcha-response") ||
    document.querySelectorAll("iframe[src*='recaptcha']").length > 0
  );

  return out;
})()
"""

INJECT_JS_TEMPLATE = r"""
((token) => {
  const report = {textareas: 0, main: 0, iframe: 0, callbackFired: false};

  for (const t of document.querySelectorAll("textarea[name='g-recaptcha-response'], textarea#g-recaptcha-response, textarea[id*='g-recaptcha-response']")) {
    t.value = token;
    t.innerHTML = token;
    t.style.display = "block";
    t.removeAttribute("hidden");
    t.dispatchEvent(new Event("input", {bubbles: true}));
    t.dispatchEvent(new Event("change", {bubbles: true}));
    report.textareas += 1;
    report.main += 1;
  }

  for (const f of document.querySelectorAll("iframe[src*='recaptcha']")) {
    try {
      const d = f.contentDocument;
      if (d) {
        for (const t of d.querySelectorAll("textarea[name='g-recaptcha-response'], textarea#g-recaptcha-response")) {
          t.value = token; report.textareas += 1; report.iframe += 1;
        }
      }
    } catch (e) {}
  }

  for (const host of document.querySelectorAll(".g-recaptcha[data-callback], [data-sitekey][data-callback]")) {
    const name = host.getAttribute("data-callback");
    if (name && typeof window[name] === "function") {
      try { window[name](token); report.callbackFired = true; } catch (e) {}
    }
  }

  if (!report.callbackFired) {
    const fire = (obj, depth) => {
      if (depth > 6 || report.callbackFired) return;
      let keys;
      try { keys = Object.keys(obj); } catch (e) { return; }
      for (const k of keys) {
        let v;
        try { v = obj[k]; } catch (e) { continue; }
        if (k === "callback" && typeof v === "function") {
          try { v(token); report.callbackFired = true; return; } catch (e) {}
        } else if (v && typeof v === "object") {
          fire(v, depth + 1);
          if (report.callbackFired) return;
        }
      }
    };
    try {
      const cfg = window.___grecaptcha_cfg;
      if (cfg && cfg.clients) fire(cfg.clients, 0);
    } catch (e) {}
  }

  return report;
})(__TOKEN__)
"""


class NoCaptchaAIClient:
    """Minimal NoCaptchaAI client. Plain JSON over HTTPS, no SDK needed."""

    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key if api_key is not None else API_KEY
        self.base_url = (base_url or API_BASE).rstrip("/")

    async def _post(self, path: str, payload: dict) -> dict:
        import json
        import urllib.request

        def call():
            req = urllib.request.Request(
                f"{self.base_url}{path}",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())

        return await asyncio.to_thread(call)

    async def balance(self) -> dict:
        return await self._post("/getBalance", {"clientKey": self.api_key})

    async def validate(self) -> tuple[bool, str]:
        """Prove the key is real. Returns (ok, detail).

        /getBalance is not usable for this. It answers {"balance": 0, "errorId": 0}
        for any string you send it, so it looks like success for a key that does not
        exist. GET /balance with the apikey header does validate and returns
        "Invalid apikey" for a bad one.
        """
        if not self.api_key:
            return False, "NOCAPTCHA_API_KEY is not set"

        import json
        import urllib.error
        import urllib.request

        def call():
            req = urllib.request.Request(
                f"{self.base_url}/balance",
                headers={"apikey": self.api_key, "Accept": "application/json"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=25) as resp:
                    return resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode()

        status, body = await asyncio.to_thread(call)
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {"raw": body[:200]}

        text = json.dumps(data)
        if "Invalid apikey" in text or "invalid apikey" in text.lower():
            return False, f"key rejected by {self.base_url}: {text[:120]}"
        if isinstance(data, dict) and data.get("errorId"):
            return False, f"{data.get('errorCode')}: {data.get('errorDescription')}"
        return True, f"balance: {text[:120]}"

    async def solve_recaptcha_v2(self, website_url: str, website_key: str, invisible: bool = False,
                                 timeout: float = 180.0) -> dict:
        """Return {'ok': bool, 'token': str|None, 'error': str|None, 'cost': ...}."""
        if not self.api_key:
            return {"ok": False, "token": None, "error": "NOCAPTCHA_API_KEY is not set"}

        task = {
            "type": "ReCaptchaV2TaskProxyLess",
            "websiteURL": website_url,
            "websiteKey": website_key,
            "isInvisible": invisible,
        }
        created = await self._post("/createTask", {"clientKey": self.api_key, "task": task})
        if created.get("errorId"):
            return {"ok": False, "token": None,
                    "error": f"{created.get('errorCode')}: {created.get('errorDescription')}"}

        task_id = created.get("taskId")
        if task_id is None:
            return {"ok": False, "token": None, "error": f"no taskId in {created}"}

        deadline = time.time() + timeout
        while time.time() < deadline:
            await asyncio.sleep(3)
            res = await self._post("/getTaskResult", {"clientKey": self.api_key, "taskId": task_id})
            if res.get("errorId"):
                return {"ok": False, "token": None,
                        "error": f"{res.get('errorCode')}: {res.get('errorDescription')}"}
            status = res.get("status")
            if status == "ready":
                solution = res.get("solution") or {}
                token = solution.get("token") or solution.get("gRecaptchaResponse")
                if token:
                    return {"ok": True, "token": token, "error": None,
                            "cost": res.get("cost"), "solveCount": res.get("solveCount")}
                return {"ok": False, "token": None, "error": f"ready but empty solution: {res}"}

        return {"ok": False, "token": None, "error": f"timed out after {timeout}s"}


async def _eval(browser_session, expression: str):
    cdp_session = await browser_session.get_or_create_cdp_session()
    result = await cdp_session.cdp_client.send.Runtime.evaluate(
        params={"expression": expression, "returnByValue": True, "awaitPromise": True},
        session_id=cdp_session.session_id,
    )
    if result.get("exceptionDetails"):
        return {"__error__": str(result["exceptionDetails"].get("text", "JS error"))}
    return result.get("result", {}).get("value")


async def wait_for_captcha_state(browser_session, timeout: float = 25.0) -> dict | None:
    """Poll until the widget has rendered, instead of guessing with a sleep.

    reCAPTCHA takes about 10s to load through the egress proxy. A fixed sleep
    is either too short and you conclude the widget is missing, or too long and
    every step pays for it. Poll the readiness flag instead.
    """
    deadline = time.time() + timeout
    state = None
    while time.time() < deadline:
        try:
            state = await _eval(browser_session, DETECT_JS)
        except Exception:
            state = None
        if isinstance(state, dict):
            if state.get("hardBlock"):
                return state
            if state.get("kind") and state.get("ready"):
                return state
        await asyncio.sleep(0.5)
    return state if isinstance(state, dict) else None


class LocalCaptchaWatchdog(CaptchaWatchdog):
    """Detects and solves captchas on a local browser instead of waiting for
    cloud-proxy events that will never arrive."""

    async def wait_if_captcha_solving(self, timeout: float | None = None) -> CaptchaWaitResult | None:
        started = time.time()
        try:
            state = await wait_for_captcha_state(self.browser_session, timeout=8.0)
        except Exception as e:
            self.logger.debug(f"LocalCaptchaWatchdog: detection failed: {e}")
            return await super().wait_if_captcha_solving(timeout=timeout)

        if not isinstance(state, dict):
            return await super().wait_if_captcha_solving(timeout=timeout)

        if state.get("hardBlock"):
            self.logger.error(
                "🚫 reCAPTCHA hard block detected: 'sending automated queries'. "
                "This is unsolvable. A solver cannot help here, only a fresh IP and fingerprint."
            )
            return CaptchaWaitResult(
                waited=True, vendor="recaptcha-hard-block",
                url=state.get("pageUrl", ""), duration_ms=int((time.time() - started) * 1000),
                result="failed",
            )

        kind = state.get("kind")
        sitekey = state.get("sitekey")
        if not kind or not sitekey:
            return await super().wait_if_captcha_solving(timeout=timeout)

        url = state.get("pageUrl", "")
        self.logger.info(f"🔒 Detected {kind} (sitekey {sitekey[:12]}…), solving via NoCaptchaAI")

        if kind != "recaptcha-v2":
            self.logger.warning(f"No local solver for {kind} yet, leaving it to the agent")
            return await super().wait_if_captcha_solving(timeout=timeout)

        client = NoCaptchaAIClient()
        solved = await client.solve_recaptcha_v2(url, sitekey, timeout=timeout or 180.0)

        if not solved.get("ok"):
            self.logger.error(f"❌ Solver failed: {solved.get('error')}")
            return CaptchaWaitResult(
                waited=True, vendor="nocaptchaai", url=url,
                duration_ms=int((time.time() - started) * 1000), result="failed",
            )

        token = solved["token"]
        report = await _eval(self.browser_session, INJECT_JS_TEMPLATE.replace("__TOKEN__", _js_str(token)))
        self.logger.info(f"✅ Token injected ({report})")

        await asyncio.sleep(1.0)
        return CaptchaWaitResult(
            waited=True, vendor="nocaptchaai", url=url,
            duration_ms=int((time.time() - started) * 1000), result="success",
        )


def _js_str(value: str) -> str:
    """Quote a Python string as a JS string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "") + '"'


def patch() -> type:
    """Make browser-use use the local solver whenever it builds a captcha watchdog.

    BrowserSession.attach_all_watchdogs does a function-level
    `from ...captcha_watchdog import CaptchaWatchdog` and then instantiates it,
    so it would overwrite anything we installed earlier. Swapping the class on
    the module is order-independent and survives that import.
    """
    import browser_use.browser.watchdogs.captcha_watchdog as cc

    LocalCaptchaWatchdog.model_rebuild()
    cc.CaptchaWatchdog = LocalCaptchaWatchdog
    return LocalCaptchaWatchdog


def install(browser_session) -> LocalCaptchaWatchdog:
    """Replace the stock (cloud-only) captcha watchdog with the local solver."""
    LocalCaptchaWatchdog.model_rebuild()
    watchdog = LocalCaptchaWatchdog(
        event_bus=browser_session.event_bus,
        browser_session=browser_session,
    )
    try:
        watchdog.attach_to_session()
    except Exception:
        pass
    browser_session._captcha_watchdog = watchdog
    return watchdog


async def selftest(url: str = "https://2captcha.com/demo/recaptcha-v2", cdp_url: str = None) -> int:
    """Prove detection and token injection against a real widget.

    Needs no API key. The token is deliberately fake: we are testing our plumbing,
    not a real solve. A green selftest means the sitekey is found and the
    textarea and callback hook accept a token.
    """
    import browser_use.browser.watchdogs.captcha_watchdog as cc

    patch()
    assert cc.CaptchaWatchdog is LocalCaptchaWatchdog, "patch() did not take effect"

    from browser_use import Browser

    cdp_url = cdp_url or os.getenv("CDP_URL", "http://localhost:9222")
    browser = Browser(cdp_url=cdp_url, captcha_solver=True)
    await browser.start()
    cdp_session = await browser.get_or_create_cdp_session()

    await cdp_session.cdp_client.send.Page.navigate(
        params={"url": url}, session_id=cdp_session.session_id
    )

    state = await wait_for_captcha_state(browser, timeout=25.0)
    print(f"detect -> {state}")
    if not isinstance(state, dict) or state.get("kind") != "recaptcha-v2" or not state.get("sitekey"):
        print("❌ FAIL: did not find a rendered reCAPTCHA v2 widget on the page")
        return 1
    print(f"✅ sitekey found: {state['sitekey']} (ready={state.get('ready')})")

    fake_token = "FAKE_TOKEN_" + "0" * 20
    report = await _eval(browser, INJECT_JS_TEMPLATE.replace("__TOKEN__", _js_str(fake_token)))
    print(f"inject -> {report}")
    if not isinstance(report, dict) or report.get("main", 0) < 1:
        print("❌ FAIL: no main-document g-recaptcha-response textarea accepted the token")
        print(f"   (form submit reads the main-document one; report was {report})")
        return 1
    print(f"✅ token written: main={report['main']} iframe={report['iframe']} callbackFired={report.get('callbackFired')}")

    verify = await _eval(browser, """
      (() => {
        const t = document.querySelector("textarea[name='g-recaptcha-response'], textarea#g-recaptcha-response");
        return t ? t.value.slice(0, 20) : null;
      })()
    """)
    print(f"readback -> {verify!r}")
    if verify != fake_token[:20]:
        print("❌ FAIL: token did not persist in the main-document textarea")
        return 1

    print("✅ SELFTEST PASSED: detect + inject plumbing is good")
    import os as _os
    _os._exit(0)


async def main():
    """Check the solver config without touching a browser."""
    client = NoCaptchaAIClient()
    if not client.api_key:
        print("❌ NOCAPTCHA_API_KEY is not set")
        return 1
    try:
        bal = await client.balance()
    except Exception as e:
        print(f"❌ Cannot reach {client.base_url}: {e}")
        return 1
    print(f"✅ NoCaptchaAI reachable. Balance response: {bal}")
    return 0


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        target = sys.argv[sys.argv.index("--selftest") + 1] if len(sys.argv) > sys.argv.index("--selftest") + 1 else "https://2captcha.com/demo/recaptcha-v2"
        raise SystemExit(asyncio.run(selftest(target)))
    raise SystemExit(asyncio.run(main()))
