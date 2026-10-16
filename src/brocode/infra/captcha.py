"""Token-based CAPTCHA plumbing preserved from captcha_solver.py.

No global watchdog patch: all solving and token injection goes through the same
scope/operation/approval policy as other mutations. Hard blocks are terminal.
The legacy top-level selftest remains untouched; this module never drives tiles.
"""
from __future__ import annotations

import asyncio
import os
import time

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

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
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
        except ValueError:
            return False, "Solver returned invalid JSON"

        text = json.dumps(data)
        if "Invalid apikey" in text or "invalid apikey" in text.lower():
            return False, "Solver key rejected"
        if isinstance(data, dict) and data.get("errorId"):
            return False, "Solver rejected validation"
        return status == 200, "Solver validation completed"

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
        except Exception:  # noqa: BLE001 - detection failure is non-authorizing
            state = None
        if isinstance(state, dict):
            if state.get("hardBlock"):
                return state
            if state.get("kind") and state.get("ready"):
                return state
        await asyncio.sleep(0.5)
    return state if isinstance(state, dict) else None




def _js_str(value: str) -> str:
    import json
    return json.dumps(value)


async def solve_if_present(browser, policy) -> None:
    state = await _eval(browser, DETECT_JS)
    if not isinstance(state, dict):
        return
    if state.get('hardBlock'):
        policy.block('CAPTCHA_HARD_BLOCK')
    if not state.get('kind'):
        return
    state = await wait_for_captcha_state(browser, timeout=15)
    if not state or not state.get('ready') or not state.get('sitekey'):
        policy.block('CAPTCHA_NEEDS_INPUT')
    if state.get('kind') != 'recaptcha-v2' or not os.environ.get('NOCAPTCHA_API_KEY'):
        policy.block('CAPTCHA_NEEDS_INPUT')
    url = await browser.get_current_page_url()
    await policy.authorize('solve_captcha', {'kind': 'recaptcha-v2'}, url,
                           {'widget': 'reCAPTCHA v2', 'effect': 'send page URL/sitekey to configured solver and inject token'})
    if url != await browser.get_current_page_url():
        policy.block('PAGE_CHANGED_DURING_APPROVAL')
    policy.check_scope(url)
    try:
        solved = await NoCaptchaAIClient().solve_recaptcha_v2(url, state['sitekey'])
    except Exception:  # noqa: BLE001 - vendor exceptions may contain credentials
        policy.block('CAPTCHA_SOLVER_FAILED')
    if not solved.get('ok'):
        policy.block('CAPTCHA_SOLVER_FAILED')
    if url != await browser.get_current_page_url():
        policy.block('PAGE_CHANGED_DURING_APPROVAL')
    policy.check_scope(url)
    policy.dispatched('solve_captcha')
    report = await _eval(browser, INJECT_JS_TEMPLATE.replace('__TOKEN__', _js_str(solved['token'])))
    if not isinstance(report, dict) or not report.get('main'):
        policy.block('CAPTCHA_INJECTION_FAILED')
