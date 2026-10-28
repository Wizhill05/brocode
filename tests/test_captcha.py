"""Provider contract tests. No live solver, browser, or paid requests."""
import asyncio
import json
import shutil
import subprocess
from unittest.mock import AsyncMock

import pytest

from brocode.infra.captcha import DETECT_JS, NoCaptchaAIClient


@pytest.mark.skipif(not shutil.which("node"), reason="Node required for synthetic detector")
@pytest.mark.parametrize("mode,kind,ready", [
    ("turnstile", "turnstile", True),
    ("generic", None, False),
    ("spoof", None, False),
    ("recaptcha", "recaptcha-v2", True),
])
def test_detector_synthetic_dom(mode, kind, ready):
    script = r"""
const mode = MODE;
const widget = {getAttribute: () => 'synthetic-sitekey', querySelector: () => null};
const frame = {getAttribute: () => mode === 'turnstile'
  ? 'https://challenges.cloudflare.com/widget'
  : mode === 'spoof' ? 'https://example.com/google.com/recaptcha?k=bad'
  : 'https://www.google.com/recaptcha/api2/anchor?k=synthetic-sitekey'};
global.location = {href: 'https://example.com/'};
global.window = {};
global.document = {
 body: {innerText: ''},
 querySelector: (s) => {
   if (s === '.cf-turnstile' && mode === 'turnstile') return widget;
   if (s === '[data-sitekey]' && mode === 'generic') return widget;
   return null;
 },
 querySelectorAll: (s) => {
   if (s === 'iframe' && mode !== 'generic') return [frame];
   if (s === "iframe[src*='recaptcha']" && mode === 'recaptcha') return [frame];
   return [];
 }
};
console.log(JSON.stringify(eval(DETECTOR)));
""".replace("MODE", json.dumps(mode)).replace("DETECTOR", json.dumps(DETECT_JS))
    output = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                            check=True, timeout=5)
    result = json.loads(output.stdout)
    assert result["kind"] == kind
    assert result["ready"] == ready


@pytest.mark.asyncio
async def test_turnstile_success(monkeypatch):
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._post = AsyncMock(side_effect=[
        {"taskId": "synthetic-id", "errorId": 0},
        {"status": "ready", "solution": {"token": "synthetic-token"}},
    ])
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())
    result = await client.solve_turnstile("https://example.com", "synthetic-sitekey")
    assert result == {"ok": True, "token": "synthetic-token", "error": None}
    assert client._post.call_count == 2
    payload = client._post.call_args_list[0].args[1]
    assert payload["task"]["type"] == "TurnstileTaskProxyLess"


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    {"errorId": 1, "errorDescription": "DO_NOT_LEAK"},
    {"taskId": None}, [],
])
async def test_create_failure_no_retry(response):
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._post = AsyncMock(return_value=response)
    result = await client.solve_turnstile("https://example.com", "key")
    assert not result["ok"]
    assert "DO_NOT_LEAK" not in str(result)
    assert client._post.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("response,error", [
    ({"status": "failed", "errorDescription": "DO_NOT_LEAK"}, "SOLVER_RESULT_FAILED"),
    ({"status": "ready", "solution": {}}, "SOLVER_TOKEN_INVALID"),
    ({"status": "unknown"}, "SOLVER_STATUS_INVALID"),
    ({"errorId": 1, "errorDescription": "DO_NOT_LEAK"}, "SOLVER_RESULT_FAILED"),
])
async def test_poll_failure(monkeypatch, response, error):
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._post = AsyncMock(side_effect=[{"taskId": "synthetic-id"}, response])
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())
    result = await client.solve_turnstile("https://example.com", "key")
    assert result["error"] == error
    assert result["token"] is None
    assert "DO_NOT_LEAK" not in str(result)
    assert client._post.call_count == 2


@pytest.mark.asyncio
async def test_timeout_and_cancel():
    client = NoCaptchaAIClient(api_key="synthetic-key")
    started = asyncio.Event()

    async def blocked(*args):
        started.set()
        await asyncio.Event().wait()

    client._post = AsyncMock(side_effect=blocked)
    result = await client.solve_turnstile("https://example.com", "key", timeout=0.01)
    assert result["error"] == "SOLVER_TIMEOUT_UNCERTAIN"
    task = asyncio.create_task(client.solve_turnstile("https://example.com", "key"))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client._post.call_count == 2


@pytest.mark.asyncio
async def test_endpoint_denied_before_dispatch():
    client = NoCaptchaAIClient(api_key="synthetic-key", base_url="https://example.com")
    client._post = AsyncMock()
    assert (await client.solve_turnstile("https://example.com", "key"))["error"] == "SOLVER_ENDPOINT_NOT_ALLOWED"
    client._post.assert_not_called()


@pytest.mark.asyncio
async def test_transport_denies_redirects(monkeypatch):
    import urllib.request

    def fake_build(*handlers):
        redirect = next(h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        with pytest.raises(ValueError, match="redirect denied"):
            redirect.redirect_request(None, None, 307, "redirect", {}, "https://example.com")
        raise RuntimeError("synthetic transport failure")

    monkeypatch.setattr(urllib.request, "build_opener", fake_build)
    client = NoCaptchaAIClient(api_key="synthetic-key")
    result = await client.solve_turnstile("https://example.com", "key")
    assert result["error"] == "SOLVER_REQUEST_UNCERTAIN"


@pytest.mark.parametrize("base", ["http://api.nocaptchaai.com", "https://example.test",
                                  "https://api.nocaptchaai.com:444", "https://user:secret@api.nocaptchaai.com"])
async def test_validation_refuses_unapproved_endpoint_before_sending_key(base):
    client = NoCaptchaAIClient(api_key="synthetic-key", base_url=base)
    client._request = AsyncMock()
    assert await client.validate() == (False, "Solver endpoint not allowed")
    client._request.assert_not_called()


@pytest.mark.parametrize("status,data,expected", [
    (200, {"balance": 1.25}, (True, "Solver key accepted; balance available")),
    (200, {"balance": 0}, (True, "Solver key accepted; zero balance")),
    (404, {"errorId": 1, "error": "Invalid apikey DO_NOT_LEAK"}, (False, "Solver key rejected")),
    (200, {"errorId": 1, "error": "DO_NOT_LEAK"}, (False, "Solver rejected validation")),
    (200, [], (False, "Solver rejected validation")),
    (200, {}, (False, "Solver validation response invalid")),
    (200, {"balance": True}, (False, "Solver validation response invalid")),
    (200, {"balance": float("nan")}, (False, "Solver validation response invalid")),
])
async def test_validation_requires_authenticated_balance(status, data, expected):
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._request = AsyncMock(return_value=(status, data))
    assert await client.validate() == expected
    client._request.assert_awaited_once_with("/balance")


async def test_validation_transport_does_not_forward_key_on_redirect(monkeypatch):
    import urllib.request

    def build(*handlers):
        assert next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler)).proxies == {}
        redirect = next(h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        for code in (301, 302, 303, 307, 308):
            with pytest.raises(ValueError, match="redirect denied"):
                redirect.redirect_request(None, None, code, "", {}, "https://example.test")
        raise OSError("DO_NOT_LEAK")

    monkeypatch.setattr(urllib.request, "build_opener", build)
    result = await NoCaptchaAIClient(api_key="synthetic-key").validate()
    assert result == (False, "Solver validation request failed")


@pytest.mark.parametrize("oversized", [False, True])
async def test_validation_uses_get_header_and_bounded_response(monkeypatch, oversized):
    import io
    import urllib.request

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            assert size == 1_048_577
            return super().read(size)

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.nocaptchaai.com/balance"
            assert request.get_method() == "GET"
            assert request.get_header("Apikey") == "synthetic-key"
            assert request.data is None and timeout <= 30
            return Response(b"x" * 1_048_577 if oversized else b'{"balance":1}')

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    ok, detail = await NoCaptchaAIClient(api_key="synthetic-key").validate()
    assert ok is not oversized
    assert "synthetic-key" not in detail


async def test_validation_cancellation_propagates():
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._request = AsyncMock(side_effect=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await client.validate()


async def test_turnstile_polls_processing_then_ready(monkeypatch):
    """Placeholder vs idle/processing statuses must keep polling the same task."""
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._post = AsyncMock(side_effect=[
        {"taskId": "synthetic-id", "errorId": 0},
        {"status": "idle"},
        {"status": "processing"},
        {"status": "ready", "solution": {"token": "synthetic-token"}},
    ])
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())
    result = await client.solve_turnstile("https://example.com", "synthetic-sitekey")
    assert result == {"ok": True, "token": "synthetic-token", "error": None}
    assert client._post.await_count == 4
    assert client._post.call_args_list[0].args[0] == "/createTask"
    polls = client._post.call_args_list[1:]
    assert all(c.args[0] == "/getTaskResult" for c in polls)
    assert all(c.args[1] == {"clientKey": "synthetic-key", "taskId": "synthetic-id"} for c in polls)


async def test_turnstile_timeout_and_cancel_after_create_never_duplicate_create(monkeypatch):
    """A hang after a created task must not retry the billable create dispatch."""
    client = NoCaptchaAIClient(api_key="synthetic-key")
    calls = []
    started = asyncio.Event()
    blocked = asyncio.Event()

    async def fake_post(path, payload):
        calls.append(path)
        if path == "/createTask":
            return {"taskId": "synthetic-id", "errorId": 0}
        started.set()
        await blocked.wait()

    client._post = fake_post
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())

    result = await client.solve_turnstile("https://example.com", "k", timeout=0.01)
    assert result == {"ok": False, "token": None, "error": "SOLVER_TIMEOUT_UNCERTAIN"}
    assert calls == ["/createTask", "/getTaskResult"]

    calls.clear()
    started.clear()
    task = asyncio.create_task(client.solve_turnstile("https://example.com", "k"))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == ["/createTask", "/getTaskResult"]


@pytest.mark.parametrize("poll_effect,expected", [
    (RuntimeError("DO_NOT_LEAK"), "SOLVER_REQUEST_UNCERTAIN"),
    ([], "SOLVER_RESULT_FAILED"),
    ({"status": "ready", "solution": None}, "SOLVER_TOKEN_INVALID"),
    ({"status": "ready", "solution": {"token": "t" * 32769}}, "SOLVER_TOKEN_INVALID"),
    ({"status": "ready", "solution": {"token": 7}}, "SOLVER_TOKEN_INVALID"),
])
async def test_turnstile_poll_transport_and_result_failures_sanitized(monkeypatch,
                                                                      poll_effect, expected):
    client = NoCaptchaAIClient(api_key="synthetic-key")
    client._post = AsyncMock(side_effect=[{"taskId": "synthetic-id", "errorId": 0}, poll_effect])
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())
    result = await client.solve_turnstile("https://example.com", "k")
    assert result == {"ok": False, "token": None, "error": expected}
    assert "DO_NOT_LEAK" not in str(result)
    assert client._post.await_count == 2


@pytest.mark.parametrize("api_key,url,key,timeout,expected", [
    ("", "https://example.com/open/role", "k", 1.0, "SOLVER_KEY_REQUIRED"),
    ("synthetic-key", "http://example.com", "k", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://user:pass@example.com/", "k", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://example.com:8443/", "k", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "example.com", "k", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", None, "k", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://example.com", "   ", 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://example.com", "k" * 2001, 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://example.com", 7, 1.0, "SOLVER_INPUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", True, "SOLVER_TIMEOUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", 0, "SOLVER_TIMEOUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", -1, "SOLVER_TIMEOUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", 301, "SOLVER_TIMEOUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", float("inf"), "SOLVER_TIMEOUT_INVALID"),
    ("synthetic-key", "https://example.com", "k", float("nan"), "SOLVER_TIMEOUT_INVALID"),
], ids=["missing-key", "scheme-http", "userinfo-url", "port-8443", "no-scheme", "url-none",
        "blank-key", "key-too-long", "key-non-str", "timeout-bool", "timeout-zero",
        "timeout-negative", "timeout-over-300", "timeout-inf", "timeout-nan"])
async def test_turnstile_input_validation_refuses_before_paid_dispatch(monkeypatch,
                                                                       api_key, url, key,
                                                                       timeout, expected):
    client = NoCaptchaAIClient(api_key=api_key)
    client._post = AsyncMock()
    result = await client.solve_turnstile(url, key, timeout=timeout)
    assert result == {"ok": False, "token": None, "error": expected}
    client._post.assert_not_called()


async def test_turnstile_create_and_poll_use_bounded_synthetic_transport(monkeypatch):
    """Real _request path: POST body/headers for create and poll, 2000-char key accepted."""
    import io
    import urllib.request

    request_log = []

    def fake_build(*handlers):
        assert next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler)).proxies == {}
        redirect = next(h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        with pytest.raises(ValueError, match="redirect denied"):
            redirect.redirect_request(None, None, 307, "redirect", {}, "https://example.test")
        return Opener()

    class Response(io.BytesIO):
        status = 200

        def read(self, size=-1):
            assert size == 1_048_577
            return super().read(size)

    class Opener:
        def open(self, request, timeout):
            request_log.append(request)
            assert timeout <= 30
            assert request.get_method() == "POST"
            assert request.get_header("Apikey") is None
            assert len(request.data) <= 8192
            assert request.full_url in ("https://api.nocaptchaai.com/createTask",
                                        "https://api.nocaptchaai.com/getTaskResult")
            if request.full_url.endswith("/createTask"):
                assert json.loads(request.data) == {
                    "clientKey": "synthetic-key",
                    "task": {"type": "TurnstileTaskProxyLess",
                             "websiteURL": "https://example.com/open/role",
                             "websiteKey": "k" * 2000},
                }
                return Response(b'{"errorId":0,"taskId":"synthetic-id"}')
            assert json.loads(request.data) == {"clientKey": "synthetic-key",
                                                "taskId": "synthetic-id"}
            return Response(b'{"status":"ready","solution":{"token":"synthetic-token"}}')

    monkeypatch.setattr(urllib.request, "build_opener", fake_build)
    monkeypatch.setattr("brocode.infra.captcha.asyncio.sleep", AsyncMock())
    result = await NoCaptchaAIClient(api_key="synthetic-key").solve_turnstile(
        "https://example.com/open/role", "k" * 2000)
    assert result == {"ok": True, "token": "synthetic-token", "error": None}
    assert len(request_log) == 2


@pytest.mark.parametrize("body", [b"x" * 1_048_577, b"{not json"], ids=["oversized", "invalid-json"])
async def test_turnstile_transport_malformed_bodies_sanitized(monkeypatch, body):
    import io
    import urllib.request

    class Response(io.BytesIO):
        status = 200

    class Opener:
        def open(self, request, timeout):
            return Response(body)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    result = await NoCaptchaAIClient(api_key="synthetic-key").solve_turnstile(
        "https://example.com", "k")
    assert result == {"ok": False, "token": None, "error": "SOLVER_REQUEST_UNCERTAIN"}
