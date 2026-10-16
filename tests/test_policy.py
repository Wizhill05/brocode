
import pytest

from brocode.contracts import Policy, TaskRequest
from brocode.policy import ActionPolicy, PolicyBlocked, safe_payload, safe_url, url_in_scope


async def yes(_):
    return True


def request(mode="observe", operation=None):
    return TaskRequest(goal="test", policy=Policy(mode=mode, allowed_domains=["example.com"]), operation_key=operation)


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com/a", "https://EXAMPLE.COM/a"])
def test_exact_scope_allowed(url):
    assert url_in_scope(url, ["example.com"])


@pytest.mark.parametrize("url", [
    "https://other.example.com", "https://example.com.evil.test", "https://evil.test/?example.com",
    "https://u:secret@example.com", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x",
    "https://example.com:8443", "https://example.com:bad", "about:blank", "//example.com",
])
def test_scope_fails_closed(url):
    assert not url_in_scope(url, ["example.com"])


@pytest.mark.asyncio
@pytest.mark.parametrize("name,params", [
    ("click", {"index": 1}), ("input", {"index": 1, "text": "password"}),
    ("send_keys", {"keys": "Enter"}), ("upload_file", {"index": 1, "path": "/tmp/a"}),
    ("select_dropdown", {"index": 1, "text": "a"}), ("evaluate", {"code": "x"}),
    ("read_file", {"file_name": "/etc/passwd"}), ("write_file", {"file_name": "a"}),
    ("shell", {}), ("unknown", {}), ("switch", {}), ("go_back", {}), ("search", {}),
    ("solve_captcha", {}),
])
async def test_observe_denies_interaction_and_escapes(name, params):
    called = []
    async def approve(a):
        called.append(a)
        return True
    policy = ActionPolicy(request(), [], approve)
    with pytest.raises(PolicyBlocked):
        await policy.authorize(name, params, "https://example.com")
    assert not called
    assert not policy.mutated


@pytest.mark.asyncio
@pytest.mark.parametrize("name,params", [
    ("navigate", {"url": "https://example.com/a"}), ("scroll", {}), ("wait", {}),
    ("extract", {}), ("search_page", {}), ("find_elements", {}), ("find_text", {}), ("done", {"text": "ok"}),
])
async def test_observe_read_actions(name, params):
    policy = ActionPolicy(request(), [], yes)
    await policy.authorize(name, params, "https://example.com")
    assert policy.actions == 0
    policy.dispatched(name)
    assert policy.actions == 1
    assert not policy.mutated


@pytest.mark.asyncio
async def test_only_bootstrap_navigation_allows_blank():
    policy = ActionPolicy(request(), [], yes)
    await policy.authorize("navigate", {"url": "https://example.com"}, "about:blank")
    with pytest.raises(PolicyBlocked, match="DOMAIN_OUT_OF_SCOPE"):
        await policy.authorize("done", {}, "about:blank")


@pytest.mark.asyncio
async def test_out_of_scope_target_is_blocked_before_approval():
    policy = ActionPolicy(request("confirm", "operation"), [], yes)
    with pytest.raises(PolicyBlocked, match="DOMAIN_OUT_OF_SCOPE"):
        await policy.authorize("navigate", {"url": "https://other.example.com"}, "https://example.com")


@pytest.mark.asyncio
async def test_mutation_requires_operation_key():
    policy = ActionPolicy(request("confirm"), [], yes)
    with pytest.raises(PolicyBlocked, match="OPERATION_KEY_REQUIRED"):
        await policy.authorize("click", {"index": 1}, "https://example.com")


@pytest.mark.asyncio
async def test_approval_preview_never_discloses_passwords():
    seen = []
    async def approve(a):
        seen.append(a)
        return True
    policy = ActionPolicy(request("confirm", "op"), [], approve)
    await policy.authorize("input", {"index": 3, "text": "sensitive-password"},
                           "https://example.com/private-token?key=hidden", {"tag": "input", "type": "password"})
    payload = seen[0].model_dump_json()
    assert "sensitive-password" not in payload
    assert "hidden" not in payload
    assert "private-token" not in payload
    assert '"index":3' in payload
    assert "password" in payload  # field type, not field value
    assert seen[0].action == "input"


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [None, ConnectionError(), TimeoutError()])
async def test_denial_and_disconnected_support_block(error):
    async def denied(a):
        if error:
            raise error
        return False
    policy = ActionPolicy(request("confirm", "op"), [], denied)
    with pytest.raises(PolicyBlocked, match="APPROVAL_DENIED"):
        await policy.authorize("click", {"index": 1}, "https://example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize("keys", ["Control+l", "Meta+o", "javascript:alert(1)", "secret text", "F12", "Control+Shift+j"])
async def test_browser_escape_keys_denied_even_with_permission(keys):
    policy = ActionPolicy(request("confirm", "op"), [], yes)
    with pytest.raises(PolicyBlocked, match="KEY_SEQUENCE_NOT_ALLOWED"):
        await policy.authorize("send_keys", {"keys": keys}, "https://example.com")


@pytest.mark.asyncio
async def test_upload_allowlist_cannot_expand_to_downloads(tmp_path):
    upload = tmp_path / "resume.pdf"
    upload.write_bytes(b"registered")
    other = tmp_path / "download.pdf"
    other.write_bytes(b"unregistered")
    policy = ActionPolicy(request("confirm", "op"), [str(upload)], yes)
    await policy.authorize("upload_file", {"index": 1, "path": str(upload)}, "https://example.com")
    with pytest.raises(PolicyBlocked, match="UPLOAD_NOT_ALLOWED"):
        await policy.authorize("upload_file", {"index": 1, "path": str(other)}, "https://example.com")


@pytest.mark.asyncio
async def test_replaced_upload_symlink_is_rejected(tmp_path):
    upload = tmp_path / "resume.pdf"
    upload.write_bytes(b"registered")
    other = tmp_path / "secret"
    other.write_bytes(b"secret")
    policy = ActionPolicy(request("confirm", "op"), [str(upload)], yes)
    upload.unlink()
    upload.symlink_to(other)
    with pytest.raises(PolicyBlocked, match="UPLOAD_NOT_ALLOWED"):
        await policy.authorize("upload_file", {"index": 1, "path": str(upload)}, "https://example.com")


def test_safe_preview_is_allowlisted():
    payload = safe_payload({"text": "hunter2", "password": "hunter2", "query": "private", "index": 1})
    assert "hunter2" not in str(payload)
    assert "private" not in str(payload)
    assert payload["index"] == 1
    assert safe_url("https://u:pass@example.com/secret?token=a#b") == "https://example.com/"
