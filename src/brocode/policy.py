"""Conservative dispatch policy, not a claim of universal website read-only access.

Navigation/scrolling may themselves trigger server or page side effects. Exact host
checks constrain agent actions, not all browser network traffic: a redirect may
reach another host before we can inspect it; subsequent actions are blocked.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .contracts import ApprovalRequest, TaskRequest

_PREVIEW_KEY = secrets.token_bytes(32)


def payload_fingerprint(value: Any) -> str:
    import json
    return hmac.new(_PREVIEW_KEY, json.dumps(value, sort_keys=True, default=str).encode(), hashlib.sha256).hexdigest()


READ_ACTIONS = frozenset({
    "navigate", "wait", "extract", "search_page", "find_elements", "scroll", "find_text", "done",
})
MUTATING_ACTIONS = frozenset({"click", "input", "upload_file", "select_dropdown", "send_keys", "solve_captcha"})
# Browser/global shortcuts, address-bar typing and arbitrary key sequences are an escape hatch.
SAFE_KEYS = frozenset({
    "Enter", "Tab", "Escape", "Backspace", "Delete", "ArrowUp", "ArrowDown", "ArrowLeft",
    "ArrowRight", "Home", "End", "PageUp", "PageDown", "Space",
})


class PolicyBlocked(PermissionError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def url_in_scope(url: str, domains: list[str]) -> bool:
    try:
        parsed = urlsplit(url)
        # Forbid credentials, non-web protocols, unusual ports and hostname suffix matching.
        return (
            parsed.scheme in {"http", "https"}
            and not parsed.username and not parsed.password
            and parsed.port in {None, 80 if parsed.scheme == "http" else 443}
            and bool(parsed.hostname)
            and parsed.hostname.lower().rstrip(".").encode("idna").decode() in {
                d.encode("idna").decode() for d in domains
            }
        )
    except (ValueError, UnicodeError):
        return False


def safe_url(url: str) -> str:
    """No credentials, query, fragment or potentially secret path segments in events."""
    try:
        p = urlsplit(url)
        if p.scheme not in {"http", "https"} or not p.hostname:
            return "[non-web page]"
        return urlunsplit((p.scheme, p.hostname, "/", "", ""))
    except ValueError:
        return "[invalid URL]"


def safe_payload(params: dict[str, Any]) -> dict[str, Any]:
    """Allowlist preview fields, never echo arbitrary model data or credential values."""
    out: dict[str, Any] = {}
    for key in ("index", "clear", "down", "pages", "new_tab", "seconds"):
        value = params.get(key)
        if isinstance(value, (bool, int, float)):
            out[key] = value
    if isinstance(params.get("url"), str):
        out["target_url"] = safe_url(params["url"])
    if isinstance(params.get("path"), str):
        out["upload_name"] = Path(params["path"]).name
    if params.get("keys") in SAFE_KEYS:
        out["keys"] = params["keys"]
    if isinstance(params.get("text"), str):
        value = params["text"]
        out.update(text="[redacted]", text_length=len(value))
    # Binds permission to the exact payload even where preview text must be redacted.
    out["payload_fingerprint"] = payload_fingerprint(params)
    return out


def absolute_path(value: str | Path, *, exists: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Absolute non-symlink path required")
    return path.resolve(strict=exists)


class ActionPolicy:
    def __init__(
        self, request: TaskRequest, upload_paths: list[str],
        approve: Callable[[ApprovalRequest], Awaitable[bool]],
    ):
        self.request = request
        self.approve = approve
        self.upload_paths = {absolute_path(p, exists=True) for p in upload_paths}
        if any(not p.is_file() for p in self.upload_paths):
            raise ValueError("Uploads must be regular files")
        self.error_code: str | None = None
        self.diagnostic: dict | None = None
        self.actions = 0
        self.mutated = False

    def block(self, code: str) -> None:
        self.error_code = code
        raise PolicyBlocked(code)

    def check_scope(self, url: str, *, bootstrap: bool = False) -> None:
        if bootstrap and url == "about:blank":
            return
        if not url_in_scope(url, self.request.policy.allowed_domains):
            self.block("DOMAIN_OUT_OF_SCOPE")

    async def authorize(
        self, name: str, params: dict[str, Any], page_url: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        if self.error_code:
            self.block(self.error_code)
        self.check_scope(page_url, bootstrap=name == "navigate")
        if name not in READ_ACTIONS | MUTATING_ACTIONS:
            self.block("ACTION_NOT_ALLOWED")
        if name == "navigate":
            self.check_scope(params.get("url", ""))
        if name == "done" and params.get("files_to_display"):
            self.block("FILE_ACTION_NOT_ALLOWED")
        if name in MUTATING_ACTIONS:
            if self.request.policy.mode != "confirm":
                self.block("OBSERVE_ONLY")
            if not self.request.operation_key:
                self.block("OPERATION_KEY_REQUIRED")
            if name == "send_keys" and params.get("keys") not in SAFE_KEYS:
                self.block("KEY_SEQUENCE_NOT_ALLOWED")
            if name == "click" and (
                not isinstance(params.get("index"), int) or params["index"] < 1
                or params.get("coordinate_x") is not None or params.get("coordinate_y") is not None
            ):
                self.block("COORDINATE_ACTION_NOT_ALLOWED")
            if name == "upload_file":
                try:
                    path = absolute_path(params.get("path", ""), exists=True)
                except (OSError, ValueError):
                    self.block("UPLOAD_NOT_ALLOWED")
                if path not in self.upload_paths or not path.is_file():
                    self.block("UPLOAD_NOT_ALLOWED")
            payload = safe_payload(params)
            payload["page_url"] = safe_url(page_url)
            # Context is built by our adapter, not supplied by the model/page prompt.
            if context:
                payload["element"] = context
            approval = ApprovalRequest(
                action=name,
                description=f"Allow one {name} action on {safe_url(page_url)}? Text values are redacted.",
                payload=payload,
            )
            import asyncio
            try:
                allowed = await asyncio.wait_for(
                    self.approve(approval), self.request.policy.approval_timeout_seconds,
                )
            except (TimeoutError, ConnectionError, OSError):
                allowed = False
            if allowed is not True:
                self.block("APPROVAL_DENIED")
        # The adapter increments only after rechecking scope/context following approval.

    def dispatched(self, name: str) -> None:
        self.actions += 1
        if name in MUTATING_ACTIONS:
            # Means attempted mutation; an action error does not prove that nothing happened.
            self.mutated = True
