"""Guarded CAPTCHA challenge helper (detection + permission + fail-closed delivery).

Scope: reCAPTCHA v2 on an in-scope page only. Everything else is an explicit
unsupported contract, never a silent fallback.

Safety properties (enforced by construction, covered by tests):

- Pure logic only. No browser, network, environment, archive, or state access.
- No import of the legacy injector (``INJECT_JS_TEMPLATE``) or the legacy
  ``solve_if_present`` automatic solver. The legacy callback traversal can fire
  arbitrary page callbacks and retry, so this module never drives tiles,
  traverses callbacks, or injects tokens itself.
- External solver access goes through an injected ``SolverClient`` protocol.
  The configured provider must be HTTPS on an explicitly allowlisted host.
  Arbitrary endpoints, plain HTTP, embedded credentials, and non-default
  ports are rejected before any approval is requested.
- Per-action permission carries an external-solver disclosure with unknown
  cost. Approval previews contain fingerprints and lengths only: never a
  sitekey, token, API key, or credential.
- Token delivery is currently a bounded unsupported contract. There is no
  atomic exact-widget delivery primitive in the worker, so binding a token to
  one widget/callback cannot be proven single-attempt. The helper fails
  closed with ``CAPTCHA_TOKEN_BINDING_UNAVAILABLE`` instead of claiming
  success. The human-handled waiting path is the supported fallback and it
  requires genuine caller input / live browser access, never a pretended
  auto-solve.

Intended worker integration (not performed here, no worker/policy edits in
this change): revalidate page/frame/widget fingerprints after approval and
after the solver wait, dispatch exactly one bound delivery through an
isolated-world primitive, and latch uncertainty on any mismatch. See
``docs/challenges.md``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from .contracts import ApprovalRequest
from .policy import safe_url, url_in_scope

SUPPORTED_KIND = "recaptcha-v2"

# Fail-closed contract codes returned by this module (never raised directly;
# the worker maps them to PolicyBlocked).
HARD_BLOCK = "CAPTCHA_HARD_BLOCK"
UNSUPPORTED_KIND = "CAPTCHA_UNSUPPORTED_KIND"
CONTEXT_UNAVAILABLE = "CAPTCHA_CONTEXT_UNAVAILABLE"
NEEDS_INPUT = "CAPTCHA_NEEDS_INPUT"
BINDING_UNAVAILABLE = "CAPTCHA_TOKEN_BINDING_UNAVAILABLE"
OUT_OF_SCOPE = "DOMAIN_OUT_OF_SCOPE"
PROVIDER_NOT_CONFIGURED = "CAPTCHA_PROVIDER_NOT_CONFIGURED"
PROVIDER_NOT_ALLOWED = "CAPTCHA_PROVIDER_NOT_ALLOWED"
SOLVER_FAILED = "CAPTCHA_SOLVER_FAILED"
APPROVAL_DENIED = "APPROVAL_DENIED"
PAGE_CHANGED = "PAGE_CHANGED_DURING_APPROVAL"
WIDGET_CHANGED = "WIDGET_CHANGED_DURING_APPROVAL"

_SOLVER_DISCLOSURE = (
    "External solver: the page URL and sitekey leave the egress boundary "
    "to the configured provider over HTTPS. Cost is unknown until the "
    "provider answers. Single attempt only; any page/widget change aborts."
)


def fingerprint_value(value: Any) -> str:
    """Stable non-reversible fingerprint for binding comparisons (no secrets)."""
    import json

    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def safe_page_label(page_url: str) -> str:
    """Redacted page label safe for approvals, events, and logs."""
    return safe_url(page_url)


@dataclass(frozen=True)
class SolverProvider:
    """Configured external solver endpoint. Host must be explicitly allowlisted."""

    base_url: str
    allowed_hosts: tuple[str, ...]

    def validated_base(self) -> str:
        return validate_provider_url(self.base_url, self.allowed_hosts)


@dataclass(frozen=True)
class PageBinding:
    """Revalidation identity for the page/frame that owns the widget."""

    safe_page: str
    page_fingerprint: str
    frame_id: str | None = None
    loader_id: str | None = None


@dataclass(frozen=True)
class WidgetBinding:
    """Revalidation identity for one detected widget (no token material)."""

    kind: str
    ready: bool
    sitekey_present: bool
    sitekey_fingerprint: str | None = None
    widget_fingerprint: str | None = None


@dataclass(frozen=True)
class DetectedWidget:
    """Private detection result. ``repr`` is redacted; use ``safe_summary``."""

    kind: str
    ready: bool
    sitekey: str | None = field(repr=False)
    page_url: str = field(repr=False)
    frame_id: str | None = None
    loader_id: str | None = None

    def __repr__(self) -> str:  # never leak sitekey/page URL in logs
        return f"DetectedWidget(kind={self.kind!r}, ready={self.ready!r}, sitekey_present={self.sitekey is not None!r})"

    def safe_summary(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ready": self.ready,
            "sitekey_present": self.sitekey is not None,
            "sitekey_length": len(self.sitekey) if self.sitekey else 0,
            "page": safe_page_label(self.page_url),
        }

    def page_binding(self) -> PageBinding:
        # Fingerprint binds the full URL privately (path changes abort); only
        # the redacted safe_page ever leaves this object in approvals/logs.
        return PageBinding(
            safe_page=safe_page_label(self.page_url),
            page_fingerprint=fingerprint_value({"page": self.page_url}),
            frame_id=self.frame_id,
            loader_id=self.loader_id,
        )

    def widget_binding(self) -> WidgetBinding:
        return WidgetBinding(
            kind=self.kind,
            ready=self.ready,
            sitekey_present=self.sitekey is not None,
            sitekey_fingerprint=fingerprint_value({"sitekey": self.sitekey}) if self.sitekey else None,
            widget_fingerprint=fingerprint_value(
                {
                    "kind": self.kind,
                    "sitekey_present": self.sitekey is not None,
                    "frame": self.frame_id,
                    "loader": self.loader_id,
                }
            ),
        )


@dataclass(frozen=True)
class ChallengeAssessment:
    supported: bool
    kind: str | None
    ready: bool
    hard_block: bool
    error_code: str | None
    guidance: str
    widget: DetectedWidget | None = field(repr=False)

    def safe_summary(self) -> dict[str, Any]:
        return {
            "supported": self.supported,
            "kind": self.kind,
            "ready": self.ready,
            "hard_block": self.hard_block,
            "error_code": self.error_code,
            "guidance": self.guidance,
            "widget": self.widget.safe_summary() if self.widget else None,
        }


@dataclass(frozen=True)
class SolverOutcome:
    """Solver answer. ``repr`` is redacted; token never appears in summaries."""

    ok: bool
    token: str | None = field(repr=False)
    error: str | None = None

    def __repr__(self) -> str:
        return f"SolverOutcome(ok={self.ok!r}, token_present={self.token is not None!r})"

    def safe_summary(self) -> dict[str, Any]:
        return {"ok": self.ok, "token_present": self.token is not None, "error": self.error}


class SolverClient(Protocol):
    """Injected external-solver boundary. Implementations perform HTTPS I/O."""

    async def solve_recaptcha_v2(
        self, *, website_url: str, website_key: str, timeout_s: float = 180.0
    ) -> SolverOutcome: ...


def validate_provider_url(base_url: str, allowed_hosts: Sequence[str]) -> str:
    """Allowlist one configured HTTPS provider. Rejects arbitrary endpoints."""
    if not isinstance(base_url, str) or not base_url:
        raise ValueError(PROVIDER_NOT_CONFIGURED)
    try:
        parsed = urlsplit(base_url)
    except ValueError as exc:
        raise ValueError(PROVIDER_NOT_ALLOWED) from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = {h.lower().rstrip(".") for h in allowed_hosts if h}
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or not host
        or host not in allowed
    ):
        raise ValueError(PROVIDER_NOT_ALLOWED)
    return base_url.rstrip("/")


def classify_challenge(
    state: Mapping[str, Any] | None, page_url: str, allowed_domains: Sequence[str]
) -> ChallengeAssessment:
    """Classify a ``DETECT_JS``-shaped snapshot without touching the page.

    ``state`` carries ``kind``/``sitekey``/``hardBlock``/``ready`` as produced
    by the worker's isolated detector. This function only reads that mapping;
    detection JS itself stays in the worker's isolated world.
    """
    if not url_in_scope(page_url, list(allowed_domains)):
        return ChallengeAssessment(
            supported=False,
            kind=None,
            ready=False,
            hard_block=False,
            error_code=OUT_OF_SCOPE,
            guidance="Page is outside the exact allowed-host scope; no challenge action is permitted.",
            widget=None,
        )
    if not isinstance(state, Mapping):
        return ChallengeAssessment(
            supported=False,
            kind=None,
            ready=False,
            hard_block=False,
            error_code=CONTEXT_UNAVAILABLE,
            guidance="Challenge context is unavailable; fail closed without solving.",
            widget=None,
        )
    hard_block = state.get("hardBlock") is True
    if hard_block:
        return ChallengeAssessment(
            supported=False,
            kind=None,
            ready=False,
            hard_block=True,
            error_code=HARD_BLOCK,
            guidance="Provider hard block: stop and reconcile; do not retry or solve.",
            widget=None,
        )
    kind = state.get("kind")
    sitekey = state.get("sitekey")
    ready = state.get("ready") is True
    if not kind:
        return ChallengeAssessment(
            supported=False,
            kind=None,
            ready=False,
            hard_block=False,
            error_code=NEEDS_INPUT,
            guidance="No supported challenge widget detected.",
            widget=None,
        )
    if kind != SUPPORTED_KIND:
        return ChallengeAssessment(
            supported=False,
            kind=str(kind),
            ready=False,
            hard_block=False,
            error_code=UNSUPPORTED_KIND,
            guidance=f"Challenge kind {kind!r} is unsupported; only {SUPPORTED_KIND} is in scope.",
            widget=None,
        )
    widget = DetectedWidget(
        kind=str(kind),
        ready=ready,
        sitekey=sitekey if isinstance(sitekey, str) and sitekey else None,
        page_url=page_url,
        frame_id=state.get("frameId") if isinstance(state.get("frameId"), str) else None,
        loader_id=state.get("loaderId") if isinstance(state.get("loaderId"), str) else None,
    )
    if not ready or not widget.sitekey:
        return ChallengeAssessment(
            supported=False,
            kind=widget.kind,
            ready=ready,
            hard_block=False,
            error_code=NEEDS_INPUT,
            guidance="reCAPTCHA v2 widget is not ready for a guarded solve; wait for human handling.",
            widget=widget,
        )
    return ChallengeAssessment(
        supported=True,
        kind=widget.kind,
        ready=True,
        hard_block=False,
        error_code=None,
        guidance="Supported reCAPTCHA v2 widget. Explicit per-action approval with "
        "external-solver disclosure is required before any solver call.",
        widget=widget,
    )


def build_solve_permission(assessment: ChallengeAssessment, provider: SolverProvider) -> ApprovalRequest:
    """Build the explicit per-action approval (disclosure + fingerprints only)."""
    if not assessment.supported or assessment.widget is None:
        raise ValueError(assessment.error_code or NEEDS_INPUT)
    provider.validated_base()
    widget = assessment.widget
    payload = {
        "action": "solve_captcha",
        "kind": SUPPORTED_KIND,
        "page_url": safe_page_label(widget.page_url),
        "page_binding": {
            "safe_page": widget.page_binding().safe_page,
            "page_fingerprint": widget.page_binding().page_fingerprint,
        },
        "widget_binding": {
            "kind": widget.widget_binding().kind,
            "ready": widget.widget_binding().ready,
            "sitekey_present": widget.widget_binding().sitekey_present,
            "sitekey_fingerprint": widget.widget_binding().sitekey_fingerprint,
            "widget_fingerprint": widget.widget_binding().widget_fingerprint,
        },
        "provider_host": (urlsplit(provider.base_url).hostname or "").lower(),
        "disclosure": _SOLVER_DISCLOSURE,
        "cost": "unknown",
        "attempts": "single",
    }
    return ApprovalRequest(
        action="solve_captcha",
        description=(
            f"Allow one guarded reCAPTCHA v2 solve on {safe_page_label(widget.page_url)}? "
            f"{_SOLVER_DISCLOSURE}"
        ),
        payload=payload,
    )


def revalidate_binding(before: ChallengeAssessment, after: ChallengeAssessment) -> str | None:
    """Return an error code if the page/widget identity changed, else None."""
    if after.error_code == HARD_BLOCK:
        return HARD_BLOCK
    if before.widget is None or after.widget is None:
        return WIDGET_CHANGED if before.supported else (after.error_code or CONTEXT_UNAVAILABLE)
    if before.widget.page_binding() != after.widget.page_binding():
        return PAGE_CHANGED
    if before.widget.widget_binding() != after.widget.widget_binding():
        return WIDGET_CHANGED
    if not after.supported:
        return after.error_code or NEEDS_INPUT
    return None


@dataclass(frozen=True)
class DeliveryDecision:
    """Bounded token-delivery contract. ``supported`` is False until the worker
    provides an atomic exact-widget delivery primitive."""

    supported: bool
    error_code: str | None
    guidance: str
    single_attempt: bool = True

    def safe_summary(self) -> dict[str, Any]:
        return {
            "supported": self.supported,
            "error_code": self.error_code,
            "guidance": self.guidance,
            "single_attempt": self.single_attempt,
        }


def decide_token_delivery(*, binding_revalidated: bool) -> DeliveryDecision:
    """Fail closed: no safe exact-widget token delivery exists yet.

    Even with a revalidated binding, the legacy injector's callback traversal
    (``data-callback`` lookup plus ``___grecaptcha_cfg`` object-graph search
    with suppressed exceptions) cannot prove exactly one widget callback
    fired. Claiming success would risk duplicate submissions, so this helper
    reports the bounded unsupported contract instead.
    """
    if not binding_revalidated:
        return DeliveryDecision(
            supported=False,
            error_code=WIDGET_CHANGED,
            guidance="Widget binding did not revalidate; abort without delivering any token.",
        )
    return DeliveryDecision(
        supported=False,
        error_code=BINDING_UNAVAILABLE,
        guidance=(
            "Token delivery is unsupported: no atomic exact-widget callback "
            "primitive exists, and the legacy callback-traversal injector must "
            "not be used. Discard any solver token and use the human-handled "
            "waiting path."
        ),
    )


def human_fallback_guidance(assessment: ChallengeAssessment) -> dict[str, Any]:
    """Genuine-input fallback: wait with the live browser open, never pretend."""
    return {
        "fallback": "human_handled_wait",
        "requires": "genuine caller input with live browser access (ask_caller while live, "
        "or a new scoped task after reconciliation once terminated)",
        "pretend_solve": False,
        "assessment": assessment.safe_summary(),
        "guidance": (
            "Keep the browser open and ask the caller one bounded question, or stop "
            "and reconcile. Do not fabricate a token, drive tiles, or claim success."
        ),
    }


async def guarded_solve(
    *, assessment: ChallengeAssessment, provider: SolverProvider, solver: SolverClient, approve, reobserve
) -> dict[str, Any]:
    """Orchestrate detection -> approval -> solver wait -> fail-closed delivery.

    Injected boundaries only (no I/O here): ``approve`` takes an
    ``ApprovalRequest`` and returns bool; ``reobserve`` takes no arguments and
    returns a fresh ``ChallengeAssessment``; ``solver`` performs the HTTPS
    provider call. Returns redacted summaries only, never tokens/credentials.
    """
    if not assessment.supported or assessment.widget is None:
        return {
            "ok": False,
            "error_code": assessment.error_code or NEEDS_INPUT,
            "assessment": assessment.safe_summary(),
        }
    try:
        provider.validated_base()
    except ValueError:
        return {"ok": False, "error_code": PROVIDER_NOT_ALLOWED, "assessment": assessment.safe_summary()}
    request = build_solve_permission(assessment, provider)
    try:
        import asyncio

        allowed = await asyncio.wait_for(approve(request), 120)
    except Exception:  # noqa: BLE001 - approval transport failure denies by default
        allowed = False
    if allowed is not True:
        return {"ok": False, "error_code": APPROVAL_DENIED, "assessment": assessment.safe_summary()}
    fresh = await reobserve()
    if not isinstance(fresh, ChallengeAssessment):
        return {"ok": False, "error_code": CONTEXT_UNAVAILABLE, "assessment": assessment.safe_summary()}
    changed = revalidate_binding(assessment, fresh)
    if changed:
        return {"ok": False, "error_code": changed, "assessment": fresh.safe_summary()}
    outcome = await solver.solve_recaptcha_v2(
        website_url=assessment.widget.page_url, website_key=assessment.widget.sitekey or ""
    )
    if not outcome.ok:
        return {
            "ok": False,
            "error_code": SOLVER_FAILED,
            "solver": outcome.safe_summary(),
            "assessment": fresh.safe_summary(),
        }
    settled = await reobserve()
    if not isinstance(settled, ChallengeAssessment):
        return {"ok": False, "error_code": CONTEXT_UNAVAILABLE, "assessment": fresh.safe_summary()}
    changed = revalidate_binding(fresh, settled)
    # Any solver token is discarded: delivery is unsupported, so a token must
    # never reach the page through an unbound injector.
    _ = outcome.token
    decision = decide_token_delivery(binding_revalidated=changed is None)
    if changed:
        return {
            "ok": False,
            "error_code": changed,
            "solver": outcome.safe_summary(),
            "delivery": decision.safe_summary(),
            "assessment": settled.safe_summary(),
        }
    return {
        "ok": False,
        "error_code": decision.error_code,
        "solver": outcome.safe_summary(),
        "delivery": decision.safe_summary(),
        "assessment": settled.safe_summary(),
        "fallback": human_fallback_guidance(settled),
    }
