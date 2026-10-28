"""Synthetic tests for the guarded CAPTCHA helper. No browser, network, env, or archive."""

import pytest

from brocode import challenges
from brocode.challenges import (
    BINDING_UNAVAILABLE,
    ChallengeAssessment,
    SolverOutcome,
    SolverProvider,
)


def provider() -> SolverProvider:
    return SolverProvider(base_url="https://api.nocaptchaai.com", allowed_hosts=("api.nocaptchaai.com",))


def supported_state(**overrides):
    state = {"kind": "recaptcha-v2", "sitekey": "synthetic-sitekey", "hardBlock": False, "ready": True}
    state.update(overrides)
    return state


def assessment(**overrides) -> ChallengeAssessment:
    return challenges.classify_challenge(
        supported_state(**overrides.pop("state", {})), "https://example.com/page", ["example.com"]
    )


def test_supported_recaptcha_v2_classified():
    out = challenges.classify_challenge(supported_state(), "https://example.com/a", ["example.com"])
    assert out.supported and out.error_code is None and out.widget is not None
    assert out.widget.sitekey == "synthetic-sitekey"
    assert "synthetic-sitekey" not in repr(out.widget)
    assert "synthetic-sitekey" not in str(out.safe_summary())


def test_out_of_scope_fails_closed():
    out = challenges.classify_challenge(supported_state(), "https://evil.test/", ["example.com"])
    assert not out.supported and out.error_code == "DOMAIN_OUT_OF_SCOPE" and out.widget is None


def test_hard_block_and_unsupported_kinds_fail_closed():
    hard = challenges.classify_challenge(
        supported_state(hardBlock=True), "https://example.com/", ["example.com"]
    )
    assert hard.error_code == "CAPTCHA_HARD_BLOCK" and not hard.supported
    turnstile = challenges.classify_challenge(
        {"kind": "turnstile", "ready": True}, "https://example.com/", ["example.com"]
    )
    assert turnstile.error_code == "CAPTCHA_UNSUPPORTED_KIND" and not turnstile.supported
    missing = challenges.classify_challenge(None, "https://example.com/", ["example.com"])
    assert missing.error_code == "CAPTCHA_CONTEXT_UNAVAILABLE"
    unready = challenges.classify_challenge(
        supported_state(ready=False), "https://example.com/", ["example.com"]
    )
    assert unready.error_code == "CAPTCHA_NEEDS_INPUT"


def test_provider_allowlist_rejects_arbitrary_endpoints():
    with pytest.raises(ValueError, match="CAPTCHA_PROVIDER_NOT_ALLOWED"):
        SolverProvider(
            base_url="http://api.nocaptchaai.com", allowed_hosts=("api.nocaptchaai.com",)
        ).validated_base()
    with pytest.raises(ValueError, match="CAPTCHA_PROVIDER_NOT_ALLOWED"):
        SolverProvider(
            base_url="https://evil.test/solve", allowed_hosts=("api.nocaptchaai.com",)
        ).validated_base()
    with pytest.raises(ValueError, match="CAPTCHA_PROVIDER_NOT_ALLOWED"):
        SolverProvider(
            base_url="https://user:pass@api.nocaptchaai.com", allowed_hosts=("api.nocaptchaai.com",)
        ).validated_base()
    with pytest.raises(ValueError, match="CAPTCHA_PROVIDER_NOT_ALLOWED"):
        SolverProvider(
            base_url="https://api.nocaptchaai.com:8443", allowed_hosts=("api.nocaptchaai.com",)
        ).validated_base()
    assert provider().validated_base() == "https://api.nocaptchaai.com"


def test_permission_discloses_external_solver_and_hides_secrets():
    out = assessment()
    approval = challenges.build_solve_permission(out, provider())
    assert approval.action == "solve_captcha"
    assert "External solver" in approval.description and "Cost is unknown" in approval.description
    dumped = approval.model_dump_json()
    assert "synthetic-sitekey" not in dumped
    assert "synthetic-token" not in dumped
    assert "token" not in str(approval.payload.get("widget_binding", {}))
    assert approval.payload["cost"] == "unknown"
    assert approval.payload["provider_host"] == "api.nocaptchaai.com"
    assert "synthetic-sitekey" not in str(approval.payload)


def test_binding_revalidation_detects_page_and_widget_change():
    before = assessment()
    same = challenges.classify_challenge(supported_state(), "https://example.com/page", ["example.com"])
    assert challenges.revalidate_binding(before, same) is None
    moved = challenges.classify_challenge(supported_state(), "https://example.com/other", ["example.com"])
    assert challenges.revalidate_binding(before, moved) == "PAGE_CHANGED_DURING_APPROVAL"
    swapped = challenges.classify_challenge(
        supported_state(sitekey="other-key"), "https://example.com/page", ["example.com"]
    )
    assert challenges.revalidate_binding(before, swapped) == "WIDGET_CHANGED_DURING_APPROVAL"


def test_token_delivery_always_fails_closed():
    decision = challenges.decide_token_delivery(binding_revalidated=True)
    assert not decision.supported and decision.error_code == BINDING_UNAVAILABLE
    assert decision.single_attempt is True
    stale = challenges.decide_token_delivery(binding_revalidated=False)
    assert not stale.supported and stale.error_code == "WIDGET_CHANGED_DURING_APPROVAL"


class FakeSolver:
    def __init__(self):
        self.calls = []

    async def solve_recaptcha_v2(self, *, website_url, website_key, timeout_s=180.0):
        self.calls.append((website_url, website_key))
        assert website_key == "synthetic-sitekey"
        return SolverOutcome(ok=True, token="synthetic-token")


@pytest.mark.asyncio
async def test_guarded_solve_discards_token_and_fails_closed_on_delivery():
    before = assessment()
    solver = FakeSolver()
    seen = {}

    async def approve(request):
        seen["request"] = request
        return True

    async def reobserve():
        return challenges.classify_challenge(supported_state(), "https://example.com/page", ["example.com"])

    result = await challenges.guarded_solve(
        assessment=before, provider=provider(), solver=solver, approve=approve, reobserve=reobserve
    )
    assert result["ok"] is False
    assert result["error_code"] == BINDING_UNAVAILABLE
    assert solver.calls and "synthetic-token" not in str(result)
    assert "fallback" in result and result["fallback"]["pretend_solve"] is False


@pytest.mark.asyncio
async def test_guarded_solve_denies_without_approval_and_aborts_on_change():
    before = assessment()

    async def deny(request):
        return False

    async def reobserve():
        raise AssertionError("must not reobserve or solve after denial")

    class NeverSolver:
        async def solve_recaptcha_v2(self, **kwargs):
            raise AssertionError("solver must not run without approval")

    result = await challenges.guarded_solve(
        assessment=before, provider=provider(), solver=NeverSolver(), approve=deny, reobserve=reobserve
    )
    assert result["error_code"] == "APPROVAL_DENIED"

    async def approve(request):
        return True

    async def changed():
        return challenges.classify_challenge(
            supported_state(sitekey="rotated"), "https://example.com/page", ["example.com"]
        )

    result = await challenges.guarded_solve(
        assessment=before, provider=provider(), solver=FakeSolver(), approve=approve, reobserve=changed
    )
    assert result["error_code"] == "WIDGET_CHANGED_DURING_APPROVAL"


def test_human_fallback_requires_genuine_input():
    fallback = challenges.human_fallback_guidance(assessment())
    assert fallback["requires"].startswith("genuine caller input")
    assert fallback["pretend_solve"] is False


def test_no_legacy_unsafe_imports():
    import brocode.challenges as module

    assert getattr(module, "INJECT_JS_TEMPLATE", None) is None
    assert getattr(module, "solve_if_present", None) is None
    with open(module.__file__) as handle:
        source = handle.read()
    assert "from .infra" not in source and "from brocode.infra" not in source
    assert "os.environ" not in source and "getenv" not in source
    assert "urlopen" not in source and "INJECT_JS_TEMPLATE.replace" not in source
