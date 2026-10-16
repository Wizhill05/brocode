import asyncio
import multiprocessing
from pathlib import Path

import pytest

from brocode.contracts import Policy, Status, TaskRequest, VerificationCheck, WorkerOutcome
from brocode.runtime import ProfileBusy, ProfileLease, Runtime
from brocode.settings import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        root=tmp_path,
        state_dir=tmp_path / "var",
        profile_dir=tmp_path / "profile",
        proxy_url="http://127.0.0.1:1088",
        egress_mode="tailscale",
        model="test-model",
        base_url="https://api.example.test/v1",
        api_key="test-secret-123",
        chrome_path="/no/chrome",
    )


async def good_checks(*_):
    return [{"name": "fixture", "ok": True, "detail": "synthetic preflight"}]


def request(**kwargs):
    return TaskRequest(
        goal="Read https://example.com", policy=Policy(allowed_domains=["example.com"]), **kwargs
    )


async def test_verification_required(settings):
    async def worker(*_):
        return WorkerOutcome(result="Done", checks_passed=False)

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    result = await runtime.run(request())
    assert result.status == Status.PARTIAL
    assert runtime.store.get(result.run_id).status == Status.PARTIAL
    assert (settings.state_dir / "runs" / result.run_id / "result.json").exists()


async def test_success_requires_direct_checks(settings):
    async def worker(*_):
        return WorkerOutcome(result="Page observed", checks_passed=True, steps=1, actions=1)

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    result = await runtime.run(
        request(verification=[VerificationCheck(kind="title_contains", value="Example")])
    )
    assert result.status == Status.SUCCEEDED
    assert result.verification == "passed"


async def test_api_cannot_bypass_preflight(settings):
    called = False

    async def checker(*_):
        return [{"name": "fixture", "ok": False, "detail": "not ready"}]

    async def worker(*_):
        nonlocal called
        called = True

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=checker)
    result = await runtime.run(request())
    assert not called
    assert result.error_code == "PREFLIGHT_FAILED"


async def test_cancel_releases_lease(settings):
    started = asyncio.Event()

    async def worker(*_):
        started.set()
        await asyncio.sleep(100)

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    run_id = await runtime.start(request())
    await started.wait()
    await runtime.cancel(run_id)
    await runtime.cancel_all()
    assert runtime.store.get(run_id).status == Status.CANCELLED
    with ProfileLease(settings.profile_dir):
        pass


async def test_repeated_run_cancellation_waits_for_worker_cleanup(settings):
    started, cleaning, release, finished = (asyncio.Event() for _ in range(4))

    async def worker(*_):
        started.set()
        try:
            await asyncio.sleep(60)
        finally:
            cleaning.set()
            await release.wait()
            finished.set()

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    task = asyncio.create_task(runtime.run(request()))
    await started.wait()
    task.cancel()
    await cleaning.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    with pytest.raises(ProfileBusy):
        with ProfileLease(settings.profile_dir):
            pass
    release.set()
    result = await task
    assert finished.is_set()
    assert result.status == Status.CANCELLED
    with ProfileLease(settings.profile_dir):
        pass


async def test_idempotency(settings):
    calls = 0

    async def worker(*_):
        nonlocal calls
        calls += 1
        return WorkerOutcome(result="observed")

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    first = await runtime.run(request(idempotency_key="abc"))
    second = await runtime.run(request(idempotency_key="abc"))
    assert first.run_id == second.run_id
    assert calls == 1


async def test_unsupported_hard_caps_fail_before_browser(settings):
    from brocode.contracts import Budget

    runtime = Runtime(settings, worker_runner=lambda *_: pytest.fail("Worker must not run"))
    result = await runtime.run(request(budget=Budget(max_tokens=100)))
    assert result.error_code == "UNSUPPORTED_BUDGET"


async def test_secrets_redacted_from_results(settings):
    async def worker(*_):
        raise RuntimeError(f"connection failed {settings.api_key}")

    runtime = Runtime(settings, worker_runner=worker, preflight_checker=good_checks)
    result = await runtime.run(request())
    text = (settings.state_dir / "runs" / result.run_id / "result.json").read_text()
    assert settings.api_key not in text
    assert "[REDACTED]" in text


def _compete(path, queue):
    try:
        with ProfileLease(Path(path)):
            queue.put("acquired")
    except ProfileBusy:
        queue.put("busy")


def test_profile_lease_across_processes(settings):
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    with ProfileLease(settings.profile_dir):
        process = context.Process(target=_compete, args=(str(settings.profile_dir), queue))
        process.start()
        assert queue.get(timeout=5) == "busy"
        process.join(5)
    assert process.exitcode == 0


async def test_preflight_consumes_overall_deadline(settings):
    from brocode.contracts import Budget

    async def slow_check(*_):
        await asyncio.sleep(5)
        return await good_checks()

    runtime = Runtime(settings, preflight_checker=slow_check,
                      worker_runner=lambda *_: pytest.fail("Expired setup must not launch a worker"))
    result = await runtime.run(request(budget=Budget(timeout_seconds=1)))
    assert result.error_code == "TIMEOUT"
    assert runtime.store.get(result.run_id).error_code == "TIMEOUT"
    with ProfileLease(settings.profile_dir):
        pass


async def test_operation_finalization_conflict_is_visible(settings, monkeypatch):
    runtime = Runtime(settings, preflight_checker=good_checks,
                      worker_runner=lambda *_: asyncio.sleep(0, result=WorkerOutcome(checks_passed=True)))
    def conflict(*_):
        raise ValueError("Ledger conflict")
    monkeypatch.setattr(runtime.store, "finish_operation", conflict)
    result = await runtime.run(request(operation_key="test-operation",
        verification=[VerificationCheck(kind="title_contains", value="Example")]))
    assert result.status == Status.PARTIAL
    assert result.error_code == "OPERATION_FINALIZATION_FAILED"
    assert result.verification == "unknown"


async def test_unknown_domains_request_input(settings):
    runtime = Runtime(settings)
    result = await runtime.run(TaskRequest(goal="Browse"))
    assert result.status == Status.NEEDS_INPUT


async def test_no_output_in_caller_workdir(settings, tmp_path, monkeypatch):
    cwd = tmp_path / "unrelated"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    runtime = Runtime(
        settings,
        preflight_checker=good_checks,
        worker_runner=lambda *_: asyncio.sleep(0, result=WorkerOutcome(result="ok")),
    )
    await runtime.run(request())
    assert list(cwd.iterdir()) == []
