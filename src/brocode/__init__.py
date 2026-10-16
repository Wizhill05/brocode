"""Brocode's guarded Python API. Importing this module never starts a browser."""

from __future__ import annotations

from .contracts import Budget, Policy, TaskRequest, TaskResult, VerificationCheck

__version__ = "0.1.0"
__all__ = ["TaskRequest", "TaskResult", "Policy", "Budget", "VerificationCheck", "run_task"]


async def run_task(
    task_prompt: str,
    model_name: str | None = None,
    max_actions: int = 30,
    record: bool = True,
    record_video_dir: str | None = None,
    available_file_paths: list | None = None,
    **kwargs,
) -> dict:
    """Compatibility API with mandatory preflight, private artifacts and conservative policy.

    New callers should construct TaskRequest and call Runtime.run directly.
    Arbitrary recording destinations are deliberately no longer supported.
    """
    if record_video_dir is not None:
        raise ValueError("Recording paths are runtime-owned; use BROCODE_STATE_DIR")
    from .cli import infer_domains
    from .runtime import Runtime

    runtime = Runtime()
    handles = [runtime.store.register_upload(path)["handle"] for path in available_file_paths or []]
    policy = kwargs.pop("policy", Policy(allowed_domains=infer_domains(task_prompt)))
    request = TaskRequest(
        goal=task_prompt,
        model=model_name,
        budget=Budget(max_steps=max_actions),
        policy=policy,
        record=record,
        upload_handles=handles,
        **kwargs,
    )
    result = await runtime.run(request)
    payload = result.model_dump(mode="json")
    payload.update(
        {
            "task_id": result.run_id,
            "artifact": str(runtime.settings.state_dir / "runs" / result.run_id / "result.json"),
            "recordings": [e.path for e in result.evidence if e.kind == "video"],
            "screenshot": next((e.path for e in result.evidence if e.kind == "screenshot"), None),
        }
    )
    return payload
