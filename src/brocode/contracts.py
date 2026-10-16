"""Transport-independent public contracts. No browser imports at module import time."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    NEEDS_INPUT = "needs_input"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL = {
    Status.NEEDS_INPUT,
    Status.SUCCEEDED,
    Status.PARTIAL,
    Status.BLOCKED,
    Status.FAILED,
    Status.CANCELLED,
}


class Policy(StrictModel):
    mode: Literal["observe", "confirm"] = "observe"
    allowed_domains: list[str] = Field(default_factory=list)
    approval_timeout_seconds: int = Field(default=120, ge=1, le=900)

    @field_validator("allowed_domains")
    @classmethod
    def domains(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or any(c in value for c in "/:@* "):
                raise ValueError("Domains must be exact hostnames, without schemes, ports or wildcards")
        return sorted(set(v.lower().rstrip(".") for v in values))


class Budget(StrictModel):
    max_steps: int = Field(default=30, ge=1, le=200)
    timeout_seconds: int = Field(default=600, ge=1, le=3600)
    max_tokens: int | None = Field(default=None, ge=1)
    max_cost_usd: float | None = Field(default=None, gt=0)


class VerificationCheck(StrictModel):
    kind: Literal["url_contains", "page_text_contains", "title_contains"]
    value: str = Field(min_length=1, max_length=2000)


class TaskRequest(StrictModel):
    goal: str = Field(min_length=1, max_length=50000)
    caller_id: str = Field(default="local", min_length=1, max_length=128)
    session_id: str | None = None
    profile_id: Literal["default"] = "default"
    model: str | None = None
    policy: Policy = Field(default_factory=Policy)
    budget: Budget = Field(default_factory=Budget)
    upload_handles: list[str] = Field(default_factory=list)
    playbook_id: str | None = None
    inputs: dict[str, Any] = Field(default_factory=dict)
    verification: list[VerificationCheck] = Field(default_factory=list)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    operation_key: str | None = Field(default=None, min_length=1, max_length=500)
    record: bool = True


class TaskEvent(StrictModel):
    kind: str
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=now)


class Evidence(StrictModel):
    kind: str
    path: str | None = None
    url: str | None = None
    description: str = ""


class TaskResult(StrictModel):
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str | None = None
    status: Status = Status.QUEUED
    result: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    verification: Literal["not_requested", "passed", "failed", "unknown"] = "not_requested"
    evidence: list[Evidence] = Field(default_factory=list)
    error_code: str | None = None
    created_at: str = Field(default_factory=now)
    updated_at: str = Field(default_factory=now)
    model: str | None = None
    steps: int = 0
    actions: int = 0
    usage: dict[str, Any] = Field(default_factory=dict)
    cost_usd: float | None = None


class ApprovalRequest(StrictModel):
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    action: str
    description: str
    payload: dict[str, Any] = Field(default_factory=dict)


class WorkerOutcome(StrictModel):
    result: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    checks_passed: bool = False
    evidence: list[Evidence] = Field(default_factory=list)
    steps: int = 0
    actions: int = 0
    mutated: bool = False
    error_code: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
