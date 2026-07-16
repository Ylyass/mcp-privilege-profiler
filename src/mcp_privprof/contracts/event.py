"""Pydantic boundary model for privacy-minimized event-v1 records."""

from __future__ import annotations

from datetime import UTC, datetime
from re import fullmatch
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_privprof.domain.limits import LimitType
from mcp_privprof.domain.policy import PolicyEffect


class AuditEventV1(BaseModel):
    """A single JSONL event without raw tool arguments or result bodies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_schema_version: Literal["1.0"] = "1.0"
    event_type: Literal[
        "policy_decision",
        "tool_completion",
        "permit_decision",
        "enforcement_failure",
    ]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    trace_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    server_id: str = Field(min_length=1)
    server_trust: Literal["approved", "unapproved"]
    tool_name: str = Field(min_length=1)
    tool_fingerprint: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    policy_id: str | None = None
    tool_effect: PolicyEffect
    decision: Literal["allowed", "denied", "approval_required"]
    reason_code: str = Field(min_length=1)
    primary_risk_category: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    drift_severity: Literal[
        "none",
        "informational",
        "review_required",
        "security_widening",
        "breaking",
    ]
    limit_type: LimitType
    audit_status: Literal["written", "failed"]
    duration_ms: int | None = Field(default=None, ge=0)
    argument_key_names: tuple[str, ...] = Field(default=(), max_length=64)
    argument_size_bytes: int | None = Field(default=None, ge=0)
    path_root_alias: str | None = None
    url_scheme: str | None = None
    url_host: str | None = None
    capability_tags: tuple[str, ...] = Field(default=(), max_length=64)
    permit_id: str | None = None

    @model_validator(mode="after")
    def metadata_is_bounded_and_deterministic(self) -> AuditEventV1:
        if tuple(sorted(set(self.argument_key_names))) != self.argument_key_names:
            raise ValueError("argument_key_names must be unique and sorted")
        if any(
            fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", item) is None
            for item in self.argument_key_names
        ):
            raise ValueError("argument_key_names must be bounded scalar identifiers")
        if tuple(sorted(set(self.capability_tags))) != self.capability_tags:
            raise ValueError("capability_tags must be unique and sorted")
        if any(fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in self.capability_tags):
            raise ValueError("capability_tags must be lowercase scalar identifiers")
        return self
