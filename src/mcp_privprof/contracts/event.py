"""Pydantic boundary model for privacy-minimized event-v1 records."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mcp_privprof.domain.policy import PolicyEffect


class AuditEventV1(BaseModel):
    """A single JSONL event without raw tool arguments or result bodies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_schema_version: Literal["1.0"] = "1.0"
    event_type: str = Field(min_length=1)
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
    primary_risk_category: str = Field(min_length=1)
    audit_status: Literal["written", "failed"]
    duration_ms: int | None = Field(default=None, ge=0)
    argument_key_names: tuple[str, ...] = ()
    argument_size_bytes: int | None = Field(default=None, ge=0)
    path_root_alias: str | None = None
    url_scheme: str | None = None
    url_host: str | None = None

