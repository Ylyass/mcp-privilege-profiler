"""Allowlist-based construction of privacy-minimized enforcement events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from re import fullmatch
from typing import Literal, cast
from urllib.parse import urlsplit

import rfc8785

from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.domain.constraints import (
    PathConstraint,
    PolicyConstraint,
    UrlConstraint,
    normalize_host,
    normalize_scheme,
)
from mcp_privprof.domain.limits import LimitType
from mcp_privprof.domain.policy import PolicyEffect, PolicyRule

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type AuditDecision = Literal["allowed", "denied", "approval_required"]
type DriftSeverityValue = Literal[
    "none",
    "informational",
    "review_required",
    "security_widening",
    "breaking",
]


@dataclass(frozen=True, slots=True)
class EnforcementIdentity:
    """Trusted launch-bound identity copied into every audit event."""

    task_id: str
    agent_id: str

    def __post_init__(self) -> None:
        if not self.task_id.strip() or not self.agent_id.strip():
            raise ValueError("task_id and agent_id must not be blank")


@dataclass(frozen=True, slots=True)
class ArgumentFacts:
    """Bounded metadata and an in-memory digest, never raw persisted values."""

    key_names: tuple[str, ...]
    size_bytes: int
    digest: str
    path_root_alias: str | None
    url_scheme: str | None
    url_host: str | None


def argument_facts(
    arguments: dict[str, object],
    constraints: tuple[PolicyConstraint, ...],
) -> ArgumentFacts:
    """Derive only explicitly allowlisted metadata from one in-memory argument map."""
    canonical = rfc8785.dumps(cast(JsonValue, arguments))
    safe_names = tuple(
        sorted(
            name
            for name in arguments
            if fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", name) is not None
        )[:64]
    )
    path_root_alias: str | None = None
    url_scheme: str | None = None
    url_host: str | None = None
    for constraint in constraints:
        value = arguments.get(constraint.argument)
        if isinstance(constraint, PathConstraint) and len(constraint.path_roots) == 1:
            path_root_alias = constraint.path_roots[0]
        elif isinstance(constraint, UrlConstraint) and isinstance(value, str):
            try:
                parsed = urlsplit(value)
                if parsed.hostname is not None:
                    normalized_scheme = normalize_scheme(parsed.scheme)
                    normalized_host = normalize_host(parsed.hostname)
                    if (
                        normalized_scheme in constraint.schemes
                        and normalized_host in constraint.hosts
                    ):
                        url_scheme = normalized_scheme
                        url_host = normalized_host
            except ValueError:
                pass
    return ArgumentFacts(
        key_names=safe_names,
        size_bytes=len(canonical),
        digest=f"sha256:{sha256(canonical).hexdigest()}",
        path_root_alias=path_root_alias,
        url_scheme=url_scheme,
        url_host=url_host,
    )


def build_audit_event(
    *,
    event_type: Literal[
        "policy_decision",
        "tool_completion",
        "permit_decision",
        "enforcement_failure",
    ],
    timestamp: datetime,
    trace_id: str,
    identity: EnforcementIdentity,
    task_type: str,
    server_id: str,
    tool_name: str,
    tool_fingerprint: str | None,
    policy_id: str,
    rule: PolicyRule | None,
    effect: PolicyEffect,
    decision: AuditDecision,
    reason_code: str,
    facts: ArgumentFacts | None,
    drift_severity: DriftSeverityValue = "none",
    limit_type: LimitType = LimitType.NONE,
    duration_ms: int | None = None,
    permit_id: str | None = None,
) -> AuditEventV1:
    """Construct one strict event exclusively from approved scalar metadata."""
    return AuditEventV1(
        event_type=event_type,
        timestamp=timestamp,
        trace_id=trace_id,
        task_id=identity.task_id,
        task_type=task_type,
        agent_id=identity.agent_id,
        server_id=server_id,
        server_trust="approved",
        tool_name=tool_name,
        tool_fingerprint=tool_fingerprint,
        policy_id=policy_id,
        tool_effect=effect,
        decision=decision,
        reason_code=reason_code,
        primary_risk_category=(
            rule.primary_risk_category if rule is not None else "unknown_capability"
        ),
        drift_severity=drift_severity,
        limit_type=limit_type,
        audit_status="written",
        duration_ms=duration_ms,
        argument_key_names=facts.key_names if facts is not None else (),
        argument_size_bytes=facts.size_bytes if facts is not None else None,
        path_root_alias=facts.path_root_alias if facts is not None else None,
        url_scheme=facts.url_scheme if facts is not None else None,
        url_host=facts.url_host if facts is not None else None,
        capability_tags=rule.capability_tags if rule is not None else (),
        permit_id=permit_id,
    )
