"""Exact, deny-by-default policy decisions.

The domain deliberately contains no MCP, database, CLI, or validation-library
imports. Boundary adapters convert untrusted documents into these types.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from re import fullmatch

from mcp_privprof.domain.constraints import PolicyConstraint, normalize_constraints
from mcp_privprof.domain.limits import ToolLimits


class PolicyEffect(StrEnum):
    """The only v0.1 policy effects."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """A tool's unambiguous policy identity."""

    server_id: str
    tool_name: str

    def __post_init__(self) -> None:
        if not self.server_id or not self.tool_name:
            raise ValueError("tool identity values must not be empty")


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One exact rule; wildcards and exceptions are not supported."""

    identity: ToolIdentity
    effect: PolicyEffect
    constraints: tuple[PolicyConstraint, ...] = ()
    limits: ToolLimits | None = None
    primary_risk_category: str = "unspecified"
    capability_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        normalized = normalize_constraints(self.constraints)
        if self.effect is PolicyEffect.DENY and (normalized or self.limits is not None):
            raise ValueError("DENY rules cannot contain constraints or limits")
        _validate_risk_metadata(self.primary_risk_category, self.capability_tags)
        object.__setattr__(self, "constraints", normalized)
        object.__setattr__(self, "capability_tags", tuple(sorted(self.capability_tags)))


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """A deterministic result suitable for enforcement and audit."""

    effect: PolicyEffect
    reason_code: str


@dataclass(frozen=True, slots=True)
class Policy:
    """An immutable policy linked to a reviewed task and toolset fingerprint."""

    policy_id: str
    task_type: str
    server_id: str
    approved_toolset_fingerprint: str
    reviewed_profile_id: str
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if not self.task_type:
            raise ValueError("task_type must not be empty")
        if not self.server_id:
            raise ValueError("server_id must not be empty")
        if not self.reviewed_profile_id:
            raise ValueError("reviewed_profile_id must not be empty")
        if fullmatch(r"sha256:[0-9a-f]{64}", self.approved_toolset_fingerprint) is None:
            raise ValueError("approved_toolset_fingerprint must be a lowercase SHA-256 fingerprint")

        identities = [rule.identity for rule in self.rules]
        if len(identities) != len(set(identities)):
            raise ValueError("policy contains duplicate tool identities")
        if any(identity.server_id != self.server_id for identity in identities):
            raise ValueError("all policy rules must use the policy server_id")

    def decide(self, identity: ToolIdentity) -> PolicyDecision:
        """Return an exact match or the invariant default deny decision."""
        if identity.server_id != self.server_id:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                reason_code="SERVER_ID_MISMATCH",
            )

        for rule in self.rules:
            if rule.identity == identity:
                return PolicyDecision(
                    effect=rule.effect,
                    reason_code="EXACT_POLICY_RULE",
                )

        return PolicyDecision(
            effect=PolicyEffect.DENY,
            reason_code="NO_EXACT_POLICY_RULE",
        )


def _validate_risk_metadata(
    primary_risk_category: str,
    capability_tags: tuple[str, ...],
) -> None:
    pattern = r"[a-z][a-z0-9_]{0,63}"
    if fullmatch(pattern, primary_risk_category) is None:
        raise ValueError("primary risk category must be a lowercase scalar identifier")
    if len(capability_tags) > 64:
        raise ValueError("capability tags must not contain more than 64 entries")
    if len(capability_tags) != len(set(capability_tags)):
        raise ValueError("capability tags must not contain duplicates")
    if any(fullmatch(pattern, item) is None for item in capability_tags):
        raise ValueError("capability tags must be lowercase scalar identifiers")
