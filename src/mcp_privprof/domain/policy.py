"""Exact, deny-by-default policy decisions.

The domain deliberately contains no MCP, database, CLI, or validation-library
imports. Boundary adapters convert untrusted documents into these types.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One exact rule; wildcards and exceptions are not supported."""

    identity: ToolIdentity
    effect: PolicyEffect


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
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if not self.task_type:
            raise ValueError("task_type must not be empty")
        if not self.server_id:
            raise ValueError("server_id must not be empty")
        if not self.approved_toolset_fingerprint.startswith("sha256:"):
            raise ValueError("approved_toolset_fingerprint must start with sha256:")

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

