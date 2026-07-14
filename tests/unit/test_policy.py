"""Tests for deny-by-default domain policy behavior."""

from __future__ import annotations

import pytest

from mcp_privprof.domain import Policy, PolicyEffect, PolicyRule, ToolIdentity


def make_policy(*rules: PolicyRule) -> Policy:
    """Create a valid policy with a deterministic fingerprint."""
    return Policy(
        policy_id="policy-1",
        task_type="dependency-review",
        server_id="lab",
        approved_toolset_fingerprint=f"sha256:{'a' * 64}",
        rules=rules,
    )


def test_unlisted_tool_is_denied() -> None:
    """A missing exact rule is never implicitly allowed."""
    decision = make_policy().decide(ToolIdentity(server_id="lab", tool_name="run_command"))

    assert decision.effect is PolicyEffect.DENY
    assert decision.reason_code == "NO_EXACT_POLICY_RULE"


def test_exact_rule_is_returned() -> None:
    """An exact identity returns its declared policy effect."""
    identity = ToolIdentity(server_id="lab", tool_name="read_fixture")
    decision = make_policy(PolicyRule(identity, PolicyEffect.ALLOW)).decide(identity)

    assert decision.effect is PolicyEffect.ALLOW
    assert decision.reason_code == "EXACT_POLICY_RULE"


def test_server_mismatch_is_denied() -> None:
    """Rules for one server never authorize another server."""
    decision = make_policy().decide(ToolIdentity(server_id="other", tool_name="read_fixture"))

    assert decision.effect is PolicyEffect.DENY
    assert decision.reason_code == "SERVER_ID_MISMATCH"


def test_duplicate_identity_is_rejected() -> None:
    """Duplicate exact identities would create ambiguous policy semantics."""
    identity = ToolIdentity(server_id="lab", tool_name="read_fixture")

    with pytest.raises(ValueError, match="duplicate"):
        make_policy(
            PolicyRule(identity, PolicyEffect.ALLOW),
            PolicyRule(identity, PolicyEffect.DENY),
        )

