"""Enforcement startup gate tests."""

from __future__ import annotations

from dataclasses import replace

import mcp.types as types
import pytest

from mcp_privprof.adapters.mcp.enforcement_proxy import (
    EnforcementCatalog,
    accept_exact_catalog,
)
from mcp_privprof.adapters.mcp.inventory import CollectedCatalog, snapshot_toolset
from mcp_privprof.domain.constraints import PathConstraint
from mcp_privprof.domain.policy import (
    Policy,
    PolicyEffect,
    PolicyRule,
    ToolIdentity,
)


def _tool(name: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=f"Fixture {name}",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )


def _policy(fingerprint: str, names: tuple[str, ...]) -> Policy:
    return Policy(
        policy_id="policy-1",
        task_type="fixture",
        server_id="lab",
        approved_toolset_fingerprint=fingerprint,
        reviewed_profile_id="profile-1",
        rules=tuple(PolicyRule(ToolIdentity("lab", name), PolicyEffect.ALLOW) for name in names),
    )


def test_startup_accepts_only_exact_fingerprint_and_complete_rule_coverage() -> None:
    """A reviewed policy must describe every tool in the exact live catalog."""
    tools = (_tool("one"), _tool("two"))
    snapshot = snapshot_toolset("lab", list(tools))
    observed = CollectedCatalog(snapshot=snapshot, tools=tools)
    policy = _policy(snapshot.fingerprint, ("one", "two"))
    catalog = EnforcementCatalog()

    accept_exact_catalog(
        observed,
        policy,
        {rule.identity.tool_name: rule for rule in policy.rules},
        catalog,
    )

    assert catalog.valid
    assert catalog.tools == tools


def test_startup_rejects_stale_fingerprint_before_serving_tools() -> None:
    """Even a complete-looking policy fails closed when the definitions changed."""
    tools = (_tool("one"),)
    snapshot = snapshot_toolset("lab", list(tools))
    observed = CollectedCatalog(
        snapshot=replace(snapshot, fingerprint="sha256:" + "0" * 64),
        tools=tools,
    )
    policy = _policy(snapshot.fingerprint, ("one",))

    with pytest.raises(RuntimeError, match="MCP_PRIVPROF_POLICY_TOOLSET_DRIFT"):
        accept_exact_catalog(
            observed,
            policy,
            {rule.identity.tool_name: rule for rule in policy.rules},
            EnforcementCatalog(),
        )


@pytest.mark.parametrize("policy_names", [("one",), ("one", "two", "three")])
def test_startup_rejects_missing_or_unknown_policy_rules(
    policy_names: tuple[str, ...],
) -> None:
    """Partial policies and rules for absent tools are both invalid artifacts."""
    tools = (_tool("one"), _tool("two"))
    snapshot = snapshot_toolset("lab", list(tools))
    observed = CollectedCatalog(snapshot=snapshot, tools=tools)
    policy = _policy(snapshot.fingerprint, policy_names)

    with pytest.raises(RuntimeError, match="MCP_PRIVPROF_POLICY_CATALOG_INCOMPLETE"):
        accept_exact_catalog(
            observed,
            policy,
            {rule.identity.tool_name: rule for rule in policy.rules},
            EnforcementCatalog(),
        )


def test_startup_rejects_constraint_argument_absent_from_tool_schema() -> None:
    """A review typo cannot create the appearance of constraining another argument."""
    tools = (_tool("one"),)
    snapshot = snapshot_toolset("lab", list(tools))
    observed = CollectedCatalog(snapshot=snapshot, tools=tools)
    policy = Policy(
        policy_id="policy-constraint-typo",
        task_type="fixture",
        server_id="lab",
        approved_toolset_fingerprint=snapshot.fingerprint,
        reviewed_profile_id="profile-1",
        rules=(
            PolicyRule(
                ToolIdentity("lab", "one"),
                PolicyEffect.ALLOW,
                (PathConstraint("misspelled_path", ("ROOT",)),),
            ),
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="MCP_PRIVPROF_POLICY_CONSTRAINT_TARGET_INVALID",
    ):
        accept_exact_catalog(
            observed,
            policy,
            {"one": policy.rules[0]},
            EnforcementCatalog(),
        )
