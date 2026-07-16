"""Property invariant: raw argument values never enter persisted event documents."""

from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from mcp_privprof.application.audit import (
    EnforcementIdentity,
    argument_facts,
    build_audit_event,
)
from mcp_privprof.domain import PolicyEffect, PolicyRule, ToolIdentity, ToolLimits


@given(
    st.text(
        alphabet=st.characters(
            min_codepoint=ord("A"),
            max_codepoint=ord("Z"),
        ),
        min_size=1,
        max_size=40,
    )
)
def test_arbitrary_private_argument_value_is_absent_from_event(secret_suffix: str) -> None:
    """Only a digest and bounded top-level key names may describe arguments."""
    secret = f"PRIVATE_VALUE_{secret_suffix}"
    arguments: dict[str, object] = {"payload": {"secret": secret}}
    rule = PolicyRule(
        ToolIdentity("lab", "safe_tool"),
        PolicyEffect.ALLOW,
        limits=ToolLimits(10, 20, 1),
        primary_risk_category="data_read",
        capability_tags=("data",),
    )
    facts = argument_facts(arguments, ())
    event = build_audit_event(
        event_type="policy_decision",
        timestamp=datetime(2026, 7, 16, tzinfo=UTC),
        trace_id="trace-property",
        identity=EnforcementIdentity("task-property", "agent-property"),
        task_type="privacy-test",
        server_id="lab",
        tool_name="safe_tool",
        tool_fingerprint=None,
        policy_id="policy-property",
        rule=rule,
        effect=PolicyEffect.ALLOW,
        decision="allowed",
        reason_code="MCP_PRIVPROF_POLICY_ALLOW",
        facts=facts,
    )

    assert secret not in event.model_dump_json()
