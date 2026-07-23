"""Tests for the bounded live Wazuh integration probe."""

from __future__ import annotations

import pytest
from mcp.types import Tool

from mcp_privprof.adapters.mcp.inventory import snapshot_toolset
from wazuh.live_probe import SERVER_ID, build_probe_policy, parse_active_lab_agent_id


def test_probe_policy_is_complete_all_deny_and_marks_credential_risk() -> None:
    """The probe must isolate denial telemetry without forwarding any lab tool."""
    snapshot = snapshot_toolset(
        SERVER_ID,
        [
            Tool(
                name="read_fixture",
                description="Read a safe fixture.",
                inputSchema={"type": "object"},
            ),
            Tool(
                name="simulated_credential_read",
                description="Return a public canary.",
                inputSchema={"type": "object"},
            ),
        ],
    )

    policy = build_probe_policy(snapshot)

    assert policy.approved_toolset_fingerprint == snapshot.fingerprint
    assert {rule.identity.tool_name for rule in policy.rules} == {
        "read_fixture",
        "simulated_credential_read",
    }
    assert {rule.effect.value for rule in policy.rules} == {"DENY"}
    credential_rule = next(
        rule for rule in policy.rules if rule.identity.tool_name == "simulated_credential_read"
    )
    assert credential_rule.primary_risk_category == "credential_access"
    assert all(rule.limits is None and not rule.constraints for rule in policy.rules)


def test_active_lab_agent_id_is_discovered_instead_of_assumed() -> None:
    """Wazuh registration IDs may change when the disposable agent is recreated."""
    output = """
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local
   ID: 002, Name: mcp-privprof-lab, IP: any, Active
"""

    assert parse_active_lab_agent_id(output) == "002"


@pytest.mark.parametrize(
    "output",
    [
        "ID: 002, Name: mcp-privprof-lab, IP: any, Disconnected\n",
        (
            "ID: 001, Name: mcp-privprof-lab, IP: any, Active\n"
            "ID: 002, Name: mcp-privprof-lab, IP: any, Active\n"
        ),
    ],
)
def test_active_lab_agent_discovery_rejects_missing_or_duplicate_matches(output: str) -> None:
    """The probe must fail closed unless exactly one named lab agent is active."""
    with pytest.raises(RuntimeError, match="not active exactly once"):
        parse_active_lab_agent_id(output)
