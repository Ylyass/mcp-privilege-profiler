"""Tests for versioned public document contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.contracts.policy import PolicyRuleV1, PolicyV1
from mcp_privprof.domain import PolicyEffect

SCHEMAS_DIR = Path(__file__).parents[2] / "schemas"
FINGERPRINT = f"sha256:{'b' * 64}"


def test_policy_contract_rejects_duplicate_rules() -> None:
    """Pydantic rejects duplicate entries before domain conversion."""
    with pytest.raises(ValidationError, match="duplicate"):
        PolicyV1(
            policy_version=1,
            policy_id="policy-1",
            task_type="dependency-review",
            server_id="lab",
            approved_toolset_fingerprint=FINGERPRINT,
            reviewed_profile_id="profile-1",
            tools=(
                PolicyRuleV1(tool_name="read_fixture", effect=PolicyEffect.ALLOW),
                PolicyRuleV1(tool_name="read_fixture", effect=PolicyEffect.DENY),
            ),
        )


def test_event_contract_forbids_raw_argument_field() -> None:
    """The default public event contract cannot accept raw arguments."""
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AuditEventV1.model_validate(
            {
                "event_type": "policy_decision",
                "trace_id": "trace-1",
                "task_id": "task-1",
                "task_type": "dependency-review",
                "agent_id": "agent-1",
                "server_id": "lab",
                "server_trust": "approved",
                "tool_name": "read_fixture",
                "tool_effect": PolicyEffect.ALLOW,
                "decision": "allowed",
                "reason_code": "EXACT_POLICY_RULE",
                "primary_risk_category": "read",
                "audit_status": "written",
                "raw_arguments": {"path": "secret.txt"},
            }
        )


@pytest.mark.parametrize("schema_name", ["policy-v1.schema.json", "event-v1.schema.json"])
def test_public_schema_is_valid_json_schema(schema_name: str) -> None:
    """Public schemas must remain valid Draft 2020-12 JSON Schema documents."""
    document = json.loads((SCHEMAS_DIR / schema_name).read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(document)
