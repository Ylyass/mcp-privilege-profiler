"""Tests for versioned public document contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from mcp_privprof.contracts.event import AuditEventV1
from mcp_privprof.contracts.limits import ToolLimitsV1
from mcp_privprof.contracts.policy import PolicyRuleV1, PolicyV1
from mcp_privprof.domain import PolicyEffect

SCHEMAS_DIR = Path(__file__).parents[2] / "schemas"
FINGERPRINT = f"sha256:{'b' * 64}"


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


def test_policy_contract_rejects_duplicate_rules() -> None:
    """Pydantic rejects duplicate entries before domain conversion."""
    with pytest.raises(ValidationError, match="duplicate"):
        PolicyV1(
            policy_version=1,
            default_effect="DENY",
            policy_id="policy-1",
            task_type="dependency-review",
            server_id="lab",
            approved_toolset_fingerprint=FINGERPRINT,
            reviewed_profile_id="profile-1",
            tools=(
                PolicyRuleV1(
                    tool_name="read_fixture",
                    effect=PolicyEffect.ALLOW,
                    constraints=(),
                    limits=ToolLimitsV1(
                        max_calls_per_minute=60,
                        max_calls_per_task=100,
                        max_concurrent_calls=2,
                    ),
                    primary_risk_category="file_read",
                    capability_tags=("filesystem",),
                ),
                PolicyRuleV1(
                    tool_name="read_fixture",
                    effect=PolicyEffect.DENY,
                    constraints=(),
                    limits=None,
                    primary_risk_category="file_read",
                    capability_tags=("filesystem",),
                ),
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
                "drift_severity": "none",
                "limit_type": "none",
                "audit_status": "written",
                "raw_arguments": {"path": "secret.txt"},
            }
        )


def test_policy_contract_bounds_capability_tags_for_auditable_events() -> None:
    """A startup-valid policy can never exceed the event metadata boundary."""
    with pytest.raises(ValidationError, match="too_long"):
        PolicyRuleV1(
            tool_name="read_fixture",
            effect=PolicyEffect.ALLOW,
            constraints=(),
            limits=ToolLimitsV1(
                max_calls_per_minute=60,
                max_calls_per_task=100,
                max_concurrent_calls=2,
            ),
            primary_risk_category="file_read",
            capability_tags=tuple(f"tag_{index}" for index in range(65)),
        )


@pytest.mark.parametrize(
    ("effect", "constraints", "limits"),
    [
        (
            "DENY",
            [{"kind": "max_utf8_bytes", "argument": "content", "maximum": 10}],
            None,
        ),
        ("ALLOW", [], None),
    ],
)
def test_published_policy_schema_enforces_effect_specific_limits_and_constraints(
    effect: str,
    constraints: list[object],
    limits: object,
) -> None:
    """The public JSON Schema matches the executable DENY/non-DENY invariant."""
    schema = json.loads((SCHEMAS_DIR / "policy-v1.schema.json").read_text(encoding="utf-8"))
    document = {
        "policy_version": 1,
        "default_effect": "DENY",
        "policy_id": "policy-1",
        "task_type": "dependency-review",
        "server_id": "lab",
        "approved_toolset_fingerprint": FINGERPRINT,
        "reviewed_profile_id": "profile-1",
        "tools": [
            {
                "tool_name": "read_fixture",
                "effect": effect,
                "constraints": constraints,
                "limits": limits,
                "primary_risk_category": "file_read",
                "capability_tags": ["filesystem"],
            }
        ],
    }

    validator = cast(_Validator, Draft202012Validator(schema))
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    "schema_name",
    [
        "policy-v1.schema.json",
        "event-v1.schema.json",
        "inventory-report-v1.schema.json",
        "profile-evidence-v1.schema.json",
        "review-decisions-v1.schema.json",
    ],
)
def test_public_schema_is_valid_json_schema(schema_name: str) -> None:
    """Public schemas must remain valid Draft 2020-12 JSON Schema documents."""
    document = json.loads((SCHEMAS_DIR / schema_name).read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(document)
