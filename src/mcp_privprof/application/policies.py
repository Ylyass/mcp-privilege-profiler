"""Conversion and deterministic rendering of reviewed policy artifacts."""

from __future__ import annotations

import json

from mcp_privprof.contracts.policy import PolicyRuleV1, PolicyV1
from mcp_privprof.domain.policy import Policy


def policy_contract(policy: Policy) -> PolicyV1:
    """Convert one reviewed domain policy to the public policy-v1 contract."""
    return PolicyV1(
        policy_version=1,
        policy_id=policy.policy_id,
        task_type=policy.task_type,
        server_id=policy.server_id,
        approved_toolset_fingerprint=policy.approved_toolset_fingerprint,
        reviewed_profile_id=policy.reviewed_profile_id,
        tools=tuple(
            PolicyRuleV1(tool_name=rule.identity.tool_name, effect=rule.effect)
            for rule in policy.rules
        ),
    )


def render_policy_json(policy: PolicyV1) -> bytes:
    """Render deterministic UTF-8 policy JSON for validation and enforcement."""
    document = policy.model_dump(mode="json")
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
