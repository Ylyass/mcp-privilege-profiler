"""Conversion and deterministic rendering of reviewed policy artifacts."""

from __future__ import annotations

import json

from mcp_privprof.application.constraints import constraint_contract, constraint_domain
from mcp_privprof.contracts.limits import ToolLimitsV1
from mcp_privprof.contracts.policy import PolicyRuleV1, PolicyV1
from mcp_privprof.domain.limits import ToolLimits
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity


def policy_contract(policy: Policy) -> PolicyV1:
    """Convert one reviewed domain policy to the public policy-v1 contract."""
    return PolicyV1(
        policy_version=1,
        default_effect="DENY",
        policy_id=policy.policy_id,
        task_type=policy.task_type,
        server_id=policy.server_id,
        approved_toolset_fingerprint=policy.approved_toolset_fingerprint,
        reviewed_profile_id=policy.reviewed_profile_id,
        tools=tuple(
            PolicyRuleV1(
                tool_name=rule.identity.tool_name,
                effect=rule.effect,
                constraints=tuple(constraint_contract(item) for item in rule.constraints),
                limits=(
                    ToolLimitsV1(
                        max_calls_per_minute=rule.limits.max_calls_per_minute,
                        max_calls_per_task=rule.limits.max_calls_per_task,
                        max_concurrent_calls=rule.limits.max_concurrent_calls,
                    )
                    if rule.limits is not None
                    else None
                ),
                primary_risk_category=rule.primary_risk_category,
                capability_tags=rule.capability_tags,
            )
            for rule in policy.rules
        ),
    )


def policy_domain(policy: PolicyV1) -> Policy:
    """Convert a strict policy-v1 document into immutable enforcement facts."""
    if policy.default_effect != PolicyEffect.DENY.value:
        raise ValueError("policy default effect must be DENY")
    return Policy(
        policy_id=policy.policy_id,
        task_type=policy.task_type,
        server_id=policy.server_id,
        approved_toolset_fingerprint=policy.approved_toolset_fingerprint,
        reviewed_profile_id=policy.reviewed_profile_id,
        rules=tuple(
            PolicyRule(
                identity=ToolIdentity(server_id=policy.server_id, tool_name=rule.tool_name),
                effect=rule.effect,
                constraints=tuple(constraint_domain(item) for item in rule.constraints),
                limits=(
                    ToolLimits(
                        max_calls_per_minute=rule.limits.max_calls_per_minute,
                        max_calls_per_task=rule.limits.max_calls_per_task,
                        max_concurrent_calls=rule.limits.max_concurrent_calls,
                    )
                    if rule.limits is not None
                    else None
                ),
                primary_risk_category=rule.primary_risk_category,
                capability_tags=rule.capability_tags,
            )
            for rule in policy.tools
        ),
    )


def render_policy_json(policy: PolicyV1) -> bytes:
    """Render deterministic UTF-8 policy JSON for validation and enforcement."""
    document = policy.model_dump(mode="json")
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
