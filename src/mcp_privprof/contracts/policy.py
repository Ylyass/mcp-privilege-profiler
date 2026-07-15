"""Pydantic boundary model for policy-v1 documents."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_privprof.domain.policy import PolicyEffect


class PolicyRuleV1(BaseModel):
    """One exact tool decision in a policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    effect: PolicyEffect


class PolicyV1(BaseModel):
    """The intentionally small, non-programmable v1 policy shape."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: Literal[1]
    policy_id: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    server_id: str = Field(min_length=1)
    approved_toolset_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reviewed_profile_id: str = Field(min_length=1)
    tools: tuple[PolicyRuleV1, ...] = ()

    @model_validator(mode="after")
    def reject_duplicate_tool_rules(self) -> PolicyV1:
        """Prevent precedence ambiguity before entering the domain."""
        names = [rule.tool_name for rule in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tools must not contain duplicate tool_name values")
        return self
