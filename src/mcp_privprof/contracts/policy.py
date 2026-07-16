"""Pydantic boundary model for policy-v1 documents."""

from __future__ import annotations

from re import fullmatch
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_privprof.contracts.constraints import ConstraintV1, validate_constraint_collection
from mcp_privprof.contracts.limits import ToolLimitsV1
from mcp_privprof.domain.policy import PolicyEffect


class PolicyRuleV1(BaseModel):
    """One exact tool decision in a policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    effect: PolicyEffect
    constraints: tuple[ConstraintV1, ...]
    limits: ToolLimitsV1 | None
    primary_risk_category: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    capability_tags: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def constraints_are_unambiguous(self) -> PolicyRuleV1:
        validate_constraint_collection(self.constraints)
        if self.effect is PolicyEffect.DENY and (self.constraints or self.limits is not None):
            raise ValueError("DENY rules cannot contain constraints or limits")
        if self.effect is not PolicyEffect.DENY and self.limits is None:
            raise ValueError("non-DENY rules require reviewed limits")
        if len(self.capability_tags) != len(set(self.capability_tags)):
            raise ValueError("capability_tags must not contain duplicates")
        if any(fullmatch(r"[a-z][a-z0-9_]{0,63}", item) is None for item in self.capability_tags):
            raise ValueError("capability_tags must be lowercase scalar identifiers")
        return self


class PolicyV1(BaseModel):
    """The intentionally small, non-programmable v1 policy shape."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: Literal[1]
    default_effect: Literal["DENY"]
    policy_id: str = Field(min_length=1)
    task_type: str = Field(min_length=1)
    server_id: str = Field(min_length=1)
    approved_toolset_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reviewed_profile_id: str = Field(min_length=1)
    tools: tuple[PolicyRuleV1, ...]

    @model_validator(mode="after")
    def reject_duplicate_tool_rules(self) -> PolicyV1:
        """Prevent precedence ambiguity before entering the domain."""
        names = [rule.tool_name for rule in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tools must not contain duplicate tool_name values")
        return self
