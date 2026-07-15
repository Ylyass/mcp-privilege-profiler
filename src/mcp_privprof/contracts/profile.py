"""Versioned profile evidence and human review decision contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from mcp_privprof.contracts.constraints import ConstraintV1, validate_constraint_collection
from mcp_privprof.domain.policy import PolicyEffect
from mcp_privprof.domain.profile import CandidateRecommendation, EvidenceTier


class ProfileRunV1(BaseModel):
    """One labeled run included in profile evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    status: Literal["COMPLETED", "ABORTED"]


class ProfileToolEvidenceV1(BaseModel):
    """Counts and non-authorizing guidance for one tool name."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    available: bool
    fingerprint: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    attempted_count: int = Field(ge=0)
    successful_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    incomplete_count: int = Field(ge=0)
    qualifying_successful_count: int = Field(ge=0)
    successful_runs: int = Field(ge=0)
    successful_scenarios: tuple[str, ...] = ()
    evidence_tier: EvidenceTier
    recommendation: CandidateRecommendation

    @model_validator(mode="after")
    def counts_and_availability_are_consistent(self) -> ProfileToolEvidenceV1:
        """Reject summaries that undercount attempts or mislabel availability."""
        if self.attempted_count != (
            self.successful_count + self.failed_count + self.incomplete_count
        ):
            raise ValueError("attempted_count must equal completed and incomplete outcomes")
        if self.qualifying_successful_count > self.successful_count:
            raise ValueError("qualifying successes cannot exceed successful_count")
        if self.successful_runs > self.qualifying_successful_count:
            raise ValueError("successful_runs cannot exceed qualifying successes")
        if len(self.successful_scenarios) != len(set(self.successful_scenarios)):
            raise ValueError("successful_scenarios must not contain duplicates")
        if len(self.successful_scenarios) > self.successful_runs:
            raise ValueError("successful scenarios cannot exceed successful runs")
        if self.available != (self.fingerprint is not None):
            raise ValueError("fingerprint must be present exactly for available tools")
        expected_recommendation = (
            CandidateRecommendation.INVESTIGATE_UNLISTED
            if not self.available
            else CandidateRecommendation.NO_SUCCESSFUL_EVIDENCE
            if self.evidence_tier is EvidenceTier.UNOBSERVED
            else CandidateRecommendation.CONSIDER_ALLOW
        )
        if self.recommendation is not expected_recommendation:
            raise ValueError("recommendation must match availability and evidence tier")
        return self


class ProfileEvidenceReportV1(BaseModel):
    """Sealed evidence reviewed before any policy can be generated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_schema_version: Literal["1.0"] = "1.0"
    generated_at: AwareDatetime
    evidence_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profile_id: str = Field(min_length=1)
    profile_status: Literal["SEALED"]
    task_type: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    server_id: str = Field(min_length=1)
    toolset_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    created_at: AwareDatetime
    sealed_at: AwareDatetime
    planned_scenarios: tuple[str, ...]
    completed_scenarios: tuple[str, ...]
    scenario_coverage: float = Field(ge=0, le=1)
    completed_run_count: int = Field(ge=0)
    aborted_run_count: int = Field(ge=0)
    runs: tuple[ProfileRunV1, ...]
    tools: tuple[ProfileToolEvidenceV1, ...]

    @model_validator(mode="after")
    def summary_is_consistent(self) -> ProfileEvidenceReportV1:
        """Keep coverage, run totals, and deterministic ordering exact."""
        if not self.planned_scenarios:
            raise ValueError("planned_scenarios must not be empty")
        if len(self.planned_scenarios) != len(set(self.planned_scenarios)):
            raise ValueError("planned_scenarios must not contain duplicates")
        if self.sealed_at < self.created_at:
            raise ValueError("sealed_at cannot precede created_at")
        run_ids = [run.run_id for run in self.runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("profile evidence runs must have unique run IDs")
        if any(run.scenario_id not in self.planned_scenarios for run in self.runs):
            raise ValueError("every evidence run must use a planned scenario")
        expected_completed = tuple(
            scenario
            for scenario in self.planned_scenarios
            if any(run.scenario_id == scenario and run.status == "COMPLETED" for run in self.runs)
        )
        if self.completed_scenarios != expected_completed:
            raise ValueError("completed_scenarios must match completed runs in planned order")
        expected_coverage = len(self.completed_scenarios) / len(self.planned_scenarios)
        if self.scenario_coverage != expected_coverage:
            raise ValueError("scenario_coverage must match completed planned scenarios")
        if self.completed_run_count != sum(run.status == "COMPLETED" for run in self.runs):
            raise ValueError("completed_run_count must match runs")
        if self.aborted_run_count != sum(run.status == "ABORTED" for run in self.runs):
            raise ValueError("aborted_run_count must match runs")
        tool_names = [tool.tool_name for tool in self.tools]
        if tool_names != sorted(tool_names) or len(tool_names) != len(set(tool_names)):
            raise ValueError("profile evidence tools must be sorted and unique")
        for tool in self.tools:
            expected_successful_scenarios = tuple(
                scenario
                for scenario in self.planned_scenarios
                if scenario in tool.successful_scenarios
            )
            if tool.successful_scenarios != expected_successful_scenarios:
                raise ValueError("tool successful_scenarios must use planned order")
            if not set(tool.successful_scenarios).issubset(self.completed_scenarios):
                raise ValueError("tool successful_scenarios must have completed runs")
            expected_tier = (
                EvidenceTier.STRONG
                if tool.successful_runs >= 3
                and set(tool.successful_scenarios) == set(self.planned_scenarios)
                else EvidenceTier.MODERATE
                if len(tool.successful_scenarios) >= 2
                else EvidenceTier.WEAK
                if tool.successful_runs
                else EvidenceTier.UNOBSERVED
            )
            if tool.evidence_tier is not expected_tier:
                raise ValueError("evidence_tier must match successful runs and scenarios")
        return self


class ReviewDecisionV1(BaseModel):
    """One human-selected effect in an evidence-bound review file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    effect: PolicyEffect
    constraints: tuple[ConstraintV1, ...]

    @model_validator(mode="after")
    def constraints_are_unambiguous(self) -> ReviewDecisionV1:
        validate_constraint_collection(self.constraints)
        if self.effect is PolicyEffect.DENY and self.constraints:
            raise ValueError("DENY review decisions cannot contain constraints")
        return self


class ReviewDecisionsV1(BaseModel):
    """Human input bound to the exact sealed evidence it reviewed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    review_schema_version: Literal["1.0"] = "1.0"
    profile_id: str = Field(min_length=1)
    evidence_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decisions: tuple[ReviewDecisionV1, ...]

    @model_validator(mode="after")
    def reject_duplicate_decisions(self) -> ReviewDecisionsV1:
        names = [decision.tool_name for decision in self.decisions]
        if len(names) != len(set(names)):
            raise ValueError("review decisions must not contain duplicate tools")
        return self
