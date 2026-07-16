"""Dependency-free profile, scenario-run, review, and evidence facts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch

from mcp_privprof.domain.constraints import PolicyConstraint, normalize_constraints
from mcp_privprof.domain.limits import ToolLimits
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity


class ProfileStatus(StrEnum):
    """Lifecycle states for an observation profile."""

    OPEN = "OPEN"
    SEALED = "SEALED"


class RunStatus(StrEnum):
    """Lifecycle states for one labeled scenario run."""

    OPEN = "OPEN"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class CallOutcome(StrEnum):
    """Privacy-safe completion facts for a forwarded tool attempt."""

    SUCCESS = "SUCCESS"
    TOOL_ERROR = "TOOL_ERROR"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"


class EvidenceTier(StrEnum):
    """Transparent evidence strength, never statistical confidence."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    UNOBSERVED = "unobserved"


class CandidateRecommendation(StrEnum):
    """Unreviewed guidance that cannot authorize a policy decision."""

    CONSIDER_ALLOW = "consider_allow"
    NO_SUCCESSFUL_EVIDENCE = "no_successful_evidence"
    INVESTIGATE_UNLISTED = "investigate_unlisted"


@dataclass(frozen=True, slots=True)
class ProfileSession:
    """One task-scoped observation profile bound to trusted launch context."""

    profile_id: str
    task_type: str
    agent_id: str
    server_id: str
    toolset_fingerprint: str
    planned_scenarios: tuple[str, ...]
    status: ProfileStatus
    created_at: datetime
    sealed_at: datetime | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("profile_id", self.profile_id),
            ("task_type", self.task_type),
            ("agent_id", self.agent_id),
            ("server_id", self.server_id),
        ):
            if not value:
                raise ValueError(f"{label} must not be empty")
        _validate_fingerprint(self.toolset_fingerprint, "toolset_fingerprint")
        if not self.planned_scenarios:
            raise ValueError("planned_scenarios must not be empty")
        if any(not scenario for scenario in self.planned_scenarios):
            raise ValueError("planned scenario IDs must not be empty")
        if len(self.planned_scenarios) != len(set(self.planned_scenarios)):
            raise ValueError("planned_scenarios must not contain duplicates")
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))
        if self.status is ProfileStatus.OPEN and self.sealed_at is not None:
            raise ValueError("an open profile cannot have sealed_at")
        if self.status is ProfileStatus.SEALED and self.sealed_at is None:
            raise ValueError("a sealed profile requires sealed_at")
        if self.sealed_at is not None:
            sealed_at = _utc(self.sealed_at, "sealed_at")
            if sealed_at < self.created_at:
                raise ValueError("sealed_at cannot precede created_at")
            object.__setattr__(self, "sealed_at", sealed_at)

    def start_run(self, run_id: str, scenario_id: str, started_at: datetime) -> ScenarioRun:
        """Create an open run only for a planned scenario on an open profile."""
        if self.status is not ProfileStatus.OPEN:
            raise ValueError("cannot start a run for a sealed profile")
        if scenario_id not in self.planned_scenarios:
            raise ValueError("scenario_id is not planned for this profile")
        return ScenarioRun(
            run_id=run_id,
            profile_id=self.profile_id,
            scenario_id=scenario_id,
            status=RunStatus.OPEN,
            started_at=started_at,
        )

    def seal(self, runs: tuple[ScenarioRun, ...], sealed_at: datetime) -> ProfileSession:
        """Seal evidence only when no run is open and one run completed."""
        if self.status is not ProfileStatus.OPEN:
            raise ValueError("profile is already sealed")
        if any(run.profile_id != self.profile_id for run in runs):
            raise ValueError("all runs must belong to the profile")
        if any(run.status is RunStatus.OPEN for run in runs):
            raise ValueError("cannot seal a profile with an open run")
        if not any(run.status is RunStatus.COMPLETED for run in runs):
            raise ValueError("cannot seal a profile without a completed run")
        return replace(
            self,
            status=ProfileStatus.SEALED,
            sealed_at=_utc(sealed_at, "sealed_at"),
        )


@dataclass(frozen=True, slots=True)
class ScenarioRun:
    """One operator-labeled execution of a planned scenario."""

    run_id: str
    profile_id: str
    scenario_id: str
    status: RunStatus
    started_at: datetime
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("run_id", self.run_id),
            ("profile_id", self.profile_id),
            ("scenario_id", self.scenario_id),
        ):
            if not value:
                raise ValueError(f"{label} must not be empty")
        object.__setattr__(self, "started_at", _utc(self.started_at, "started_at"))
        if self.status is RunStatus.OPEN and self.completed_at is not None:
            raise ValueError("an open run cannot have completed_at")
        if self.status is not RunStatus.OPEN and self.completed_at is None:
            raise ValueError("a finished run requires completed_at")
        if self.completed_at is not None:
            completed_at = _utc(self.completed_at, "completed_at")
            if completed_at < self.started_at:
                raise ValueError("completed_at cannot precede started_at")
            object.__setattr__(self, "completed_at", completed_at)

    def finish(self, status: RunStatus, completed_at: datetime) -> ScenarioRun:
        """Finish an open run as completed or aborted exactly once."""
        if self.status is not RunStatus.OPEN:
            raise ValueError("run is already finished")
        if status is RunStatus.OPEN:
            raise ValueError("finish status must be COMPLETED or ABORTED")
        return replace(self, status=status, completed_at=_utc(completed_at, "completed_at"))


@dataclass(frozen=True, slots=True)
class AvailableTool:
    """A tool exposed by the bound catalog at profile creation."""

    name: str
    fingerprint: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("tool name must not be empty")
        _validate_fingerprint(self.fingerprint, "tool fingerprint")


@dataclass(frozen=True, slots=True)
class CallFact:
    """A tool attempt without argument values or result content."""

    call_id: int
    run_id: str
    tool_name: str
    attempted_at: datetime
    outcome: CallOutcome | None = None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.call_id <= 0:
            raise ValueError("call_id must be positive")
        if not self.run_id or not self.tool_name:
            raise ValueError("run_id and tool_name must not be empty")
        object.__setattr__(self, "attempted_at", _utc(self.attempted_at, "attempted_at"))
        if (self.outcome is None) != (self.completed_at is None):
            raise ValueError("outcome and completed_at must be present together")
        if self.completed_at is not None:
            completed_at = _utc(self.completed_at, "completed_at")
            if completed_at < self.attempted_at:
                raise ValueError("completed_at cannot precede attempted_at")
            object.__setattr__(self, "completed_at", completed_at)


@dataclass(frozen=True, slots=True)
class ToolEvidence:
    """Transparent counts and candidate guidance for one observed tool name."""

    tool_name: str
    available: bool
    fingerprint: str | None
    attempted_count: int
    successful_count: int
    failed_count: int
    incomplete_count: int
    qualifying_successful_count: int
    successful_runs: int
    successful_scenarios: tuple[str, ...]
    evidence_tier: EvidenceTier
    recommendation: CandidateRecommendation


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    """One explicit human decision for an available tool."""

    tool_name: str
    effect: PolicyEffect
    constraints: tuple[PolicyConstraint, ...] = ()
    limits: ToolLimits | None = None
    primary_risk_category: str = "unspecified"
    capability_tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.tool_name:
            raise ValueError("review tool_name must not be empty")
        normalized = normalize_constraints(self.constraints)
        if self.effect is PolicyEffect.DENY and (normalized or self.limits is not None):
            raise ValueError("DENY review decisions cannot contain constraints or limits")
        # Reuse PolicyRule validation so review and enforcement metadata cannot diverge.
        validated = PolicyRule(
            identity=ToolIdentity(server_id="review-validation", tool_name=self.tool_name),
            effect=self.effect,
            constraints=normalized,
            limits=self.limits,
            primary_risk_category=self.primary_risk_category,
            capability_tags=self.capability_tags,
        )
        object.__setattr__(self, "constraints", normalized)
        object.__setattr__(self, "capability_tags", validated.capability_tags)


@dataclass(frozen=True, slots=True)
class CompletedReview:
    """An immutable completed review bound to exact evidence and toolset."""

    review_id: str
    profile_id: str
    reviewer: str
    reviewed_at: datetime
    evidence_fingerprint: str
    toolset_fingerprint: str
    decisions: tuple[ReviewDecision, ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("review_id", self.review_id),
            ("profile_id", self.profile_id),
            ("reviewer", self.reviewer),
        ):
            if not value:
                raise ValueError(f"{label} must not be empty")
        object.__setattr__(self, "reviewed_at", _utc(self.reviewed_at, "reviewed_at"))
        _validate_fingerprint(self.evidence_fingerprint, "evidence_fingerprint")
        _validate_fingerprint(self.toolset_fingerprint, "toolset_fingerprint")
        names = [decision.tool_name for decision in self.decisions]
        if len(names) != len(set(names)):
            raise ValueError("review decisions must not contain duplicate tools")


def complete_review(
    profile: ProfileSession,
    available_tools: tuple[AvailableTool, ...],
    *,
    review_id: str,
    reviewer: str,
    reviewed_at: datetime,
    evidence_fingerprint: str,
    decisions: tuple[ReviewDecision, ...],
) -> CompletedReview:
    """Complete a review only after every available tool has one decision."""
    if profile.status is not ProfileStatus.SEALED:
        raise ValueError("profile must be sealed before review")
    available_names = {tool.name for tool in available_tools}
    decision_names = {decision.tool_name for decision in decisions}
    if decision_names != available_names or len(decisions) != len(available_tools):
        raise ValueError("review must contain exactly one decision for every available tool")
    return CompletedReview(
        review_id=review_id,
        profile_id=profile.profile_id,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
        evidence_fingerprint=evidence_fingerprint,
        toolset_fingerprint=profile.toolset_fingerprint,
        decisions=tuple(sorted(decisions, key=lambda decision: decision.tool_name)),
    )


def generate_reviewed_policy(
    profile: ProfileSession,
    available_tools: tuple[AvailableTool, ...],
    review: CompletedReview,
    *,
    policy_id: str,
) -> Policy:
    """Generate policy only from a matching completed review of all tools."""
    if profile.status is not ProfileStatus.SEALED:
        raise ValueError("profile must be sealed before policy generation")
    if review.profile_id != profile.profile_id:
        raise ValueError("review does not belong to the profile")
    if review.toolset_fingerprint != profile.toolset_fingerprint:
        raise ValueError("review toolset does not match the profile")
    available_names = {tool.name for tool in available_tools}
    if {decision.tool_name for decision in review.decisions} != available_names:
        raise ValueError("review does not cover the complete available catalog")
    return Policy(
        policy_id=policy_id,
        task_type=profile.task_type,
        server_id=profile.server_id,
        approved_toolset_fingerprint=profile.toolset_fingerprint,
        reviewed_profile_id=profile.profile_id,
        rules=tuple(
            PolicyRule(
                identity=ToolIdentity(
                    server_id=profile.server_id,
                    tool_name=decision.tool_name,
                ),
                effect=decision.effect,
                constraints=decision.constraints,
                limits=decision.limits,
                primary_risk_category=decision.primary_risk_category,
                capability_tags=decision.capability_tags,
            )
            for decision in review.decisions
        ),
    )


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _validate_fingerprint(value: str, label: str) -> None:
    if fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 fingerprint")
