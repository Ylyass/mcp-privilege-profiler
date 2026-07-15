"""Sealed profile evidence summaries and reviewer-facing reports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from typing import Literal, cast

from mcp_privprof.application.fingerprints import JsonValue, fingerprint_json
from mcp_privprof.contracts.profile import (
    ProfileEvidenceReportV1,
    ProfileRunV1,
    ProfileToolEvidenceV1,
    ReviewDecisionsV1,
    ReviewDecisionV1,
)
from mcp_privprof.domain.policy import PolicyEffect
from mcp_privprof.domain.profile import (
    AvailableTool,
    CallFact,
    CallOutcome,
    CandidateRecommendation,
    EvidenceTier,
    ProfileSession,
    ProfileStatus,
    RunStatus,
    ScenarioRun,
    ToolEvidence,
)


def build_profile_evidence_report(
    profile: ProfileSession,
    available_tools: tuple[AvailableTool, ...],
    runs: tuple[ScenarioRun, ...],
    calls: tuple[CallFact, ...],
    *,
    generated_at: datetime,
) -> ProfileEvidenceReportV1:
    """Build immutable evidence only after the profile is sealed."""
    if profile.status is not ProfileStatus.SEALED or profile.sealed_at is None:
        raise ValueError("profile must be sealed before evidence reporting")
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must include a timezone")
    run_by_id = {run.run_id: run for run in runs}
    if len(run_by_id) != len(runs) or any(run.profile_id != profile.profile_id for run in runs):
        raise ValueError("runs must be unique and belong to the profile")
    if any(run.status is RunStatus.OPEN for run in runs):
        raise ValueError("sealed profile evidence cannot contain open runs")
    if any(call.run_id not in run_by_id for call in calls):
        raise ValueError("every call must belong to a supplied profile run")

    evidence = _summarize_tools(profile, available_tools, run_by_id, calls)
    completed_scenarios = tuple(
        scenario
        for scenario in profile.planned_scenarios
        if any(run.scenario_id == scenario and run.status is RunStatus.COMPLETED for run in runs)
    )
    report_runs = tuple(
        ProfileRunV1(
            run_id=run.run_id,
            scenario_id=run.scenario_id,
            status=cast("RunReportStatus", run.status.value),
        )
        for run in runs
    )
    report_tools = tuple(_profile_tool_contract(item) for item in evidence)
    core: JsonValue = {
        "profile_id": profile.profile_id,
        "profile_status": profile.status.value,
        "task_type": profile.task_type,
        "agent_id": profile.agent_id,
        "server_id": profile.server_id,
        "toolset_fingerprint": profile.toolset_fingerprint,
        "created_at": _timestamp(profile.created_at),
        "sealed_at": _timestamp(profile.sealed_at),
        "planned_scenarios": list(profile.planned_scenarios),
        "completed_scenarios": list(completed_scenarios),
        "runs": [run.model_dump(mode="json") for run in report_runs],
        "tools": [tool.model_dump(mode="json") for tool in report_tools],
    }
    _, evidence_fingerprint = fingerprint_json(core)
    return ProfileEvidenceReportV1(
        generated_at=generated_at.astimezone(UTC),
        evidence_fingerprint=evidence_fingerprint,
        profile_id=profile.profile_id,
        profile_status="SEALED",
        task_type=profile.task_type,
        agent_id=profile.agent_id,
        server_id=profile.server_id,
        toolset_fingerprint=profile.toolset_fingerprint,
        created_at=profile.created_at,
        sealed_at=profile.sealed_at,
        planned_scenarios=profile.planned_scenarios,
        completed_scenarios=completed_scenarios,
        scenario_coverage=len(completed_scenarios) / len(profile.planned_scenarios),
        completed_run_count=sum(run.status is RunStatus.COMPLETED for run in runs),
        aborted_run_count=sum(run.status is RunStatus.ABORTED for run in runs),
        runs=report_runs,
        tools=report_tools,
    )


type RunReportStatus = Literal["COMPLETED", "ABORTED"]


def render_profile_evidence_json(report: ProfileEvidenceReportV1) -> bytes:
    document = report.model_dump(mode="json")
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def render_profile_evidence_markdown(report: ProfileEvidenceReportV1) -> str:
    """Render evidence with an explicit non-authorization warning."""
    lines = [
        "# MCP Profile Evidence",
        "",
        "> These observations do not prove necessity and do not authorize any tool.",
        "> A human must review every available tool before policy generation.",
        "",
        f"- Profile: {_markdown_text(report.profile_id)}",
        f"- Task type: {_markdown_text(report.task_type)}",
        f"- Agent: {_markdown_text(report.agent_id)}",
        f"- Server: {_markdown_text(report.server_id)}",
        f"- Evidence fingerprint: `{report.evidence_fingerprint}`",
        f"- Scenario coverage: `{len(report.completed_scenarios)}/{len(report.planned_scenarios)}`",
        f"- Completed runs: `{report.completed_run_count}`",
        f"- Aborted runs: `{report.aborted_run_count}`",
        "",
        "## Tool evidence",
        "",
        "| Tool | Available | Attempts | Successes | Completed-run successes | Tier | Guidance |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    lines.extend(
        "| "
        + " | ".join(
            (
                _markdown_text(tool.tool_name),
                "yes" if tool.available else "no",
                str(tool.attempted_count),
                str(tool.successful_count),
                str(tool.qualifying_successful_count),
                _label(tool.evidence_tier.value),
                _label(tool.recommendation.value),
            )
        )
        + " |"
        for tool in report.tools
    )
    lines.extend(
        [
            "",
            "Evidence tiers are transparent heuristics, not statistical confidence.",
            "Repeating one scenario increases run count but not scenario coverage.",
            "",
        ]
    )
    return "\n".join(lines)


def build_review_template(report: ProfileEvidenceReportV1) -> ReviewDecisionsV1:
    """Create an exact-evidence review file with the safest editable default."""
    return ReviewDecisionsV1(
        profile_id=report.profile_id,
        evidence_fingerprint=report.evidence_fingerprint,
        decisions=tuple(
            ReviewDecisionV1(
                tool_name=tool.tool_name,
                effect=PolicyEffect.DENY,
                constraints=(),
            )
            for tool in report.tools
            if tool.available
        ),
    )


def render_review_decisions_json(review: ReviewDecisionsV1) -> bytes:
    """Render a deterministic, schema-versioned human decision document."""
    document = review.model_dump(mode="json")
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _summarize_tools(
    profile: ProfileSession,
    available_tools: tuple[AvailableTool, ...],
    run_by_id: dict[str, ScenarioRun],
    calls: tuple[CallFact, ...],
) -> tuple[ToolEvidence, ...]:
    available_by_name = {tool.name: tool for tool in available_tools}
    if len(available_by_name) != len(available_tools):
        raise ValueError("available tools must be unique")
    names = sorted(available_by_name.keys() | {call.tool_name for call in calls})
    summaries: list[ToolEvidence] = []
    for name in names:
        tool_calls = tuple(call for call in calls if call.tool_name == name)
        successful = tuple(call for call in tool_calls if call.outcome is CallOutcome.SUCCESS)
        qualifying = tuple(
            call for call in successful if run_by_id[call.run_id].status is RunStatus.COMPLETED
        )
        successful_run_ids = {call.run_id for call in qualifying}
        successful_scenarios = tuple(
            scenario
            for scenario in profile.planned_scenarios
            if any(run_by_id[run_id].scenario_id == scenario for run_id in successful_run_ids)
        )
        tier = _evidence_tier(
            profile.planned_scenarios,
            successful_run_ids,
            successful_scenarios,
        )
        available = available_by_name.get(name)
        recommendation = (
            CandidateRecommendation.INVESTIGATE_UNLISTED
            if available is None
            else CandidateRecommendation.CONSIDER_ALLOW
            if tier is not EvidenceTier.UNOBSERVED
            else CandidateRecommendation.NO_SUCCESSFUL_EVIDENCE
        )
        summaries.append(
            ToolEvidence(
                tool_name=name,
                available=available is not None,
                fingerprint=available.fingerprint if available is not None else None,
                attempted_count=len(tool_calls),
                successful_count=len(successful),
                failed_count=sum(
                    call.outcome in (CallOutcome.TOOL_ERROR, CallOutcome.INFRASTRUCTURE_ERROR)
                    for call in tool_calls
                ),
                incomplete_count=sum(call.outcome is None for call in tool_calls),
                qualifying_successful_count=len(qualifying),
                successful_runs=len(successful_run_ids),
                successful_scenarios=successful_scenarios,
                evidence_tier=tier,
                recommendation=recommendation,
            )
        )
    return tuple(summaries)


def _evidence_tier(
    planned_scenarios: tuple[str, ...],
    successful_run_ids: set[str],
    successful_scenarios: tuple[str, ...],
) -> EvidenceTier:
    if len(successful_run_ids) >= 3 and set(successful_scenarios) == set(planned_scenarios):
        return EvidenceTier.STRONG
    if len(successful_scenarios) >= 2:
        return EvidenceTier.MODERATE
    if successful_run_ids:
        return EvidenceTier.WEAK
    return EvidenceTier.UNOBSERVED


def _profile_tool_contract(evidence: ToolEvidence) -> ProfileToolEvidenceV1:
    return ProfileToolEvidenceV1(
        tool_name=evidence.tool_name,
        available=evidence.available,
        fingerprint=evidence.fingerprint,
        attempted_count=evidence.attempted_count,
        successful_count=evidence.successful_count,
        failed_count=evidence.failed_count,
        incomplete_count=evidence.incomplete_count,
        qualifying_successful_count=evidence.qualifying_successful_count,
        successful_runs=evidence.successful_runs,
        successful_scenarios=evidence.successful_scenarios,
        evidence_tier=evidence.evidence_tier,
        recommendation=evidence.recommendation,
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _markdown_text(value: str) -> str:
    return escape(value, quote=True).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def _label(value: str) -> str:
    return value.replace("_", " ").title()
