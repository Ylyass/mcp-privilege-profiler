"""Profile evidence tiers, safe language, and public schema tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from mcp_privprof.application.profile_reports import (
    build_profile_evidence_report,
    render_profile_evidence_json,
    render_profile_evidence_markdown,
)
from mcp_privprof.contracts.profile import (
    ProfileEvidenceReportV1,
    ReviewDecisionsV1,
    ReviewDecisionV1,
)
from mcp_privprof.domain import (
    AvailableTool,
    CallFact,
    CallOutcome,
    CandidateRecommendation,
    EvidenceTier,
    PolicyEffect,
    ProfileSession,
    ProfileStatus,
    RunStatus,
    ScenarioRun,
)

SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "profile-evidence-v1.schema.json"
NOW = datetime(2026, 7, 15, tzinfo=UTC)


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


def _profile() -> ProfileSession:
    return ProfileSession(
        profile_id="profile-1",
        task_type="dependency-review",
        agent_id="agent-1",
        server_id="lab",
        toolset_fingerprint=f"sha256:{'a' * 64}",
        planned_scenarios=("scenario-a", "scenario-b"),
        status=ProfileStatus.SEALED,
        created_at=NOW,
        sealed_at=NOW + timedelta(hours=1),
    )


def _run(run_id: str, scenario_id: str, status: RunStatus) -> ScenarioRun:
    return ScenarioRun(
        run_id=run_id,
        profile_id="profile-1",
        scenario_id=scenario_id,
        status=status,
        started_at=NOW + timedelta(minutes=int(run_id[-1])),
        completed_at=NOW + timedelta(minutes=10 + int(run_id[-1])),
    )


def _call(
    call_id: int,
    run_id: str,
    tool_name: str,
    outcome: CallOutcome | None,
) -> CallFact:
    return CallFact(
        call_id=call_id,
        run_id=run_id,
        tool_name=tool_name,
        attempted_at=NOW + timedelta(minutes=20 + call_id),
        outcome=outcome,
        completed_at=NOW + timedelta(minutes=21 + call_id) if outcome is not None else None,
    )


def _report(
    generated_at: datetime = NOW + timedelta(hours=2),
) -> ProfileEvidenceReportV1:
    available = tuple(
        AvailableTool(name, f"sha256:{digit * 64}")
        for name, digit in (
            ("moderate_tool", "b"),
            ("read_fixture", "c"),
            ("unobserved_tool", "d"),
            ("weak_tool", "e"),
        )
    )
    runs = (
        _run("run-1", "scenario-a", RunStatus.COMPLETED),
        _run("run-2", "scenario-b", RunStatus.COMPLETED),
        _run("run-3", "scenario-a", RunStatus.COMPLETED),
        _run("run-4", "scenario-b", RunStatus.ABORTED),
    )
    calls = (
        _call(1, "run-1", "read_fixture", CallOutcome.SUCCESS),
        _call(2, "run-2", "read_fixture", CallOutcome.SUCCESS),
        _call(3, "run-3", "read_fixture", CallOutcome.SUCCESS),
        _call(4, "run-1", "moderate_tool", CallOutcome.SUCCESS),
        _call(5, "run-2", "moderate_tool", CallOutcome.SUCCESS),
        _call(6, "run-1", "weak_tool", CallOutcome.SUCCESS),
        _call(7, "run-4", "weak_tool", CallOutcome.SUCCESS),
        _call(8, "run-1", "unknown_tool", CallOutcome.SUCCESS),
        _call(9, "run-2", "weak_tool", CallOutcome.TOOL_ERROR),
        _call(10, "run-3", "weak_tool", None),
    )
    return build_profile_evidence_report(
        _profile(),
        available,
        runs,
        calls,
        generated_at=generated_at,
    )


def test_evidence_tiers_use_completed_runs_and_distinct_scenarios() -> None:
    """Repeated calls do not masquerade as scenario coverage or strong evidence."""
    report = _report()
    by_name = {tool.tool_name: tool for tool in report.tools}

    assert by_name["read_fixture"].evidence_tier is EvidenceTier.STRONG
    assert by_name["moderate_tool"].evidence_tier is EvidenceTier.MODERATE
    assert by_name["weak_tool"].evidence_tier is EvidenceTier.WEAK
    assert by_name["weak_tool"].successful_count == 2
    assert by_name["weak_tool"].qualifying_successful_count == 1
    assert by_name["unobserved_tool"].evidence_tier is EvidenceTier.UNOBSERVED
    assert by_name["unknown_tool"].recommendation is CandidateRecommendation.INVESTIGATE_UNLISTED
    assert report.scenario_coverage == 1


def test_profile_evidence_json_validates_and_fingerprint_ignores_generation_time() -> None:
    """The reviewed digest binds evidence facts, not report rendering time."""
    report = _report()
    later = _report(NOW + timedelta(days=1))
    document = json.loads(render_profile_evidence_json(report))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = cast(
        _Validator,
        Draft202012Validator(schema, format_checker=FormatChecker()),
    )
    validator.validate(document)

    assert report.evidence_fingerprint == later.evidence_fingerprint
    assert "raw_arguments" not in document
    assert "result" not in document


def test_markdown_uses_non_authorizing_language() -> None:
    """The UI never calls an unreviewed observation required or approved."""
    markdown = render_profile_evidence_markdown(_report())

    assert "do not prove necessity" in markdown
    assert "do not authorize" in markdown
    assert "required" not in markdown.lower()
    assert "approved" not in markdown.lower()


def test_review_decisions_reject_duplicate_tool_names() -> None:
    """Human review input cannot contain ambiguous duplicate effects."""
    with pytest.raises(ValidationError, match="duplicate"):
        ReviewDecisionsV1(
            profile_id="profile-1",
            evidence_fingerprint=f"sha256:{'f' * 64}",
            decisions=(
                ReviewDecisionV1(
                    tool_name="read_fixture", effect=PolicyEffect.ALLOW, constraints=()
                ),
                ReviewDecisionV1(
                    tool_name="read_fixture", effect=PolicyEffect.DENY, constraints=()
                ),
            ),
        )


def test_evidence_contract_rejects_completed_scenarios_not_proven_by_runs() -> None:
    """Cross-field validation prevents a report from overstating scenario coverage."""
    document = json.loads(render_profile_evidence_json(_report()))
    document["completed_scenarios"] = ["scenario-a"]
    document["scenario_coverage"] = 0.5

    with pytest.raises(ValidationError, match="completed_scenarios"):
        ProfileEvidenceReportV1.model_validate(document)


def test_evidence_contract_rejects_tier_not_derived_from_counts() -> None:
    """Evidence labels must remain reproducible from successful runs and scenarios."""
    document = json.loads(render_profile_evidence_json(_report()))
    read_evidence = next(tool for tool in document["tools"] if tool["tool_name"] == "read_fixture")
    read_evidence["evidence_tier"] = "weak"

    with pytest.raises(ValidationError, match="evidence_tier"):
        ProfileEvidenceReportV1.model_validate(document)
