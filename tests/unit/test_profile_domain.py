"""Profile lifecycle, review gate, and reviewed policy domain tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mcp_privprof.domain import (
    AvailableTool,
    PolicyEffect,
    ProfileSession,
    ProfileStatus,
    ReviewDecision,
    RunStatus,
    complete_review,
    generate_reviewed_policy,
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)
FINGERPRINT = f"sha256:{'a' * 64}"
EVIDENCE_FINGERPRINT = f"sha256:{'b' * 64}"


def _profile() -> ProfileSession:
    return ProfileSession(
        profile_id="profile-1",
        task_type="dependency-review",
        agent_id="agent-1",
        server_id="lab",
        toolset_fingerprint=FINGERPRINT,
        planned_scenarios=("scenario-a", "scenario-b"),
        status=ProfileStatus.OPEN,
        created_at=NOW,
    )


def _tools() -> tuple[AvailableTool, ...]:
    return (
        AvailableTool("read_fixture", f"sha256:{'c' * 64}"),
        AvailableTool("simulated_command_run", f"sha256:{'d' * 64}"),
    )


def _sealed_profile() -> ProfileSession:
    profile = _profile()
    run = profile.start_run("run-1", "scenario-a", NOW)
    completed = run.finish(RunStatus.COMPLETED, NOW + timedelta(minutes=1))
    return profile.seal((completed,), NOW + timedelta(minutes=2))


def test_profile_rejects_duplicate_planned_scenarios() -> None:
    """Scenario coverage cannot be inflated by duplicate plan entries."""
    with pytest.raises(ValueError, match="duplicates"):
        ProfileSession(
            profile_id="profile-1",
            task_type="dependency-review",
            agent_id="agent-1",
            server_id="lab",
            toolset_fingerprint=FINGERPRINT,
            planned_scenarios=("same", "same"),
            status=ProfileStatus.OPEN,
            created_at=NOW,
        )


def test_run_must_use_a_planned_scenario() -> None:
    """Agent-provided labels cannot create trusted scenario coverage."""
    with pytest.raises(ValueError, match="not planned"):
        _profile().start_run("run-1", "unplanned", NOW)


def test_profile_cannot_seal_with_an_open_run() -> None:
    """Incomplete activity cannot be presented as completed scenario evidence."""
    run = _profile().start_run("run-1", "scenario-a", NOW)

    with pytest.raises(ValueError, match="open run"):
        _profile().seal((run,), NOW + timedelta(minutes=1))


def test_unsealed_profile_cannot_be_reviewed() -> None:
    """Observation must be frozen before a human decision is recorded."""
    with pytest.raises(ValueError, match="sealed"):
        complete_review(
            _profile(),
            _tools(),
            review_id="review-1",
            reviewer="operator@example",
            reviewed_at=NOW,
            evidence_fingerprint=EVIDENCE_FINGERPRINT,
            decisions=(),
        )


def test_review_must_decide_every_available_tool_exactly_once() -> None:
    """Omitted tools cannot disappear from the explicit human review."""
    with pytest.raises(ValueError, match="every available tool"):
        complete_review(
            _sealed_profile(),
            _tools(),
            review_id="review-1",
            reviewer="operator@example",
            reviewed_at=NOW,
            evidence_fingerprint=EVIDENCE_FINGERPRINT,
            decisions=(ReviewDecision("read_fixture", PolicyEffect.ALLOW),),
        )


def test_completed_review_generates_exact_policy_decisions() -> None:
    """Only reviewed effects become policy rules; no observation auto-allows."""
    profile = _sealed_profile()
    review = complete_review(
        profile,
        _tools(),
        review_id="review-1",
        reviewer="operator@example",
        reviewed_at=NOW + timedelta(minutes=3),
        evidence_fingerprint=EVIDENCE_FINGERPRINT,
        decisions=(
            ReviewDecision("read_fixture", PolicyEffect.ALLOW),
            ReviewDecision("simulated_command_run", PolicyEffect.DENY),
        ),
    )

    policy = generate_reviewed_policy(
        profile,
        _tools(),
        review,
        policy_id="policy-1",
    )

    assert policy.reviewed_profile_id == "profile-1"
    assert [(rule.identity.tool_name, rule.effect) for rule in policy.rules] == [
        ("read_fixture", PolicyEffect.ALLOW),
        ("simulated_command_run", PolicyEffect.DENY),
    ]
