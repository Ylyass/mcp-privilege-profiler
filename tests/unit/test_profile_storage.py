"""SQLite profile evidence, migration, and review persistence tests."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import mcp.types as types
import pytest

from mcp_privprof.adapters.mcp.inventory import snapshot_toolset
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository, SqliteProfileRepository
from mcp_privprof.application import ProfileService
from mcp_privprof.domain import (
    CallOutcome,
    PathConstraint,
    PolicyEffect,
    ProfileSession,
    ProfileStatus,
    ReviewDecision,
    RunStatus,
    ToolLimits,
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


def _tool(name: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=f"Fixture {name}",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )


async def _create_profile(database_path: Path) -> tuple[ProfileService, ProfileSession]:
    inventory_repository = SqliteInventoryRepository(database_path)
    await inventory_repository.initialize()
    snapshot = snapshot_toolset("lab", [_tool("read_fixture"), _tool("simulated_command_run")])
    inventory = await inventory_repository.save(snapshot, NOW)
    service = ProfileService(SqliteProfileRepository(database_path))
    await service.initialize()
    profile = ProfileSession(
        profile_id="profile-1",
        task_type="dependency-review",
        agent_id="agent-1",
        server_id="lab",
        toolset_fingerprint=snapshot.fingerprint,
        planned_scenarios=("scenario-a", "scenario-b"),
        status=ProfileStatus.OPEN,
        created_at=NOW,
    )
    await service.create(profile, inventory)
    return service, profile


@pytest.mark.anyio
async def test_profile_storage_round_trips_privacy_safe_call_facts(tmp_path: Path) -> None:
    """Attempts and outcomes persist without any argument or result columns."""
    database_path = tmp_path / "state.sqlite3"
    service, profile = await _create_profile(database_path)
    run = await service.start_run(
        profile.profile_id,
        run_id="run-1",
        scenario_id="scenario-a",
        started_at=NOW + timedelta(minutes=1),
    )
    attempted = await service.begin_call(
        run.run_id,
        "read_fixture",
        NOW + timedelta(minutes=2),
    )
    completed = await service.finish_call(
        attempted.call_id,
        CallOutcome.SUCCESS,
        NOW + timedelta(minutes=3),
    )
    await service.finish_run(
        run.run_id,
        status=RunStatus.COMPLETED,
        completed_at=NOW + timedelta(minutes=4),
    )

    assert await service.profile(profile.profile_id) == profile
    assert await service.calls(profile.profile_id) == (completed,)
    with sqlite3.connect(database_path) as database:
        columns = [row[1] for row in database.execute("PRAGMA table_info(profile_calls)")]
    assert columns == [
        "call_id",
        "run_id",
        "tool_name",
        "attempted_at",
        "outcome",
        "completed_at",
    ]


@pytest.mark.anyio
async def test_profile_review_and_policy_gate_round_trip(tmp_path: Path) -> None:
    """A sealed stored profile can be reviewed once and then generate policy."""
    service, profile = await _create_profile(tmp_path / "state.sqlite3")
    run = await service.start_run(
        profile.profile_id,
        run_id="run-1",
        scenario_id="scenario-a",
        started_at=NOW + timedelta(minutes=1),
    )
    await service.finish_run(
        run.run_id,
        status=RunStatus.COMPLETED,
        completed_at=NOW + timedelta(minutes=2),
    )
    sealed = await service.seal(profile.profile_id, sealed_at=NOW + timedelta(minutes=3))
    evidence = await service.evidence_report(
        profile.profile_id,
        generated_at=NOW + timedelta(minutes=4),
    )
    review = await service.complete_review(
        profile.profile_id,
        review_id="review-1",
        reviewer="operator@example",
        reviewed_at=NOW + timedelta(minutes=4),
        evidence_fingerprint=evidence.evidence_fingerprint,
        decisions=(
            ReviewDecision(
                "read_fixture",
                PolicyEffect.ALLOW,
                (PathConstraint("relative_path", ("PROJECT_ROOT",)),),
                ToolLimits(60, 100, 2),
                "file_read",
                ("filesystem",),
            ),
            ReviewDecision("simulated_command_run", PolicyEffect.DENY),
        ),
    )
    policy = await service.policy_from_review(review.review_id, "policy-1")

    assert sealed.status is ProfileStatus.SEALED
    assert policy.reviewed_profile_id == profile.profile_id
    assert [(rule.identity.tool_name, rule.effect) for rule in policy.rules] == [
        ("read_fixture", PolicyEffect.ALLOW),
        ("simulated_command_run", PolicyEffect.DENY),
    ]
    assert policy.rules[0].constraints == (PathConstraint("relative_path", ("PROJECT_ROOT",)),)


@pytest.mark.anyio
async def test_policy_generation_rejects_missing_completed_review(tmp_path: Path) -> None:
    """A profile observation alone can never become an enforceable policy."""
    service, _ = await _create_profile(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="completed review"):
        await service.policy_from_review("missing-review", "policy-1")


@pytest.mark.anyio
async def test_schema_one_database_migrates_to_current_schema(tmp_path: Path) -> None:
    """Existing inventory history survives the profile-table migration."""
    database_path = tmp_path / "state.sqlite3"
    inventory_repository = SqliteInventoryRepository(database_path)
    await inventory_repository.initialize()
    stored = await inventory_repository.save(snapshot_toolset("lab", [_tool("read")]), NOW)
    with sqlite3.connect(database_path) as database:
        for table in (
            "approval_permits",
            "enforcement_rate_usage",
            "enforcement_task_usage",
            "profile_review_decisions",
            "profile_reviews",
            "profile_calls",
            "profile_runs",
            "profile_scenarios",
            "profile_sessions",
        ):
            database.execute(f"DROP TABLE {table}")
        database.execute("DELETE FROM schema_migrations WHERE version >= 2")

    profile_repository = SqliteProfileRepository(database_path)
    await profile_repository.initialize()

    assert await inventory_repository.latest("lab") == stored
    with sqlite3.connect(database_path) as database:
        version = database.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        profile_table = database.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'profile_sessions'"
        ).fetchone()
        decision_columns = [
            row[1] for row in database.execute("PRAGMA table_info(profile_review_decisions)")
        ]
    assert version == 4
    assert profile_table == ("profile_sessions",)
    assert decision_columns[-4:] == [
        "constraints_json",
        "limits_json",
        "primary_risk_category",
        "capability_tags_json",
    ]


@pytest.mark.anyio
async def test_schema_two_review_rows_gain_empty_constraints_on_migration(
    tmp_path: Path,
) -> None:
    """A completed pre-constraint review remains readable and deny-preserving."""
    database_path = tmp_path / "state.sqlite3"
    service, profile = await _create_profile(database_path)
    run = await service.start_run(
        profile.profile_id,
        run_id="schema-2-run",
        scenario_id="scenario-a",
        started_at=NOW + timedelta(minutes=1),
    )
    await service.finish_run(
        run.run_id,
        status=RunStatus.COMPLETED,
        completed_at=NOW + timedelta(minutes=2),
    )
    await service.seal(profile.profile_id, sealed_at=NOW + timedelta(minutes=3))
    evidence = await service.evidence_report(
        profile.profile_id,
        generated_at=NOW + timedelta(minutes=4),
    )
    original = await service.complete_review(
        profile.profile_id,
        review_id="review-schema-2",
        reviewer="operator@example",
        reviewed_at=NOW + timedelta(minutes=5),
        evidence_fingerprint=evidence.evidence_fingerprint,
        decisions=(
            ReviewDecision("read_fixture", PolicyEffect.ALLOW),
            ReviewDecision("simulated_command_run", PolicyEffect.DENY),
        ),
    )
    with sqlite3.connect(database_path) as database:
        database.execute("DROP TABLE approval_permits")
        database.execute("DROP TABLE enforcement_rate_usage")
        database.execute("DROP TABLE enforcement_task_usage")
        database.execute("ALTER TABLE profile_review_decisions DROP COLUMN capability_tags_json")
        database.execute("ALTER TABLE profile_review_decisions DROP COLUMN primary_risk_category")
        database.execute("ALTER TABLE profile_review_decisions DROP COLUMN limits_json")
        database.execute("ALTER TABLE profile_review_decisions DROP COLUMN constraints_json")
        database.execute("DELETE FROM schema_migrations WHERE version >= 3")

    migrated_repository = SqliteProfileRepository(database_path)
    await migrated_repository.initialize()

    assert await migrated_repository.get_review(original.review_id) == original
