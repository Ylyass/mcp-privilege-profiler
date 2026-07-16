"""Evidence-bound review and deterministic public policy tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

import mcp.types as types
import pytest
from jsonschema import Draft202012Validator

from mcp_privprof.adapters.mcp.inventory import snapshot_toolset
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository, SqliteProfileRepository
from mcp_privprof.application import ProfileService
from mcp_privprof.application.policies import policy_contract, render_policy_json
from mcp_privprof.domain import (
    PathConstraint,
    PolicyEffect,
    ProfileSession,
    ProfileStatus,
    ReviewDecision,
    RunStatus,
    ToolLimits,
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)
POLICY_SCHEMA = Path(__file__).parents[2] / "schemas" / "policy-v1.schema.json"


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _sealed_service(database_path: Path) -> ProfileService:
    inventory_repository = SqliteInventoryRepository(database_path)
    await inventory_repository.initialize()
    snapshot = snapshot_toolset(
        "lab",
        [
            types.Tool(
                name="read_fixture",
                inputSchema={"type": "object", "properties": {}},
            )
        ],
    )
    inventory = await inventory_repository.save(snapshot, NOW)
    service = ProfileService(SqliteProfileRepository(database_path))
    await service.initialize()
    await service.create(
        ProfileSession(
            profile_id="profile-1",
            task_type="dependency-review",
            agent_id="agent-1",
            server_id="lab",
            toolset_fingerprint=snapshot.fingerprint,
            planned_scenarios=("scenario-a",),
            status=ProfileStatus.OPEN,
            created_at=NOW,
        ),
        inventory,
    )
    await service.start_run(
        "profile-1",
        run_id="run-1",
        scenario_id="scenario-a",
        started_at=NOW + timedelta(minutes=1),
    )
    await service.finish_run(
        "run-1",
        status=RunStatus.COMPLETED,
        completed_at=NOW + timedelta(minutes=2),
    )
    await service.seal("profile-1", sealed_at=NOW + timedelta(minutes=3))
    return service


@pytest.mark.anyio
async def test_review_rejects_stale_or_substituted_evidence_digest(tmp_path: Path) -> None:
    """A human decision file must identify the exact evidence being reviewed."""
    service = await _sealed_service(tmp_path / "state.sqlite3")

    with pytest.raises(ValueError, match="does not match"):
        await service.complete_review(
            "profile-1",
            review_id="review-1",
            reviewer="operator@example",
            reviewed_at=NOW + timedelta(minutes=4),
            evidence_fingerprint=f"sha256:{'f' * 64}",
            decisions=(ReviewDecision("read_fixture", PolicyEffect.ALLOW),),
        )


@pytest.mark.anyio
async def test_completed_review_renders_schema_valid_policy(tmp_path: Path) -> None:
    """Only the completed evidence-bound review produces policy-v1 JSON."""
    service = await _sealed_service(tmp_path / "state.sqlite3")
    evidence = await service.evidence_report(
        "profile-1",
        generated_at=NOW + timedelta(minutes=4),
    )
    review = await service.complete_review(
        "profile-1",
        review_id="review-1",
        reviewer="operator@example",
        reviewed_at=NOW + timedelta(minutes=5),
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
        ),
    )
    domain_policy = await service.policy_from_review(review.review_id, "policy-1")
    document = json.loads(render_policy_json(policy_contract(domain_policy)))
    schema = json.loads(POLICY_SCHEMA.read_text(encoding="utf-8"))
    validator = cast(_Validator, Draft202012Validator(schema))
    validator.validate(document)

    assert document["reviewed_profile_id"] == "profile-1"
    assert document["default_effect"] == "DENY"
    assert document["tools"] == [
        {
            "constraints": [
                {
                    "argument": "relative_path",
                    "kind": "path",
                    "path_roots": ["PROJECT_ROOT"],
                }
            ],
            "effect": "ALLOW",
            "limits": {
                "max_calls_per_minute": 60,
                "max_calls_per_task": 100,
                "max_concurrent_calls": 2,
            },
            "primary_risk_category": "file_read",
            "capability_tags": ["filesystem"],
            "tool_name": "read_fixture",
        }
    ]
