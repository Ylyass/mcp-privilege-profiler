"""Restart-resistant rate, task-budget, concurrency, and rollback tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_privprof.adapters.sqlite import SqliteEnforcementRepository
from mcp_privprof.application.limits import LimitCoordinator
from mcp_privprof.domain import LimitType, ToolLimits

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    """Use the project's supported asyncio backend."""
    return "asyncio"


async def _coordinator(path: Path) -> LimitCoordinator:
    coordinator = LimitCoordinator(SqliteEnforcementRepository(path))
    await coordinator.initialize()
    return coordinator


@pytest.mark.anyio
async def test_task_budget_survives_coordinator_restart(tmp_path: Path) -> None:
    """A new proxy process cannot reset the reviewed task call budget."""
    database = tmp_path / "state.sqlite3"
    limits = ToolLimits(10, 1, 1)
    first = await _coordinator(database)
    reserved = await first.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    assert reserved.lease is not None
    await first.finish(reserved.lease, forwarded=True)

    restarted = await _coordinator(database)
    denied = await restarted.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW + timedelta(seconds=1),
    )

    assert not denied.allowed
    assert denied.limit_type is LimitType.CALLS_PER_TASK


@pytest.mark.anyio
async def test_rate_limit_survives_coordinator_restart(tmp_path: Path) -> None:
    """A fixed-window rate count persists across proxy restarts."""
    database = tmp_path / "state.sqlite3"
    limits = ToolLimits(1, 10, 1)
    first = await _coordinator(database)
    reserved = await first.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    assert reserved.lease is not None
    await first.finish(reserved.lease, forwarded=True)

    restarted = await _coordinator(database)
    denied = await restarted.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW + timedelta(seconds=1),
    )

    assert not denied.allowed
    assert denied.limit_type is LimitType.CALLS_PER_MINUTE


@pytest.mark.anyio
async def test_concurrency_limit_releases_and_failed_audit_rolls_back_usage(
    tmp_path: Path,
) -> None:
    """A non-forwarded lease consumes neither concurrency nor persistent budget."""
    coordinator = await _coordinator(tmp_path / "state.sqlite3")
    limits = ToolLimits(1, 1, 1)
    first = await coordinator.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    assert first.lease is not None

    concurrent = await coordinator.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    assert concurrent.limit_type is LimitType.CONCURRENT_CALLS

    await coordinator.finish(first.lease, forwarded=False)
    retried = await coordinator.reserve(
        task_id="task-1",
        policy_id="policy-1",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )

    assert retried.allowed
    assert retried.lease is not None
    await coordinator.finish(retried.lease, forwarded=True)
