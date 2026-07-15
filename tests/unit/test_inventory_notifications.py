"""Catalog-change notification queue behavior tests."""

from __future__ import annotations

import anyio
import mcp.types as types
import pytest

from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


def _notification() -> types.ServerNotification:
    return types.ServerNotification(types.ToolListChangedNotification())


@pytest.mark.anyio
async def test_monitor_coalesces_bursts_without_blocking_message_handler() -> None:
    """Many announcements before a worker starts require one complete refresh."""
    monitor = ToolListChangedMonitor()
    for _ in range(10):
        await monitor.handle_message(_notification())

    refreshed = anyio.Event()
    refresh_count = 0

    async def refresh() -> None:
        nonlocal refresh_count
        refresh_count += 1
        refreshed.set()

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(monitor.run, refresh)
        with anyio.fail_after(1):
            await refreshed.wait()
        await monitor.aclose()

    assert refresh_count == 1


@pytest.mark.anyio
async def test_monitor_propagates_refresh_failure() -> None:
    """A failed security refresh is visible instead of silently discarded."""
    monitor = ToolListChangedMonitor()

    async def fail_refresh() -> None:
        raise RuntimeError("refresh failed")

    with pytest.RaisesGroup(pytest.RaisesExc(RuntimeError, match="refresh failed")):
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(monitor.run, fail_refresh)
            await monitor.handle_message(_notification())
