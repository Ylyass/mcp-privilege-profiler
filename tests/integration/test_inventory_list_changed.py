"""Real MCP tools/list_changed inventory refresh integration test."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_privprof.adapters.mcp.inventory import McpToolsetSource
from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor
from mcp_privprof.adapters.sqlite import SqliteInventoryRepository
from mcp_privprof.application import InventoryRefresh, InventoryService

PROJECT_ROOT = Path(__file__).parents[2]


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


@pytest.mark.anyio
async def test_list_changed_notification_creates_a_new_durable_snapshot(tmp_path: Path) -> None:
    """A real server announcement refreshes history outside the receive loop."""
    notifications = ToolListChangedMonitor()
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.changing_catalog_server"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams, message_handler=notifications.handle_message) as session,
    ):
        initialized = await session.initialize()
        assert initialized.capabilities.tools is not None
        assert initialized.capabilities.tools.list_changed is True

        repository = SqliteInventoryRepository(tmp_path / "inventory.sqlite3")
        service = InventoryService(McpToolsetSource(session, "changing-lab"), repository)
        await service.initialize()
        initial = await service.refresh(captured_at=datetime(2026, 7, 15, tzinfo=UTC))
        refreshed = anyio.Event()
        refresh_result: list[InventoryRefresh] = []

        async def refresh() -> None:
            refresh_result.append(
                await service.refresh(captured_at=datetime(2026, 7, 15, 0, 1, tzinfo=UTC))
            )
            refreshed.set()

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(notifications.run, refresh)
            call_result = await session.call_tool("change_catalog", {})
            assert call_result.is_error is False
            with anyio.fail_after(5):
                await refreshed.wait()
            await notifications.aclose()

    assert [tool.name for tool in initial.current.snapshot.tools] == [
        "before_change",
        "change_catalog",
    ]
    assert len(refresh_result) == 1
    changed = refresh_result[0]
    assert [tool.name for tool in changed.current.snapshot.tools] == [
        "after_change",
        "change_catalog",
    ]
    assert changed.drift is not None and changed.drift.changed
    assert len(await repository.history("changing-lab")) == 2
