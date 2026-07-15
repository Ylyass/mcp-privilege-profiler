"""Real paginated MCP inventory collection test."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_privprof.adapters.mcp.inventory import collect_toolset

PROJECT_ROOT = Path(__file__).parents[2]


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


@pytest.mark.anyio
async def test_collector_reads_every_catalog_page() -> None:
    """The inventory collector follows nextCursor until completion."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.paginated_server"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        snapshot = await collect_toolset(session, server_id="pagination-lab")

    assert [tool.name for tool in snapshot.tools] == ["page_one_tool", "page_two_tool"]
    assert snapshot.fingerprint.startswith("sha256:")


@pytest.mark.anyio
async def test_collector_times_out_an_unresponsive_catalog() -> None:
    """Successful initialization cannot lead to an unbounded tools/list wait."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.hanging_catalog_server"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        with pytest.raises(TimeoutError):
            await collect_toolset(
                session,
                server_id="hanging-catalog-lab",
                catalog_timeout_seconds=0.1,
            )
