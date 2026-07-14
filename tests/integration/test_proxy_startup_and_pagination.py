"""Startup-boundary and pagination tests for the transparent proxy."""

from __future__ import annotations

import sys
from pathlib import Path

import anyio
import mcp.types as types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError

PROJECT_ROOT = Path(__file__).parents[2]


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


@pytest.mark.anyio
async def test_proxy_preserves_two_page_tool_catalog() -> None:
    """Both the request cursor and downstream nextCursor cross the proxy."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.paginated_proxy"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        first = await session.list_tools()
        assert [tool.name for tool in first.tools] == ["page_one_tool"]
        assert first.nextCursor == "page-2"
        second = await session.list_tools(
            params=types.PaginatedRequestParams(cursor=first.nextCursor)
        )

    assert [tool.name for tool in second.tools] == ["page_two_tool"]
    assert second.nextCursor is None


@pytest.mark.anyio
async def test_hanging_downstream_startup_is_bounded() -> None:
    """An unresponsive child cannot keep proxy initialization open forever."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.hanging_proxy"],
        cwd=PROJECT_ROOT,
    )

    with anyio.fail_after(6):
        with pytest.RaisesGroup(
            pytest.RaisesExc(McpError, match="Connection closed"),
            flatten_subgroups=True,
        ):
            async with (
                stdio_client(parameters) as streams,
                ClientSession(*streams) as session,
            ):
                await session.initialize()
