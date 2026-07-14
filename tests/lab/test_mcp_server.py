"""Real stdio MCP handshake and tool-call test for the lab server."""

from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

PROJECT_ROOT = Path(__file__).parents[2]
EXPECTED_TOOLS = {
    "fetch_fixture_advisory",
    "list_fixture_directory",
    "read_fixture",
    "simulated_command_run",
    "simulated_credential_read",
    "simulated_external_post",
    "write_sandbox_patch",
}


@pytest.fixture
def anyio_backend() -> str:
    """The stdio SDK path is verified on the project's asyncio backend."""
    return "asyncio"


@pytest.fixture
async def lab_session() -> AsyncGenerator[ClientSession]:
    """Start the real lab subprocess and complete MCP initialization."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.server"],
        cwd=PROJECT_ROOT,
    )
    async with stdio_client(parameters) as streams, ClientSession(*streams) as session:
        await session.initialize()
        yield session


@pytest.mark.anyio
async def test_lab_server_lists_expected_tools(lab_session: ClientSession) -> None:
    """The real MCP catalog contains only the seven documented lab tools."""
    result = await lab_session.list_tools()

    assert {tool.name for tool in result.tools} == EXPECTED_TOOLS


@pytest.mark.anyio
async def test_lab_server_calls_safe_fixture_tool(lab_session: ClientSession) -> None:
    """A client can read deterministic fixture data over real MCP stdio."""
    result = await lab_session.call_tool(
        "read_fixture",
        {"relative_path": "project/requirements.txt"},
    )

    assert result.isError is not True
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert "demo-parser==1.2.3" in result.content[0].text
