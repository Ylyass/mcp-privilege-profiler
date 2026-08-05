"""Real client -> proxy -> lab integration tests."""

from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client import Client
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
    """Use the project's supported asyncio backend."""
    return "asyncio"


@pytest.fixture
async def proxy_session() -> AsyncGenerator[ClientSession]:
    """Start the proxy, which in turn starts exactly one lab server."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.proxy"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        yield session


@pytest.mark.anyio
async def test_proxy_preserves_downstream_tool_catalog(
    proxy_session: ClientSession,
) -> None:
    """The transparent proxy exposes the complete downstream catalog."""
    result = await proxy_session.list_tools()

    assert {tool.name for tool in result.tools} == EXPECTED_TOOLS


@pytest.mark.anyio
async def test_proxy_forwards_safe_tool_call(
    proxy_session: ClientSession,
) -> None:
    """A harmless call crosses both MCP sessions and returns unchanged text."""
    result = await proxy_session.call_tool(
        "read_fixture",
        {"relative_path": "project/requirements.txt"},
    )

    assert result.is_error is not True
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text == "demo-parser==1.2.3\ndemo-client==4.5.6\n"


@pytest.mark.anyio
async def test_proxy_preserves_downstream_tool_error(
    proxy_session: ClientSession,
) -> None:
    """A downstream failure remains an MCP tool error rather than a crash."""
    result = await proxy_session.call_tool(
        "read_fixture",
        {"relative_path": "missing.txt"},
    )

    assert result.is_error is True
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert "fixture does not exist" in result.content[0].text


@pytest.mark.anyio
async def test_proxy_negotiates_current_protocol_with_modern_client() -> None:
    """SDK v2 auto negotiation reaches the current protocol through stdio."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.proxy"],
        cwd=PROJECT_ROOT,
    )
    async with Client(stdio_client(parameters), mode="auto", cache=None) as client:
        assert client.protocol_version == "2026-07-28"
        result = await client.list_tools()

    assert {tool.name for tool in result.tools} == EXPECTED_TOOLS
