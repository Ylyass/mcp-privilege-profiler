"""Failure, timeout, cancellation, and recovery tests for the proxy."""

from __future__ import annotations

import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

PROJECT_ROOT = Path(__file__).parents[2]


@pytest.fixture
def anyio_backend() -> str:
    """Use the supported asyncio backend."""
    return "asyncio"


@pytest.fixture
async def fault_proxy_session() -> AsyncGenerator[ClientSession]:
    """Start a fresh fault proxy and child server for each test."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.fault_proxy"],
        cwd=PROJECT_ROOT,
    )
    async with (
        stdio_client(parameters) as streams,
        ClientSession(*streams) as session,
    ):
        await session.initialize()
        yield session


def error_text(result_content: list[object]) -> str:
    """Extract the single stable text error used by infrastructure failures."""
    assert len(result_content) == 1
    content = result_content[0]
    assert isinstance(content, TextContent)
    return content.text


@pytest.mark.anyio
async def test_slow_downstream_call_returns_stable_timeout(
    fault_proxy_session: ClientSession,
) -> None:
    """A slow child is cancelled and represented as a bounded MCP tool error."""
    result = await fault_proxy_session.call_tool(
        "delayed_echo",
        {"text": "late", "delay_seconds": 1.0},
    )

    assert result.is_error is True
    assert error_text(list(result.content)) == "MCP_PRIVPROF_DOWNSTREAM_TIMEOUT"


@pytest.mark.anyio
async def test_upstream_cancellation_propagates_and_session_recovers(
    fault_proxy_session: ClientSession,
) -> None:
    """Client cancellation does not become a fake result or poison the session."""
    with anyio.move_on_after(0.05) as scope:
        await fault_proxy_session.call_tool(
            "delayed_echo",
            {"text": "cancel-me", "delay_seconds": 1.0},
        )

    assert scope.cancel_called
    recovery = await fault_proxy_session.call_tool("immediate_echo", {"text": "still-alive"})
    assert recovery.is_error is not True
    assert len(recovery.content) == 1
    assert isinstance(recovery.content[0], TextContent)
    assert recovery.content[0].text == "still-alive"


@pytest.mark.anyio
async def test_downstream_crash_returns_stable_unavailable_error(
    fault_proxy_session: ClientSession,
) -> None:
    """A disposable child crash becomes an error rather than a proxy traceback."""
    result = await fault_proxy_session.call_tool("deliberate_child_exit", {})

    assert result.is_error is True
    assert error_text(list(result.content)) == "MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE"


@pytest.mark.anyio
async def test_malformed_downstream_data_fails_closed(
    fault_proxy_session: ClientSession,
) -> None:
    """Invalid JSON-RPC bytes never pass through the security boundary."""
    result = await fault_proxy_session.call_tool("emit_malformed_and_exit", {})

    assert result.is_error is True
    assert error_text(list(result.content)) == "MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE"
