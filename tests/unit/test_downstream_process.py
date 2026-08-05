"""Validation tests for safe downstream process configuration."""

from __future__ import annotations

import math
from typing import cast

import pytest
from mcp import ClientSession
from mcp import types as mcp_types

from mcp_privprof.adapters.mcp.transparent_proxy import DownstreamProcess, call_downstream_tool


class RecordingSession:
    """Minimal call-tool spy for request-budget regression coverage."""

    def __init__(self) -> None:
        self.read_timeout_seconds: float | None = None

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, object] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> mcp_types.CallToolResult:
        del name, arguments
        self.read_timeout_seconds = read_timeout_seconds
        return mcp_types.CallToolResult(content=[mcp_types.TextContent(type="text", text="ok")])


@pytest.mark.parametrize("command", ["", "   "])
def test_empty_downstream_command_is_rejected(command: str) -> None:
    """An absent executable cannot form a valid process boundary."""
    with pytest.raises(ValueError, match="command"):
        DownstreamProcess(command=command)


@pytest.mark.parametrize("timeout", [0.0, -1.0, math.inf, math.nan])
def test_invalid_startup_timeout_is_rejected(timeout: float) -> None:
    """Startup waits must always be positive and finite."""
    with pytest.raises(ValueError, match="startup timeout"):
        DownstreamProcess(command="python", startup_timeout_seconds=timeout)


@pytest.mark.parametrize("timeout", [0.0, -1.0, math.inf, math.nan])
def test_invalid_call_timeout_is_rejected(timeout: float) -> None:
    """Tool-call waits must always be positive and finite."""
    with pytest.raises(ValueError, match="call timeout"):
        DownstreamProcess(command="python", call_timeout_seconds=timeout)


@pytest.mark.anyio
async def test_tool_call_uses_the_post_startup_request_budget() -> None:
    """Tool calls do not inherit the separate negotiation timeout."""
    recording = RecordingSession()

    result = await call_downstream_tool(
        cast(ClientSession, recording),
        name="safe_tool",
        arguments={},
        timeout_seconds=7.5,
    )

    assert result.is_error is not True
    assert recording.read_timeout_seconds == 7.5
