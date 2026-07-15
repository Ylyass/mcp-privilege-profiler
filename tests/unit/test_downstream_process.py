"""Validation tests for safe downstream process configuration."""

from __future__ import annotations

import math

import pytest

from mcp_privprof.adapters.mcp.transparent_proxy import DownstreamProcess


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
