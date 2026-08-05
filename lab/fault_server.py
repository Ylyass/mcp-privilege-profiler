"""Fault-injection MCP server used only by proxy lifecycle tests."""

from __future__ import annotations

import os
import sys

import anyio
from mcp.server import MCPServer

mcp = MCPServer("mcp-privilege-profiler-fault-lab")


@mcp.tool()
async def delayed_echo(text: str, delay_seconds: float) -> str:
    """Return text after a bounded delay for timeout and cancellation tests."""
    if not 0 <= delay_seconds <= 5:
        raise ValueError("delay_seconds must be between 0 and 5")
    await anyio.sleep(delay_seconds)
    return text


@mcp.tool()
def immediate_echo(text: str) -> str:
    """Return text immediately to prove the session remains usable."""
    return text


@mcp.tool()
def deliberate_child_exit() -> str:
    """Terminate only this disposable lab child to simulate a server crash."""
    os._exit(23)


@mcp.tool()
def emit_malformed_and_exit() -> str:
    """Emit an invalid protocol line, then terminate the disposable child."""
    sys.stdout.write("this-is-not-json-rpc\n")
    sys.stdout.flush()
    os._exit(24)


if __name__ == "__main__":
    mcp.run(transport="stdio")
