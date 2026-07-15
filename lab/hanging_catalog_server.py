"""MCP fixture that initializes but never answers tools/list."""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server(name="mcp-privilege-profiler-hanging-catalog-lab", version="0.0.0")


async def list_tools(_: types.ListToolsRequest) -> types.ListToolsResult:
    """Wait until the client cancels the intentionally unresponsive request."""
    await anyio.sleep_forever()
    raise AssertionError("sleep_forever returned unexpectedly")


server.list_tools()(list_tools)


async def run() -> None:
    """Run the unresponsive catalog fixture over stdio."""
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(run)
