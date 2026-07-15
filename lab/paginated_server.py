"""Two-page MCP catalog used to prove pagination through the proxy."""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server(name="mcp-privilege-profiler-pagination-lab", version="0.0.0")


async def list_tools(request: types.ListToolsRequest) -> types.ListToolsResult:
    """Return a deterministic two-page tool catalog."""
    cursor = request.params.cursor if request.params is not None else None
    if cursor is None:
        return types.ListToolsResult(
            tools=[_tool("page_one_tool")],
            nextCursor="page-2",
        )
    if cursor == "page-2":
        return types.ListToolsResult(tools=[_tool("page_two_tool")])
    return types.ListToolsResult(tools=[])


def _tool(name: str) -> types.Tool:
    """Create a minimal valid tool definition."""
    return types.Tool(
        name=name,
        description=f"Pagination fixture {name}.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    )


server.list_tools()(list_tools)


async def run() -> None:
    """Run the pagination fixture over stdio."""
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(run)
