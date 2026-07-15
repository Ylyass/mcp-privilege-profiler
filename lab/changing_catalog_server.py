"""MCP fixture that announces a deterministic live tool-catalog change."""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp.server import NotificationOptions
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server(name="mcp-privilege-profiler-changing-catalog-lab", version="0.0.0")
_catalog_changed = False


async def list_tools(_: types.ListToolsRequest) -> types.ListToolsResult:
    """Return a catalog that changes only after the explicit fixture call."""
    catalog = [_tool("change_catalog")]
    catalog.append(_tool("after_change") if _catalog_changed else _tool("before_change"))
    return types.ListToolsResult(tools=catalog)


async def call_tool(name: str, _: dict[str, object]) -> types.CallToolResult:
    """Change the catalog and send the standard list-changed notification."""
    global _catalog_changed
    if name != "change_catalog":
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="UNKNOWN_FIXTURE_TOOL")],
            isError=True,
        )
    _catalog_changed = True
    await server.request_context.session.send_tool_list_changed()
    return types.CallToolResult(
        content=[types.TextContent(type="text", text="CATALOG_CHANGED")],
    )


def _tool(name: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=f"Changing-catalog fixture {name}.",
        inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
    )


server.list_tools()(list_tools)
server.call_tool(validate_input=True)(call_tool)


async def run() -> None:
    """Run the changing-catalog fixture over stdio."""
    options = server.create_initialization_options(
        notification_options=NotificationOptions(tools_changed=True)
    )
    async with stdio_server() as streams:
        await server.run(*streams, options)


if __name__ == "__main__":
    anyio.run(run)
