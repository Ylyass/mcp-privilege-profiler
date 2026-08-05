"""MCP fixture that announces a deterministic live tool-catalog change."""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp.server import NotificationOptions
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

_catalog_changed = False


async def list_tools(
    _: ServerRequestContext[dict[str, object]],
    __: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    """Return a catalog that changes only after the explicit fixture call."""
    catalog = [_tool("change_catalog")]
    catalog.append(_tool("after_change") if _catalog_changed else _tool("before_change"))
    return types.ListToolsResult(tools=catalog)


async def call_tool(
    context: ServerRequestContext[dict[str, object]],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    """Change the catalog and send the standard list-changed notification."""
    global _catalog_changed
    if params.name != "change_catalog":
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="UNKNOWN_FIXTURE_TOOL")],
            is_error=True,
        )
    _catalog_changed = True
    await context.session.send_tool_list_changed()
    return types.CallToolResult(
        content=[types.TextContent(type="text", text="CATALOG_CHANGED")],
    )


def _tool(name: str) -> types.Tool:
    return types.Tool(
        name=name,
        description=f"Changing-catalog fixture {name}.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    )


server = Server[dict[str, object]](
    name="mcp-privilege-profiler-changing-catalog-lab",
    version="0.0.0",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def run() -> None:
    """Run the changing-catalog fixture over stdio."""
    options = server.create_initialization_options(
        notification_options=NotificationOptions(tools_changed=True)
    )
    async with stdio_server() as streams:
        await server.run(*streams, options)


if __name__ == "__main__":
    anyio.run(run)
