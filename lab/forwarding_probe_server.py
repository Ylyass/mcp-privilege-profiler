"""Harmless MCP fixture that records forwarding only inside the OS temp tree."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

import anyio
import mcp.types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

_marker_path: Path | None = None


async def list_tools(
    _: ServerRequestContext[dict[str, object]],
    __: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    """Expose one deterministic no-argument forwarding probe."""
    return types.ListToolsResult(
        tools=[
            types.Tool(
                name="mark_forwarded",
                description="Create a harmless test marker in the operating-system temp tree.",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            )
        ]
    )


async def call_tool(
    _: ServerRequestContext[dict[str, object]],
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    """Create the marker only if the proxy actually forwarded this call."""
    if params.name != "mark_forwarded" or _marker_path is None:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="UNKNOWN_FIXTURE_TOOL")],
            is_error=True,
        )
    with _marker_path.open("x", encoding="utf-8") as marker:
        marker.write("FORWARDED\n")
    return types.CallToolResult(
        content=[types.TextContent(type="text", text="FORWARD_RECORDED")],
    )


server = Server[dict[str, object]](
    name="mcp-privilege-profiler-forwarding-probe",
    version="0.0.0",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


async def run(marker_path: Path) -> None:
    """Run the probe after constraining its only side effect to OS temporary storage."""
    global _marker_path
    temporary_root = Path(tempfile.gettempdir()).resolve()
    resolved_marker = marker_path.resolve()
    if not resolved_marker.is_relative_to(temporary_root) or resolved_marker.exists():
        raise ValueError("forwarding probe marker must be a new file inside the OS temp tree")
    _marker_path = resolved_marker
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())


def main() -> None:
    """Parse the explicit temporary marker path and start the fixture."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", type=Path, required=True)
    arguments = parser.parse_args()
    anyio.run(run, arguments.marker)


if __name__ == "__main__":
    main()
