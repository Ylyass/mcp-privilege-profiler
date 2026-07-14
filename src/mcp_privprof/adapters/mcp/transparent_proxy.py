"""Transparent one-to-one stdio MCP proxy.

This module proves the transport boundary only. Policy, profiling, audit, and
drift behavior are deliberately added in later application-layer stages.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


@dataclass(frozen=True, slots=True)
class DownstreamProcess:
    """A downstream process definition without shell interpolation."""

    command: str
    args: tuple[str, ...] = ()
    cwd: Path | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("downstream command must not be empty")


@dataclass(slots=True)
class ProxyContext:
    """Resources kept alive for the full upstream proxy session."""

    downstream: ClientSession


def create_transparent_proxy(
    process: DownstreamProcess,
) -> Server[ProxyContext]:
    """Create a proxy bound to exactly one downstream stdio MCP server."""

    @asynccontextmanager
    async def lifespan(_: Server[ProxyContext]) -> AsyncGenerator[ProxyContext]:
        parameters = StdioServerParameters(
            command=process.command,
            args=list(process.args),
            cwd=process.cwd,
        )
        async with (
            stdio_client(parameters) as streams,
            ClientSession(*streams) as downstream,
        ):
            await downstream.initialize()
            yield ProxyContext(downstream=downstream)

    proxy = Server[ProxyContext](
        name="mcp-privilege-profiler-proxy",
        version="0.0.0",
        instructions="Transparent stdio proxy transport proof.",
        lifespan=lifespan,
    )

    async def list_tools(
        request: types.ListToolsRequest,
    ) -> types.ListToolsResult:
        """Forward tools/list, including the SDK's internal cache refresh."""
        context = proxy.request_context.lifespan_context
        # MCP SDK 1.28.1 requires this exact parameter annotation for request
        # dispatch, while its call-tool cache refresh invokes the handler with
        # None internally. Widen only after registration introspection.
        possible_request = cast(types.ListToolsRequest | None, request)
        if possible_request is None:
            return await context.downstream.list_tools()
        return await context.downstream.list_tools(params=possible_request.params)

    async def call_tool(
        name: str,
        arguments: dict[str, object],
    ) -> types.CallToolResult:
        """Forward a validated tool call and preserve its complete result."""
        context = proxy.request_context.lifespan_context
        return await context.downstream.call_tool(name=name, arguments=arguments)

    proxy.list_tools()(list_tools)
    proxy.call_tool(validate_input=True)(call_tool)
    return proxy


async def run_transparent_proxy(process: DownstreamProcess) -> None:
    """Serve the upstream side over stdio until the host disconnects."""
    proxy = create_transparent_proxy(process)
    async with stdio_server() as (read_stream, write_stream):
        await proxy.run(
            read_stream,
            write_stream,
            proxy.create_initialization_options(),
        )
