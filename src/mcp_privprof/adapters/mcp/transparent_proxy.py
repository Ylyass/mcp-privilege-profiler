"""Transparent one-to-one stdio MCP proxy.

This module proves the transport boundary only. Policy, profiling, audit, and
drift behavior are deliberately added in later application-layer stages.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import cast

import anyio
import mcp.types as types
from anyio.abc import ObjectReceiveStream
from anyio.streams.memory import MemoryObjectReceiveStream
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError
from mcp.shared.message import SessionMessage


class DownstreamProtocolError(RuntimeError):
    """The downstream emitted bytes that are not a valid MCP message."""


class StrictMessageStream(ObjectReceiveStream[SessionMessage | Exception]):
    """Convert parser exception items into a closed downstream session."""

    def __init__(
        self,
        source: ObjectReceiveStream[SessionMessage | Exception],
    ) -> None:
        self._source = source

    async def receive(self) -> SessionMessage | Exception:
        """Receive one valid message or fail the downstream protocol."""
        item = await self._source.receive()
        if isinstance(item, Exception):
            raise DownstreamProtocolError("downstream emitted malformed MCP data") from item
        return item

    async def aclose(self) -> None:
        """Close the wrapped receive stream."""
        await self._source.aclose()


@dataclass(frozen=True, slots=True)
class DownstreamProcess:
    """A downstream process definition without shell interpolation."""

    command: str
    args: tuple[str, ...] = ()
    cwd: Path | None = None
    startup_timeout_seconds: float = 10.0
    call_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if not self.command.strip():
            raise ValueError("downstream command must not be empty")
        if not isfinite(self.startup_timeout_seconds) or self.startup_timeout_seconds <= 0:
            raise ValueError("startup timeout must be positive and finite")
        if not isfinite(self.call_timeout_seconds) or self.call_timeout_seconds <= 0:
            raise ValueError("call timeout must be positive and finite")


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
        async with stdio_client(parameters) as streams:
            # ClientSession 1.28.1 is typed against the concrete memory stream
            # although it consumes only the ObjectReceiveStream interface.
            strict_read = cast(
                MemoryObjectReceiveStream[SessionMessage | Exception],
                StrictMessageStream(streams[0]),
            )
            async with ClientSession(strict_read, streams[1]) as downstream:
                try:
                    with anyio.fail_after(process.startup_timeout_seconds):
                        await downstream.initialize()
                except TimeoutError as exc:
                    raise RuntimeError("downstream MCP initialization timed out") from exc
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
        try:
            with anyio.fail_after(process.call_timeout_seconds):
                return await context.downstream.call_tool(name=name, arguments=arguments)
        except TimeoutError:
            return _infrastructure_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            McpError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            return _infrastructure_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")

    proxy.list_tools()(list_tools)
    proxy.call_tool(validate_input=True)(call_tool)
    return proxy


def _infrastructure_error(reason_code: str) -> types.CallToolResult:
    """Return a stable error without leaking downstream exception details."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=reason_code)],
        isError=True,
    )


async def run_transparent_proxy(process: DownstreamProcess) -> None:
    """Serve the upstream side over stdio until the host disconnects."""
    proxy = create_transparent_proxy(process)
    async with stdio_server() as (read_stream, write_stream):
        await proxy.run(
            read_stream,
            write_stream,
            proxy.create_initialization_options(),
        )
