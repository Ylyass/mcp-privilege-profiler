"""Transparent one-to-one stdio MCP proxy.

This module proves the transport boundary only. Policy, profiling, audit, and
drift behavior are deliberately added in later application-layer stages.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import cast

import anyio
import mcp.types as types
from anyio.abc import ObjectReceiveStream
from anyio.streams.memory import MemoryObjectReceiveStream
from mcp import ClientSession, MCPError, StdioServerParameters
from mcp.client import Client, Transport
from mcp.client.session import MessageHandlerFnT
from mcp.client.stdio import stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
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


async def call_downstream_tool(
    session: ClientSession,
    *,
    name: str,
    arguments: dict[str, object],
    timeout_seconds: float,
) -> types.CallToolResult:
    """Call one downstream tool using the post-startup request budget."""
    with anyio.fail_after(timeout_seconds):
        return await session.call_tool(
            name=name,
            arguments=arguments,
            read_timeout_seconds=timeout_seconds,
        )


@asynccontextmanager
async def open_downstream_session(
    process: DownstreamProcess,
    *,
    message_handler: MessageHandlerFnT | None = None,
) -> AsyncGenerator[ClientSession]:
    """Open one strict downstream session with modern-to-legacy negotiation."""
    parameters = StdioServerParameters(
        command=process.command,
        args=list(process.args),
        cwd=process.cwd,
    )
    transport = cast(Transport, _strict_stdio_transport(parameters))
    client = Client(
        transport,
        mode="auto",
        cache=None,
        message_handler=message_handler,
        read_timeout_seconds=process.startup_timeout_seconds,
    )
    async with AsyncExitStack() as stack:
        connected = await stack.enter_async_context(client)
        yield connected.session


@asynccontextmanager
async def _strict_stdio_transport(
    parameters: StdioServerParameters,
) -> AsyncGenerator[tuple[MemoryObjectReceiveStream[SessionMessage | Exception], object]]:
    """Wrap SDK stdio so malformed downstream protocol data closes the session."""
    async with stdio_client(parameters) as streams:
        source = cast(ObjectReceiveStream[SessionMessage | Exception], streams[0])
        strict_read = cast(
            MemoryObjectReceiveStream[SessionMessage | Exception],
            StrictMessageStream(source),
        )
        yield strict_read, streams[1]


def create_transparent_proxy(
    process: DownstreamProcess,
) -> Server[ProxyContext]:
    """Create a proxy bound to exactly one downstream stdio MCP server."""

    @asynccontextmanager
    async def lifespan(_: Server[ProxyContext]) -> AsyncGenerator[ProxyContext]:
        async with open_downstream_session(process) as downstream:
            yield ProxyContext(downstream=downstream)

    async def list_tools(
        context: ServerRequestContext[ProxyContext],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Forward tools/list without caching the security-relevant catalog."""
        try:
            with anyio.fail_after(process.call_timeout_seconds):
                return await context.lifespan_context.downstream.send_request(
                    types.ListToolsRequest(params=params),
                    types.ListToolsResult,
                    request_read_timeout_seconds=process.call_timeout_seconds,
                )
        except TimeoutError as exc:
            raise _proxy_mcp_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT") from exc
        except (
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ) as exc:
            raise _proxy_mcp_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE") from exc

    async def call_tool(
        context: ServerRequestContext[ProxyContext],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        """Forward a validated tool call and preserve its complete result."""
        try:
            return await call_downstream_tool(
                context.lifespan_context.downstream,
                name=params.name,
                arguments=params.arguments or {},
                timeout_seconds=process.call_timeout_seconds,
            )
        except TimeoutError:
            return _infrastructure_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            return _infrastructure_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")

    return Server[ProxyContext](
        name="mcp-privilege-profiler-proxy",
        version="0.0.0",
        instructions="Transparent stdio proxy transport proof.",
        lifespan=lifespan,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def _infrastructure_error(reason_code: str) -> types.CallToolResult:
    """Return a stable error without leaking downstream exception details."""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=reason_code)],
        is_error=True,
    )


def _proxy_mcp_error(reason_code: str) -> MCPError:
    """Return a stable catalog error without exposing downstream details."""
    return MCPError(
        code=types.INTERNAL_ERROR,
        message=reason_code,
        data={"reason_code": reason_code},
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
