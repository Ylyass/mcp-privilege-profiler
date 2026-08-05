"""Observation-only MCP proxy bound to one trusted labeled profile run."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

import anyio
import mcp.types as types
from mcp import ClientSession, MCPError
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_privprof.adapters.mcp.inventory import collect_catalog
from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor
from mcp_privprof.adapters.mcp.transparent_proxy import (
    DownstreamProcess,
    call_downstream_tool,
    open_downstream_session,
)
from mcp_privprof.application.profile import ProfileService
from mcp_privprof.domain.profile import CallOutcome, ProfileSession, ScenarioRun


@dataclass(slots=True)
class CatalogState:
    """Mutable exact-catalog state shared with the notification monitor."""

    valid: bool = False
    tools: tuple[types.Tool, ...] = ()


@dataclass(slots=True)
class ProfileProxyContext:
    """Long-lived resources for one initialized upstream profile run."""

    downstream: ClientSession
    catalog: CatalogState
    refresh_catalog: Callable[[], Awaitable[None]]


def create_profile_proxy(
    process: DownstreamProcess,
    profile: ProfileSession,
    run: ScenarioRun,
    service: ProfileService,
) -> Server[ProfileProxyContext]:
    """Create an observation proxy that never turns evidence into permission."""
    if run.profile_id != profile.profile_id:
        raise ValueError("run does not belong to profile")

    catalog = CatalogState()

    def invalidate_catalog() -> None:
        catalog.valid = False

    notifications = ToolListChangedMonitor(on_signal=invalidate_catalog)

    @asynccontextmanager
    async def lifespan(_: Server[ProfileProxyContext]) -> AsyncGenerator[ProfileProxyContext]:
        async with open_downstream_session(
            process,
            message_handler=notifications.handle_message,
        ) as downstream:
            observed = await collect_catalog(
                downstream,
                profile.server_id,
                catalog_timeout_seconds=process.call_timeout_seconds,
            )
            if observed.snapshot.fingerprint != profile.toolset_fingerprint:
                raise RuntimeError("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
            catalog.tools = observed.tools
            catalog.valid = True

            refresh_lock = anyio.Lock()

            async def refresh_catalog() -> None:
                async with refresh_lock:
                    catalog.valid = False
                    refreshed = await collect_catalog(
                        downstream,
                        profile.server_id,
                        catalog_timeout_seconds=process.call_timeout_seconds,
                    )
                    if refreshed.snapshot.fingerprint == profile.toolset_fingerprint:
                        catalog.tools = refreshed.tools
                        catalog.valid = True

            async with anyio.create_task_group() as task_group:
                task_group.start_soon(notifications.run, refresh_catalog)
                try:
                    yield ProfileProxyContext(
                        downstream=downstream,
                        catalog=catalog,
                        refresh_catalog=refresh_catalog,
                    )
                finally:
                    await notifications.aclose()

    async def list_tools(
        context: ServerRequestContext[ProfileProxyContext],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Expose the unchanged catalog only while its exact digest remains bound."""
        state = context.lifespan_context
        try:
            with anyio.fail_after(process.call_timeout_seconds):
                await state.refresh_catalog()
        except TimeoutError as exc:
            raise _profile_mcp_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT") from exc
        except (
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ) as exc:
            raise _profile_mcp_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE") from exc
        if not state.catalog.valid:
            raise _profile_mcp_error("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
        if params is not None and params.cursor is not None:
            raise _profile_mcp_error(
                "MCP_PRIVPROF_INVALID_CATALOG_CURSOR",
                code=types.INVALID_PARAMS,
            )
        return types.ListToolsResult(tools=list(state.catalog.tools))

    async def call_tool(
        context: ServerRequestContext[ProfileProxyContext],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        """Record privacy-safe attempt and outcome facts around one forwarded call."""
        state = context.lifespan_context
        name = params.name
        arguments = params.arguments or {}
        fact = await service.begin_call(run.run_id, name, datetime.now(UTC))
        try:
            await state.refresh_catalog()
        except TimeoutError:
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")
        if not state.catalog.valid:
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
        try:
            result = await call_downstream_tool(
                state.downstream,
                name=name,
                arguments=arguments,
                timeout_seconds=process.call_timeout_seconds,
            )
        except TimeoutError:
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")

        await service.finish_call(
            fact.call_id,
            CallOutcome.TOOL_ERROR if result.is_error else CallOutcome.SUCCESS,
            datetime.now(UTC),
        )
        return result

    return Server[ProfileProxyContext](
        name="mcp-privilege-profiler-profile-proxy",
        version="0.0.0",
        instructions="Observation-only profile proxy. Evidence never authorizes calls.",
        lifespan=lifespan,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


async def run_profile_proxy(
    process: DownstreamProcess,
    profile: ProfileSession,
    run: ScenarioRun,
    service: ProfileService,
) -> None:
    """Serve one labeled profile run over the upstream stdio transport."""
    proxy = create_profile_proxy(process, profile, run, service)
    async with stdio_server() as (read_stream, write_stream):
        await proxy.run(
            read_stream,
            write_stream,
            proxy.create_initialization_options(),
        )


def _profile_error_result(reason_code: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=reason_code)],
        is_error=True,
    )


def _profile_mcp_error(
    reason_code: str,
    *,
    code: int = types.INTERNAL_ERROR,
) -> MCPError:
    return MCPError(code=code, message=reason_code)
