"""Observation-only MCP proxy bound to one trusted labeled profile run."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError

from mcp_privprof.adapters.mcp.inventory import collect_toolset
from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor
from mcp_privprof.adapters.mcp.transparent_proxy import DownstreamProcess, open_downstream_session
from mcp_privprof.application.profile import ProfileService
from mcp_privprof.domain.profile import CallOutcome, ProfileSession, ScenarioRun


@dataclass(slots=True)
class CatalogState:
    """Mutable exact-catalog state shared with the notification monitor."""

    valid: bool = False


@dataclass(slots=True)
class ProfileProxyContext:
    """Long-lived resources for one initialized upstream profile run."""

    downstream: ClientSession
    catalog: CatalogState


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
            observed = await collect_toolset(
                downstream,
                profile.server_id,
                catalog_timeout_seconds=process.call_timeout_seconds,
            )
            if observed.fingerprint != profile.toolset_fingerprint:
                raise RuntimeError("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
            catalog.valid = True

            async def refresh_catalog() -> None:
                refreshed = await collect_toolset(
                    downstream,
                    profile.server_id,
                    catalog_timeout_seconds=process.call_timeout_seconds,
                )
                catalog.valid = refreshed.fingerprint == profile.toolset_fingerprint

            async with anyio.create_task_group() as task_group:
                task_group.start_soon(notifications.run, refresh_catalog)
                try:
                    yield ProfileProxyContext(downstream=downstream, catalog=catalog)
                finally:
                    await notifications.aclose()

    proxy = Server[ProfileProxyContext](
        name="mcp-privilege-profiler-profile-proxy",
        version="0.0.0",
        instructions="Observation-only profile proxy. Evidence never authorizes calls.",
        lifespan=lifespan,
    )

    async def list_tools(request: types.ListToolsRequest) -> types.ListToolsResult:
        """Expose the unchanged catalog only while its exact digest remains bound."""
        context = proxy.request_context.lifespan_context
        if not context.catalog.valid:
            raise _profile_mcp_error("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
        possible_request = cast(types.ListToolsRequest | None, request)
        try:
            with anyio.fail_after(process.call_timeout_seconds):
                if possible_request is None:
                    return await context.downstream.list_tools()
                return await context.downstream.list_tools(params=possible_request.params)
        except TimeoutError as exc:
            raise _profile_mcp_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT") from exc
        except (
            McpError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ) as exc:
            raise _profile_mcp_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE") from exc

    async def call_tool(name: str, arguments: dict[str, object]) -> types.CallToolResult:
        """Record privacy-safe attempt and outcome facts around one forwarded call."""
        context = proxy.request_context.lifespan_context
        fact = await service.begin_call(run.run_id, name, datetime.now(UTC))
        if not context.catalog.valid:
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_PROFILE_TOOLSET_DRIFT")
        try:
            with anyio.fail_after(process.call_timeout_seconds):
                result = await context.downstream.call_tool(name=name, arguments=arguments)
        except TimeoutError:
            await service.finish_call(
                fact.call_id,
                CallOutcome.INFRASTRUCTURE_ERROR,
                datetime.now(UTC),
            )
            return _profile_error_result("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            McpError,
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
            CallOutcome.TOOL_ERROR if result.isError else CallOutcome.SUCCESS,
            datetime.now(UTC),
        )
        return result

    proxy.list_tools()(list_tools)
    proxy.call_tool(validate_input=True)(call_tool)
    return proxy


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
        isError=True,
    )


def _profile_mcp_error(reason_code: str) -> McpError:
    return McpError(types.ErrorData(code=types.INTERNAL_ERROR, message=reason_code))
