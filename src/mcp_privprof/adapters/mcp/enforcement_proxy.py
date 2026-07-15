"""Reviewed, deny-by-default MCP enforcement proxy."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import anyio
import jsonschema
import mcp.types as types
from mcp import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import McpError

from mcp_privprof.adapters.mcp.inventory import CollectedCatalog, collect_catalog
from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor
from mcp_privprof.adapters.mcp.transparent_proxy import DownstreamProcess, open_downstream_session
from mcp_privprof.application.constraints import evaluate_constraints, validate_path_root_coverage
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity


@dataclass(slots=True)
class EnforcementCatalog:
    """Mutable catalog validity and definitions shared with the refresh worker."""

    valid: bool = False
    tools: tuple[types.Tool, ...] = ()


@dataclass(slots=True)
class EnforcementProxyContext:
    """Resources kept alive for one initialized enforcement session."""

    downstream: ClientSession
    catalog: EnforcementCatalog


def create_enforcement_proxy(
    process: DownstreamProcess,
    policy: Policy,
    path_roots: Mapping[str, Path],
) -> Server[EnforcementProxyContext]:
    """Create an exact-policy proxy that denies before downstream forwarding."""
    rules = {rule.identity.tool_name: rule for rule in policy.rules}
    validate_path_root_coverage(
        tuple(constraint for rule in policy.rules for constraint in rule.constraints),
        path_roots,
    )
    catalog = EnforcementCatalog()

    def invalidate_catalog() -> None:
        catalog.valid = False

    notifications = ToolListChangedMonitor(on_signal=invalidate_catalog)

    @asynccontextmanager
    async def lifespan(
        _: Server[EnforcementProxyContext],
    ) -> AsyncGenerator[EnforcementProxyContext]:
        async with open_downstream_session(
            process,
            message_handler=notifications.handle_message,
        ) as downstream:
            observed = await collect_catalog(
                downstream,
                policy.server_id,
                catalog_timeout_seconds=process.call_timeout_seconds,
            )
            accept_exact_catalog(observed, policy, rules, catalog)

            async def refresh_catalog() -> None:
                refreshed = await collect_catalog(
                    downstream,
                    policy.server_id,
                    catalog_timeout_seconds=process.call_timeout_seconds,
                )
                if refreshed.snapshot.fingerprint == policy.approved_toolset_fingerprint:
                    catalog.tools = refreshed.tools
                    catalog.valid = True
                else:
                    catalog.valid = False

            async with anyio.create_task_group() as task_group:
                task_group.start_soon(notifications.run, refresh_catalog)
                try:
                    yield EnforcementProxyContext(downstream=downstream, catalog=catalog)
                finally:
                    await notifications.aclose()

    proxy = Server[EnforcementProxyContext](
        name="mcp-privilege-profiler-enforcement-proxy",
        version="0.0.0",
        instructions="Reviewed, exact-match, deny-by-default MCP enforcement boundary.",
        lifespan=lifespan,
    )

    async def list_tools(request: types.ListToolsRequest) -> types.ListToolsResult:
        """Return one filtered page containing only reviewed non-DENY tools."""
        context = proxy.request_context.lifespan_context
        if not context.catalog.valid:
            raise _enforcement_mcp_error("MCP_PRIVPROF_POLICY_TOOLSET_DRIFT")
        possible_request = cast(types.ListToolsRequest | None, request)
        if (
            possible_request is not None
            and possible_request.params is not None
            and possible_request.params.cursor is not None
        ):
            raise _enforcement_mcp_error(
                "MCP_PRIVPROF_INVALID_CATALOG_CURSOR",
                code=types.INVALID_PARAMS,
            )
        visible = [
            tool
            for tool in context.catalog.tools
            if rules[tool.name].effect in (PolicyEffect.ALLOW, PolicyEffect.REQUIRE_APPROVAL)
        ]
        return types.ListToolsResult(tools=visible)

    async def call_tool(name: str, arguments: dict[str, object]) -> types.CallToolResult:
        """Decide and constrain a call before any downstream tool request is sent."""
        context = proxy.request_context.lifespan_context
        if not context.catalog.valid:
            return _enforcement_error("MCP_PRIVPROF_POLICY_TOOLSET_DRIFT")

        observed_names = {tool.name for tool in context.catalog.tools}
        if name not in observed_names:
            return _enforcement_error("MCP_PRIVPROF_UNKNOWN_TOOL")

        decision = policy.decide(ToolIdentity(server_id=policy.server_id, tool_name=name))
        rule = rules.get(name)
        if decision.effect is PolicyEffect.DENY or rule is None:
            return _enforcement_error("MCP_PRIVPROF_POLICY_DENY")

        constraint_check = evaluate_constraints(rule.constraints, arguments, path_roots)
        if not constraint_check.allowed:
            return _enforcement_error(
                constraint_check.reason_code,
                constraint_kind=constraint_check.constraint_kind,
                argument_name=constraint_check.argument_name,
            )

        if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
            return _enforcement_error("MCP_PRIVPROF_APPROVAL_REQUIRED")

        tool = next(item for item in context.catalog.tools if item.name == name)
        try:
            jsonschema.validate(instance=arguments, schema=tool.inputSchema)
        except Exception:
            # Schemas are untrusted downstream data. Invalid schemas, failed
            # references, and validation errors all deny without forwarding.
            return _enforcement_error("MCP_PRIVPROF_INPUT_SCHEMA_INVALID")

        try:
            with anyio.fail_after(process.call_timeout_seconds):
                return await context.downstream.call_tool(name=name, arguments=arguments)
        except TimeoutError:
            return _enforcement_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            McpError,
            RuntimeError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            return _enforcement_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")

    proxy.list_tools()(list_tools)
    # Permission and constraint checks must run before generic input-schema
    # validation, so denied calls cannot observe schema details.
    proxy.call_tool(validate_input=False)(call_tool)
    return proxy


def accept_exact_catalog(
    observed: CollectedCatalog,
    policy: Policy,
    rules: Mapping[str, PolicyRule],
    catalog: EnforcementCatalog,
) -> None:
    """Activate only a complete policy over the exact approved catalog."""
    if observed.snapshot.fingerprint != policy.approved_toolset_fingerprint:
        raise RuntimeError("MCP_PRIVPROF_POLICY_TOOLSET_DRIFT")
    observed_names = {tool.name for tool in observed.tools}
    unknown_rules = sorted(rules.keys() - observed_names)
    missing_rules = sorted(observed_names - rules.keys())
    if unknown_rules or missing_rules:
        raise RuntimeError("MCP_PRIVPROF_POLICY_CATALOG_INCOMPLETE")
    tools_by_name = {tool.name: tool for tool in observed.tools}
    for rule in rules.values():
        properties = tools_by_name[rule.identity.tool_name].inputSchema.get("properties")
        for constraint in rule.constraints:
            if not isinstance(properties, dict) or constraint.argument not in properties:
                raise RuntimeError("MCP_PRIVPROF_POLICY_CONSTRAINT_TARGET_INVALID")
    catalog.tools = observed.tools
    catalog.valid = True


def _enforcement_error(
    reason_code: str,
    *,
    constraint_kind: str | None = None,
    argument_name: str | None = None,
) -> types.CallToolResult:
    details: dict[str, object] = {"reason_code": reason_code}
    if constraint_kind is not None:
        details["constraint_kind"] = constraint_kind
    if argument_name is not None:
        details["argument_name"] = argument_name
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=reason_code)],
        structuredContent=details,
        isError=True,
    )


def _enforcement_mcp_error(
    reason_code: str,
    *,
    code: int = types.INTERNAL_ERROR,
) -> McpError:
    return McpError(
        types.ErrorData(
            code=code,
            message=reason_code,
            data={"reason_code": reason_code},
        )
    )


async def run_enforcement_proxy(
    process: DownstreamProcess,
    policy: Policy,
    path_roots: Mapping[str, Path],
) -> None:
    """Serve a reviewed enforcement boundary over stdio until disconnect."""
    proxy = create_enforcement_proxy(process, policy, path_roots)
    async with stdio_server() as (read_stream, write_stream):
        await proxy.run(
            read_stream,
            write_stream,
            proxy.create_initialization_options(),
        )
