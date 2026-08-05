"""Reviewed, audited, deny-by-default MCP enforcement proxy."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import anyio
import jsonschema
import mcp.types as types
from mcp import ClientSession, MCPError
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from mcp_privprof.adapters.approval_control import ApprovalControlServer
from mcp_privprof.adapters.mcp.inventory import (
    CollectedCatalog,
    collect_catalog,
    snapshot_tool,
)
from mcp_privprof.adapters.mcp.notifications import ToolListChangedMonitor
from mcp_privprof.adapters.mcp.transparent_proxy import (
    DownstreamProcess,
    call_downstream_tool,
    open_downstream_session,
)
from mcp_privprof.application.audit import (
    ArgumentFacts,
    DriftSeverityValue,
    EnforcementIdentity,
    argument_facts,
    build_audit_event,
)
from mcp_privprof.application.constraints import evaluate_constraints, validate_path_root_coverage
from mcp_privprof.application.limits import LimitCoordinator
from mcp_privprof.application.permits import PermitCheck, PermitService
from mcp_privprof.domain.limits import LimitType
from mcp_privprof.domain.permits import ApprovalPermit
from mcp_privprof.domain.policy import Policy, PolicyEffect, PolicyRule, ToolIdentity
from mcp_privprof.ports.audit import AuditSink

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class EnforcementCatalog:
    """Mutable catalog and mandatory-audit validity."""

    valid: bool = False
    audit_valid: bool = True
    tools: tuple[types.Tool, ...] = ()


@dataclass(slots=True)
class EnforcementProxyContext:
    """Resources kept alive for one initialized enforcement session."""

    downstream: ClientSession
    catalog: EnforcementCatalog
    refresh_catalog: Callable[[], Awaitable[None]]


def create_enforcement_proxy(
    process: DownstreamProcess,
    policy: Policy,
    path_roots: Mapping[str, Path],
    *,
    identity: EnforcementIdentity,
    audit_sink: AuditSink,
    limits: LimitCoordinator,
    permits: PermitService,
    approval_control_path: Path | None,
    approval_control_secret: bytes | None,
) -> Server[EnforcementProxyContext]:
    """Create an exact policy, mandatory-audit, bounded MCP proxy."""
    rules = {rule.identity.tool_name: rule for rule in policy.rules}
    validate_path_root_coverage(
        tuple(constraint for rule in policy.rules for constraint in rule.constraints),
        path_roots,
    )
    if any(rule.effect is not PolicyEffect.DENY and rule.limits is None for rule in policy.rules):
        raise ValueError("MCP_PRIVPROF_POLICY_LIMITS_REQUIRED")
    requires_approval = any(rule.effect is PolicyEffect.REQUIRE_APPROVAL for rule in policy.rules)
    if (approval_control_path is None) != (approval_control_secret is None):
        raise ValueError("MCP_PRIVPROF_APPROVAL_CONTROL_CONFIGURATION_INVALID")
    if requires_approval and approval_control_path is None:
        raise ValueError("MCP_PRIVPROF_APPROVAL_CONTROL_REQUIRED")
    catalog = EnforcementCatalog()

    def invalidate_catalog() -> None:
        catalog.valid = False

    notifications = ToolListChangedMonitor(on_signal=invalidate_catalog)

    async def audit_approved_permit(permit: ApprovalPermit) -> None:
        rule = rules[permit.tool_name]
        await audit_sink.append(
            build_audit_event(
                event_type="permit_decision",
                timestamp=datetime.now(UTC),
                trace_id=permit.request_id,
                identity=identity,
                task_type=policy.task_type,
                server_id=policy.server_id,
                tool_name=permit.tool_name,
                tool_fingerprint=_tool_fingerprint(catalog, permit.tool_name),
                policy_id=policy.policy_id,
                rule=rule,
                effect=PolicyEffect.REQUIRE_APPROVAL,
                decision="allowed",
                reason_code="MCP_PRIVPROF_PERMIT_APPROVED",
                facts=None,
                permit_id=permit.permit_id,
            )
        )

    approval_control: ApprovalControlServer | None = None
    if approval_control_path is not None:
        assert approval_control_secret is not None
        approval_control = ApprovalControlServer(
            control_path=approval_control_path,
            secret=approval_control_secret,
            permits=permits,
            on_approved=audit_approved_permit,
        )

    @asynccontextmanager
    async def lifespan(
        _: Server[EnforcementProxyContext],
    ) -> AsyncGenerator[EnforcementProxyContext]:
        await audit_sink.initialize()
        await limits.initialize()
        await permits.initialize()
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

            refresh_lock = anyio.Lock()

            async def refresh_catalog() -> None:
                async with refresh_lock:
                    catalog.valid = False
                    refreshed = await collect_catalog(
                        downstream,
                        policy.server_id,
                        catalog_timeout_seconds=process.call_timeout_seconds,
                    )
                    if refreshed.snapshot.fingerprint == policy.approved_toolset_fingerprint:
                        catalog.tools = refreshed.tools
                        catalog.valid = True

            if approval_control is not None:
                await approval_control.initialize()
            async with anyio.create_task_group() as task_group:
                task_group.start_soon(notifications.run, refresh_catalog)
                if approval_control is not None:
                    task_group.start_soon(approval_control.serve)
                try:
                    yield EnforcementProxyContext(
                        downstream=downstream,
                        catalog=catalog,
                        refresh_catalog=refresh_catalog,
                    )
                finally:
                    await notifications.aclose()
                    if approval_control is not None:
                        await approval_control.aclose()

    async def list_tools(
        context: ServerRequestContext[EnforcementProxyContext],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Return one filtered page only while catalog and audit remain healthy."""
        state = context.lifespan_context
        if not state.catalog.audit_valid:
            raise _enforcement_mcp_error("MCP_PRIVPROF_AUDIT_UNAVAILABLE")
        try:
            await state.refresh_catalog()
        except (
            TimeoutError,
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ) as exc:
            raise _enforcement_mcp_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE") from exc
        if not state.catalog.valid:
            raise _enforcement_mcp_error("MCP_PRIVPROF_POLICY_TOOLSET_DRIFT")
        if params is not None and params.cursor is not None:
            raise _enforcement_mcp_error(
                "MCP_PRIVPROF_INVALID_CATALOG_CURSOR",
                code=types.INVALID_PARAMS,
            )
        visible = [
            tool
            for tool in state.catalog.tools
            if rules[tool.name].effect in (PolicyEffect.ALLOW, PolicyEffect.REQUIRE_APPROVAL)
        ]
        return types.ListToolsResult(tools=visible)

    async def call_tool(
        context: ServerRequestContext[EnforcementProxyContext],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        """Audit, bound, approve, and forward one exact reviewed call."""
        state = context.lifespan_context
        name = params.name
        arguments = params.arguments or {}
        started_at = datetime.now(UTC)
        started_monotonic = anyio.current_time()
        trace_id = f"trace-{uuid4().hex}"
        rule = rules.get(name)
        facts = _argument_facts(arguments, rule)
        if not state.catalog.audit_valid:
            return _enforcement_error("MCP_PRIVPROF_AUDIT_UNAVAILABLE")
        if facts is None:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=None,
                reason_code="MCP_PRIVPROF_ARGUMENT_CANONICALIZATION_FAILED",
            )
        try:
            await state.refresh_catalog()
        except (
            TimeoutError,
            MCPError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE",
            )
        if not state.catalog.valid:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_POLICY_TOOLSET_DRIFT",
                drift_severity="security_widening",
            )

        observed_names = {tool.name for tool in state.catalog.tools}
        if name not in observed_names:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=None,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_UNKNOWN_TOOL",
            )

        decision = policy.decide(ToolIdentity(server_id=policy.server_id, tool_name=name))
        if decision.effect is PolicyEffect.DENY or rule is None:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_POLICY_DENY",
            )

        constraint_check = evaluate_constraints(rule.constraints, arguments, path_roots)
        if not constraint_check.allowed:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code=constraint_check.reason_code,
                error_details={
                    "constraint_kind": constraint_check.constraint_kind,
                    "argument_name": constraint_check.argument_name,
                },
            )

        tool = next(item for item in state.catalog.tools if item.name == name)
        try:
            jsonschema.validate(instance=arguments, schema=tool.input_schema)
        except Exception:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_INPUT_SCHEMA_INVALID",
            )

        assert rule.limits is not None
        try:
            limit_check = await limits.reserve(
                task_id=identity.task_id,
                policy_id=policy.policy_id,
                tool_name=name,
                limits=rule.limits,
                now=started_at,
            )
        except Exception:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_LIMIT_STATE_UNAVAILABLE",
            )
        if not limit_check.allowed or limit_check.lease is None:
            return await _deny_with_audit(
                audit_sink=audit_sink,
                catalog=catalog,
                identity=identity,
                policy=policy,
                rule=rule,
                name=name,
                trace_id=trace_id,
                timestamp=started_at,
                facts=facts,
                reason_code="MCP_PRIVPROF_LIMIT_EXCEEDED",
                limit_type=limit_check.limit_type,
                error_details={"limit_type": limit_check.limit_type.value},
            )
        lease = limit_check.lease

        permit_check: PermitCheck | None = None
        if decision.effect is PolicyEffect.REQUIRE_APPROVAL:
            try:
                permit_check = await permits.authorize_or_request(
                    task_id=identity.task_id,
                    policy_id=policy.policy_id,
                    server_id=policy.server_id,
                    tool_name=name,
                    arguments=arguments,
                    now=started_at,
                )
            except Exception:
                await limits.finish(lease, forwarded=False)
                return await _deny_with_audit(
                    audit_sink=audit_sink,
                    catalog=catalog,
                    identity=identity,
                    policy=policy,
                    rule=rule,
                    name=name,
                    trace_id=trace_id,
                    timestamp=started_at,
                    facts=facts,
                    reason_code="MCP_PRIVPROF_PERMIT_STATE_UNAVAILABLE",
                )
            if not permit_check.allowed:
                await limits.finish(lease, forwarded=False)
                return await _approval_with_audit(
                    audit_sink=audit_sink,
                    catalog=catalog,
                    identity=identity,
                    policy=policy,
                    rule=rule,
                    name=name,
                    trace_id=trace_id,
                    timestamp=started_at,
                    facts=facts,
                    permit_check=permit_check,
                )

        preforward = build_audit_event(
            event_type="policy_decision",
            timestamp=started_at,
            trace_id=trace_id,
            identity=identity,
            task_type=policy.task_type,
            server_id=policy.server_id,
            tool_name=name,
            tool_fingerprint=snapshot_tool(tool).fingerprint,
            policy_id=policy.policy_id,
            rule=rule,
            effect=decision.effect,
            decision="allowed",
            reason_code=(
                "MCP_PRIVPROF_PERMIT_CONSUMED"
                if permit_check is not None
                else "MCP_PRIVPROF_POLICY_ALLOW"
            ),
            facts=facts,
            permit_id=permit_check.permit_id if permit_check is not None else None,
        )
        try:
            await audit_sink.append(preforward)
        except Exception:
            catalog.audit_valid = False
            await limits.finish(lease, forwarded=False)
            return _enforcement_error("MCP_PRIVPROF_AUDIT_WRITE_FAILED")

        result: types.CallToolResult
        forwarded = True
        try:
            result = await call_downstream_tool(
                state.downstream,
                name=name,
                arguments=arguments,
                timeout_seconds=process.call_timeout_seconds,
            )
        except TimeoutError:
            result = _enforcement_error("MCP_PRIVPROF_DOWNSTREAM_TIMEOUT")
        except (
            MCPError,
            RuntimeError,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
            anyio.EndOfStream,
        ):
            result = _enforcement_error("MCP_PRIVPROF_DOWNSTREAM_UNAVAILABLE")
        finally:
            await limits.finish(lease, forwarded=forwarded)

        completion = build_audit_event(
            event_type="tool_completion",
            timestamp=datetime.now(UTC),
            trace_id=trace_id,
            identity=identity,
            task_type=policy.task_type,
            server_id=policy.server_id,
            tool_name=name,
            tool_fingerprint=snapshot_tool(tool).fingerprint,
            policy_id=policy.policy_id,
            rule=rule,
            effect=decision.effect,
            decision="allowed",
            reason_code=_completion_reason(result),
            facts=facts,
            duration_ms=max(0, int((anyio.current_time() - started_monotonic) * 1000)),
            permit_id=permit_check.permit_id if permit_check is not None else None,
        )
        try:
            await audit_sink.append(completion)
        except Exception:
            # The downstream action already happened. Preserve its actual result to
            # prevent blind retries, then close the gate for all future activity.
            catalog.audit_valid = False
            logger.critical("MCP_PRIVPROF_AUDIT_COMPLETION_FAILED")
        return result

    return Server[EnforcementProxyContext](
        name="mcp-privilege-profiler-enforcement-proxy",
        version="0.0.0",
        instructions="Reviewed, audited, bounded, deny-by-default MCP enforcement boundary.",
        lifespan=lifespan,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


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
        properties = tools_by_name[rule.identity.tool_name].input_schema.get("properties")
        for constraint in rule.constraints:
            if not isinstance(properties, dict) or constraint.argument not in properties:
                raise RuntimeError("MCP_PRIVPROF_POLICY_CONSTRAINT_TARGET_INVALID")
    catalog.tools = observed.tools
    catalog.valid = True


async def _deny_with_audit(
    *,
    audit_sink: AuditSink,
    catalog: EnforcementCatalog,
    identity: EnforcementIdentity,
    policy: Policy,
    rule: PolicyRule | None,
    name: str,
    trace_id: str,
    timestamp: datetime,
    facts: ArgumentFacts | None,
    reason_code: str,
    drift_severity: DriftSeverityValue = "none",
    limit_type: LimitType = LimitType.NONE,
    error_details: dict[str, object] | None = None,
) -> types.CallToolResult:
    effect = rule.effect if rule is not None else PolicyEffect.DENY
    event = build_audit_event(
        event_type="policy_decision",
        timestamp=timestamp,
        trace_id=trace_id,
        identity=identity,
        task_type=policy.task_type,
        server_id=policy.server_id,
        tool_name=name,
        tool_fingerprint=_tool_fingerprint(catalog, name),
        policy_id=policy.policy_id,
        rule=rule,
        effect=effect,
        decision="denied",
        reason_code=reason_code,
        facts=facts,
        drift_severity=drift_severity,
        limit_type=limit_type,
    )
    try:
        await audit_sink.append(event)
    except Exception:
        catalog.audit_valid = False
        return _enforcement_error("MCP_PRIVPROF_AUDIT_WRITE_FAILED")
    return _enforcement_error(reason_code, details=error_details)


async def _approval_with_audit(
    *,
    audit_sink: AuditSink,
    catalog: EnforcementCatalog,
    identity: EnforcementIdentity,
    policy: Policy,
    rule: PolicyRule,
    name: str,
    trace_id: str,
    timestamp: datetime,
    facts: ArgumentFacts,
    permit_check: PermitCheck,
) -> types.CallToolResult:
    pending = permit_check.pending
    decision = "approval_required" if pending is not None else "denied"
    event = build_audit_event(
        event_type="policy_decision",
        timestamp=timestamp,
        trace_id=trace_id,
        identity=identity,
        task_type=policy.task_type,
        server_id=policy.server_id,
        tool_name=name,
        tool_fingerprint=_tool_fingerprint(catalog, name),
        policy_id=policy.policy_id,
        rule=rule,
        effect=PolicyEffect.REQUIRE_APPROVAL,
        decision=decision,
        reason_code=permit_check.reason_code,
        facts=facts,
        permit_id=permit_check.permit_id,
    )
    try:
        await audit_sink.append(event)
    except Exception:
        catalog.audit_valid = False
        return _enforcement_error("MCP_PRIVPROF_AUDIT_WRITE_FAILED")
    details: dict[str, object] = {}
    if pending is not None:
        details = {
            "request_id": pending.request_id,
            "argument_digest": pending.argument_digest,
            "expires_at": pending.expires_at.isoformat().replace("+00:00", "Z"),
        }
    if permit_check.permit_id is not None:
        details["permit_id"] = permit_check.permit_id
    return _enforcement_error(permit_check.reason_code, details=details)


def _argument_facts(
    arguments: dict[str, object],
    rule: PolicyRule | None,
) -> ArgumentFacts | None:
    try:
        return argument_facts(arguments, rule.constraints if rule is not None else ())
    except Exception:
        return None


def _tool_fingerprint(catalog: EnforcementCatalog, name: str) -> str | None:
    tool = next((item for item in catalog.tools if item.name == name), None)
    return snapshot_tool(tool).fingerprint if tool is not None else None


def _completion_reason(result: types.CallToolResult) -> str:
    if result.is_error:
        if (
            len(result.content) == 1
            and isinstance(result.content[0], types.TextContent)
            and result.content[0].text.startswith("MCP_PRIVPROF_DOWNSTREAM_")
        ):
            return result.content[0].text
        return "MCP_PRIVPROF_TOOL_ERROR"
    return "MCP_PRIVPROF_TOOL_SUCCESS"


def _enforcement_error(
    reason_code: str,
    *,
    details: Mapping[str, object] | None = None,
) -> types.CallToolResult:
    structured: dict[str, object] = {"reason_code": reason_code}
    if details is not None:
        structured.update({key: value for key, value in details.items() if value is not None})
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=reason_code)],
        structured_content=structured,
        is_error=True,
    )


def _enforcement_mcp_error(
    reason_code: str,
    *,
    code: int = types.INTERNAL_ERROR,
) -> MCPError:
    return MCPError(
        code=code,
        message=reason_code,
        data={"reason_code": reason_code},
    )


async def run_enforcement_proxy(
    process: DownstreamProcess,
    policy: Policy,
    path_roots: Mapping[str, Path],
    *,
    identity: EnforcementIdentity,
    audit_sink: AuditSink,
    limits: LimitCoordinator,
    permits: PermitService,
    approval_control_path: Path | None,
    approval_control_secret: bytes | None,
) -> None:
    """Serve one mandatory-audit enforcement boundary over stdio."""
    proxy = create_enforcement_proxy(
        process,
        policy,
        path_roots,
        identity=identity,
        audit_sink=audit_sink,
        limits=limits,
        permits=permits,
        approval_control_path=approval_control_path,
        approval_control_secret=approval_control_secret,
    )
    async with stdio_server() as (read_stream, write_stream):
        await proxy.run(
            read_stream,
            write_stream,
            proxy.create_initialization_options(),
        )
