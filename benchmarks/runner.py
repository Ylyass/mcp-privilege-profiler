"""Run the deterministic Stage 10 security and performance benchmark."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import math
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, TextIO, cast

import anyio
import mcp.types as types
from jsonschema import Draft202012Validator, FormatChecker
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_privprof.adapters.audit import JsonlAuditSink
from mcp_privprof.adapters.mcp.inventory import CollectedCatalog, collect_catalog, snapshot_toolset
from mcp_privprof.adapters.sqlite import SqliteEnforcementRepository, SqlitePermitRepository
from mcp_privprof.application.audit import (
    EnforcementIdentity,
    argument_facts,
    build_audit_event,
)
from mcp_privprof.application.constraints import evaluate_constraints
from mcp_privprof.application.fingerprints import fingerprint_json
from mcp_privprof.application.limits import LimitCoordinator
from mcp_privprof.application.permits import PermitService
from mcp_privprof.application.policies import policy_contract, render_policy_json
from mcp_privprof.domain import (
    ApprovalPermit,
    EnumConstraint,
    LimitType,
    MaxUtf8BytesConstraint,
    PathConstraint,
    Policy,
    PolicyEffect,
    PolicyRule,
    ToolIdentity,
    ToolLimits,
    compare_toolsets,
)
from wazuh.verify import EXPECTED_VERSION, load_detection_pack, validate_static_pack

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, object]


class JsonValidator(Protocol):
    """Minimal validation interface without unknown third-party types."""

    def validate(self, instance: object) -> None:
        """Raise when a result violates the public schema."""


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "benchmarks" / "scenarios-v1.json"
RESULT_SCHEMA = ROOT / "schemas" / "benchmark-result-v1.schema.json"
RUNNER_VERSION = "1.0.0"
MINIMUM_COUNTS = {
    "legitimate": 30,
    "malicious": 30,
    "drift": 10,
    "overuse": 5,
}
NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
PERMIT_SECRET = bytes.fromhex("42" * 32)


@dataclass(frozen=True, slots=True)
class CallScenario:
    """One expanded deterministic MCP call without persisted arguments."""

    case_id: str
    category: str
    tool_name: str
    arguments: dict[str, object]
    expected_decision: str


@dataclass(frozen=True, slots=True)
class DirectRun:
    """Live catalog plus direct-server timing samples."""

    catalog: CollectedCatalog
    startup_inventory_ms: float
    call_durations_ns: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class EnforcedRun:
    """Observed proxy decisions and timing samples."""

    exposed_tools: int
    cases: tuple[JsonObject, ...]
    call_durations_ns: tuple[int, ...]


def load_manifest(path: Path = DEFAULT_MANIFEST) -> JsonObject:
    """Load and strictly validate the small benchmark scenario manifest."""
    document = _load_json_object(path)
    if _required_str(document, "schema_version") != "1.0":
        raise ValueError("benchmark manifest schema_version must be 1.0")
    _required_str(document, "suite_id")
    legitimate = _expand_call_groups(document, "legitimate_call_groups", "legitimate")
    malicious = _expand_call_groups(document, "malicious_call_groups", "malicious")
    drift = _required_object_list(document, "drift_cases")
    overuse = _required_object_list(document, "overuse_cases")
    counts = {
        "legitimate": len(legitimate),
        "malicious": len(malicious),
        "drift": len(drift),
        "overuse": len(overuse),
    }
    for category, minimum in MINIMUM_COUNTS.items():
        if counts[category] < minimum:
            raise ValueError(
                f"benchmark requires at least {minimum} {category} cases; "
                f"manifest has {counts[category]}"
            )
    case_ids = [
        *(scenario.case_id for scenario in legitimate),
        *(scenario.case_id for scenario in malicious),
        *(_required_str(item, "case_id") for item in drift),
        *(_required_str(item, "case_id") for item in overuse),
    ]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("benchmark case IDs must be unique")
    return document


def expanded_calls(manifest: JsonObject) -> tuple[CallScenario, ...]:
    """Return all labeled legitimate and malicious calls in stable order."""
    return (
        *_expand_call_groups(manifest, "legitimate_call_groups", "legitimate"),
        *_expand_call_groups(manifest, "malicious_call_groups", "malicious"),
    )


def percentile_timings(samples_ns: Sequence[int]) -> JsonObject:
    """Return nearest-rank p50/p95/p99 milliseconds for finite samples."""
    if not samples_ns:
        raise ValueError("timing samples must not be empty")
    ordered = sorted(samples_ns)

    def nearest_rank(percentile: float) -> float:
        index = max(0, math.ceil(percentile * len(ordered)) - 1)
        return round(ordered[index] / 1_000_000, 6)

    return {
        "samples": len(ordered),
        "p50_ms": nearest_rank(0.50),
        "p95_ms": nearest_rank(0.95),
        "p99_ms": nearest_rank(0.99),
    }


async def run_benchmark(manifest: JsonObject, work_root: Path) -> JsonObject:
    """Execute every benchmark layer and return one schema-valid result."""
    calls = expanded_calls(manifest)
    legitimate = tuple(item for item in calls if item.category == "legitimate")
    malicious = tuple(item for item in calls if item.category == "malicious")
    direct = await _run_direct_server(legitimate)
    policy = _benchmark_policy(direct.catalog)
    enforced = await _run_enforced_proxy(
        policy=policy,
        scenarios=calls,
        work_root=work_root,
    )
    drift_cases = run_drift_cases(manifest, direct.catalog)
    overuse_cases = await run_overuse_cases(manifest, work_root)
    policy_timings = _policy_timings(policy, calls)
    audit_timings = await _audit_timings(policy, work_root)
    wazuh = _validate_wazuh_fixtures()

    proxy_legitimate_durations = enforced.call_durations_ns[: len(legitimate)]
    if len(proxy_legitimate_durations) != len(direct.call_durations_ns):
        raise AssertionError("direct and enforced timing sample counts differ")
    overhead = tuple(
        enforced_ns - direct_ns
        for enforced_ns, direct_ns in zip(
            proxy_legitimate_durations,
            direct.call_durations_ns,
            strict=True,
        )
    )
    call_cases = enforced.cases
    all_cases = (*call_cases, *drift_cases, *overuse_cases)
    counts = {
        "legitimate": len(legitimate),
        "malicious": len(malicious),
        "drift": len(drift_cases),
        "overuse": len(overuse_cases),
    }
    legitimate_cases = tuple(item for item in call_cases if item["category"] == "legitimate")
    malicious_cases = tuple(item for item in call_cases if item["category"] == "malicious")
    true_positives = sum(1 for item in malicious_cases if item["observed"] == "denied")
    false_negatives = len(malicious_cases) - true_positives
    false_positives = sum(1 for item in legitimate_cases if item["observed"] != "allowed")
    true_negatives = len(legitimate_cases) - false_positives
    available = len(direct.catalog.tools)
    exposed = enforced.exposed_tools
    security: JsonObject = {
        "available_tools": available,
        "exposed_tools": exposed,
        "catalog_reduction_rate": _rate(available - exposed, available),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "precision": _rate(true_positives, true_positives + false_positives),
        "recall": _rate(true_positives, true_positives + false_negatives),
        "true_positive_rate": _rate(true_positives, len(malicious_cases)),
        "false_positive_rate": _rate(false_positives, len(legitimate_cases)),
        "drift_detection_rate": _rate(
            sum(1 for item in drift_cases if item["passed"] is True),
            len(drift_cases),
        ),
        "overuse_rejection_rate": _rate(
            sum(1 for item in overuse_cases if item["passed"] is True),
            len(overuse_cases),
        ),
    }
    _, suite_fingerprint = fingerprint_json(cast(JsonValue, manifest))
    commit, dirty = _source_revision()
    result: JsonObject = {
        "benchmark_schema_version": "1.0",
        "runner_version": RUNNER_VERSION,
        "suite_id": _required_str(manifest, "suite_id"),
        "suite_fingerprint": suite_fingerprint,
        "generated_at": _timestamp(datetime.now(UTC)),
        "source_revision": {
            "commit": commit,
            "dirty": dirty,
        },
        "environment": {
            "operating_system": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor() or "unreported",
            "logical_cpus": os.cpu_count() or 1,
            "python": platform.python_version(),
            "mcp_sdk": importlib.metadata.version("mcp"),
            "wazuh_fixture_version": EXPECTED_VERSION.removeprefix("v"),
            "clock": "time.perf_counter_ns",
        },
        "scenario_counts": counts,
        "security": security,
        "performance": {
            "policy_decision": percentile_timings(policy_timings),
            "direct_tool_call": percentile_timings(direct.call_durations_ns),
            "enforced_tool_call": percentile_timings(proxy_legitimate_durations),
            "proxy_overhead": percentile_timings(overhead),
            "startup_inventory_ms": round(direct.startup_inventory_ms, 6),
            "audit_append": percentile_timings(audit_timings),
        },
        "wazuh": wazuh,
        "cases": list(all_cases),
        "limitations": [
            "The deterministic lab uses harmless simulated tools, not production SaaS systems.",
            (
                "The call labels measure policy behavior; they do not prove resistance "
                "to every prompt injection."
            ),
            (
                "Performance values describe this machine and run only, and include "
                "local filesystem effects."
            ),
            (
                "This run validates Wazuh fixtures statically; Stage 9 separately records "
                "real Wazuh 4.14.6 logtest and live-ingest evidence."
            ),
        ],
    }
    validate_result(result)
    if not all(item["passed"] is True for item in all_cases):
        raise AssertionError("one or more benchmark cases failed")
    return result


async def _run_direct_server(scenarios: tuple[CallScenario, ...]) -> DirectRun:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "lab.server"],
        cwd=ROOT,
        env=_quiet_subprocess_environment(),
    )
    started = time.perf_counter_ns()
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errlog:
        captured_errlog = cast(TextIO, errlog)
        try:
            async with (
                stdio_client(parameters, errlog=captured_errlog) as streams,
                ClientSession(*streams) as session,
            ):
                await session.initialize()
                catalog = await collect_catalog(session, "benchmark-lab")
                startup_inventory_ms = (time.perf_counter_ns() - started) / 1_000_000
                durations: list[int] = []
                for scenario in scenarios:
                    call_started = time.perf_counter_ns()
                    result = await session.call_tool(scenario.tool_name, scenario.arguments)
                    durations.append(time.perf_counter_ns() - call_started)
                    if result.is_error is True:
                        raise AssertionError(f"direct legitimate call failed: {scenario.case_id}")
        except Exception as exc:
            raise RuntimeError(
                f"direct MCP benchmark failed; bounded stderr:\n{_stderr_tail(captured_errlog)}"
            ) from exc
    return DirectRun(
        catalog=catalog,
        startup_inventory_ms=startup_inventory_ms,
        call_durations_ns=tuple(durations),
    )


async def _run_enforced_proxy(
    *,
    policy: Policy,
    scenarios: tuple[CallScenario, ...],
    work_root: Path,
) -> EnforcedRun:
    cli = shutil.which("mcp-privprof")
    if cli is None:
        candidate = ROOT / ".venv" / "Scripts" / "mcp-privprof.exe"
        if not candidate.is_file():
            raise RuntimeError("mcp-privprof CLI is not installed in the active environment")
        cli = str(candidate)
    policy_file = work_root / "policy.json"
    policy_file.write_bytes(render_policy_json(policy_contract(policy)))
    audit_file = work_root / "events.jsonl"
    state_database = work_root / "state.sqlite3"
    approval_control = work_root / "approval-control.json"
    parameters = StdioServerParameters(
        command=cli,
        args=[
            "enforce",
            "--policy",
            str(policy_file),
            "--task-id",
            "benchmark-task",
            "--agent-id",
            "benchmark-agent",
            "--audit-log",
            str(audit_file),
            "--state-database",
            str(state_database),
            "--approval-control",
            str(approval_control),
            "--path-root",
            f"FIXTURES={ROOT / 'lab' / 'fixtures'}",
            "--cwd",
            str(ROOT),
            "--",
            sys.executable,
            "-m",
            "lab.server",
        ],
        cwd=ROOT,
        env=_quiet_subprocess_environment(),
    )
    cases: list[JsonObject] = []
    durations: list[int] = []
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errlog:
        captured_errlog = cast(TextIO, errlog)
        try:
            async with (
                stdio_client(parameters, errlog=captured_errlog) as streams,
                ClientSession(*streams) as session,
            ):
                await session.initialize()
                listed = await session.list_tools()
                exposed_tools = len(listed.tools)
                for scenario in scenarios:
                    started = time.perf_counter_ns()
                    result = await session.call_tool(scenario.tool_name, scenario.arguments)
                    durations.append(time.perf_counter_ns() - started)
                    observed = "denied" if result.is_error is True else "allowed"
                    cases.append(
                        {
                            "case_id": scenario.case_id,
                            "category": scenario.category,
                            "passed": observed == scenario.expected_decision,
                            "observed": observed,
                        }
                    )
        except Exception as exc:
            raise RuntimeError(
                f"enforced MCP benchmark failed; bounded stderr:\n{_stderr_tail(captured_errlog)}"
            ) from exc
    if approval_control.exists():
        raise AssertionError("approval-control capability remained after proxy shutdown")
    return EnforcedRun(
        exposed_tools=exposed_tools,
        cases=tuple(cases),
        call_durations_ns=tuple(durations),
    )


def _benchmark_policy(catalog: CollectedCatalog) -> Policy:
    effects = {
        "list_fixture_directory": PolicyEffect.ALLOW,
        "read_fixture": PolicyEffect.ALLOW,
        "fetch_fixture_advisory": PolicyEffect.ALLOW,
        "write_sandbox_patch": PolicyEffect.REQUIRE_APPROVAL,
        "simulated_credential_read": PolicyEffect.DENY,
        "simulated_command_run": PolicyEffect.DENY,
        "simulated_external_post": PolicyEffect.DENY,
    }
    if set(effects) != {tool.name for tool in catalog.tools}:
        raise AssertionError("benchmark policy does not exactly cover the live lab catalog")
    rules: list[PolicyRule] = []
    for tool in catalog.tools:
        effect = effects[tool.name]
        constraints = ()
        if tool.name == "read_fixture":
            constraints = (PathConstraint("relative_path", ("FIXTURES",)),)
        elif tool.name == "fetch_fixture_advisory":
            constraints = (
                EnumConstraint(
                    "advisory_id",
                    ("LAB-2026-0001", "LAB-2026-0002"),
                ),
            )
        elif tool.name == "write_sandbox_patch":
            constraints = (MaxUtf8BytesConstraint("content", 100_000),)
        rules.append(
            PolicyRule(
                identity=ToolIdentity("benchmark-lab", tool.name),
                effect=effect,
                constraints=constraints,
                limits=None if effect is PolicyEffect.DENY else ToolLimits(1_000_000, 1_000_000, 4),
                primary_risk_category=_risk_category(tool.name),
                capability_tags=("benchmark_fixture",),
            )
        )
    return Policy(
        policy_id="benchmark-policy-v1",
        task_type="dependency-review",
        server_id="benchmark-lab",
        approved_toolset_fingerprint=catalog.snapshot.fingerprint,
        reviewed_profile_id="benchmark-reviewed-profile-v1",
        rules=tuple(rules),
    )


def _policy_timings(policy: Policy, scenarios: tuple[CallScenario, ...]) -> tuple[int, ...]:
    roots = {"FIXTURES": (ROOT / "lab" / "fixtures").resolve()}
    rules = {rule.identity.tool_name: rule for rule in policy.rules}
    timings: list[int] = []
    for index in range(10_000):
        scenario = scenarios[index % len(scenarios)]
        started = time.perf_counter_ns()
        decision = policy.decide(ToolIdentity(policy.server_id, scenario.tool_name))
        rule = rules.get(scenario.tool_name)
        if decision.effect is not PolicyEffect.DENY and rule is not None:
            evaluate_constraints(rule.constraints, scenario.arguments, roots)
        timings.append(time.perf_counter_ns() - started)
    return tuple(timings)


async def _audit_timings(policy: Policy, work_root: Path) -> tuple[int, ...]:
    rule = next(item for item in policy.rules if item.identity.tool_name == "read_fixture")
    arguments: dict[str, object] = {"relative_path": "project/README.md"}
    facts = argument_facts(arguments, rule.constraints)
    event = build_audit_event(
        event_type="policy_decision",
        timestamp=NOW,
        trace_id="trace-benchmark-audit",
        identity=EnforcementIdentity("benchmark-audit-task", "benchmark-agent"),
        task_type=policy.task_type,
        server_id=policy.server_id,
        tool_name=rule.identity.tool_name,
        tool_fingerprint=None,
        policy_id=policy.policy_id,
        rule=rule,
        effect=rule.effect,
        decision="allowed",
        reason_code="MCP_PRIVPROF_POLICY_ALLOW",
        facts=facts,
    )
    sink = JsonlAuditSink(work_root / "audit-performance.jsonl")
    await sink.initialize()
    timings: list[int] = []
    for _ in range(30):
        started = time.perf_counter_ns()
        await sink.append(event)
        timings.append(time.perf_counter_ns() - started)
    return tuple(timings)


def run_drift_cases(
    manifest: JsonObject,
    baseline: CollectedCatalog,
) -> tuple[JsonObject, ...]:
    results: list[JsonObject] = []
    for item in _required_object_list(manifest, "drift_cases"):
        case_id = _required_str(item, "case_id")
        operation = _required_str(item, "operation")
        target = _required_str(item, "target")
        mutated = _mutate_catalog(baseline.tools, operation=operation, target=target)
        current = snapshot_toolset(baseline.snapshot.server_id, list(mutated))
        report = compare_toolsets(baseline.snapshot, current)
        detected = (
            current.fingerprint != baseline.snapshot.fingerprint
            and report.changed
            and report.maximum_severity is not None
        )
        observed = (
            report.maximum_severity.name.lower()
            if report.maximum_severity is not None
            else "unchanged"
        )
        results.append(
            {
                "case_id": case_id,
                "category": "drift",
                "passed": detected,
                "observed": observed,
            }
        )
    return tuple(results)


def _mutate_catalog(
    baseline: tuple[types.Tool, ...],
    *,
    operation: str,
    target: str,
) -> tuple[types.Tool, ...]:
    tools = list(baseline)
    if operation == "add":
        tools.append(
            types.Tool(
                name=target,
                description="Deterministic added benchmark tool.",
                input_schema={"type": "object", "properties": {}},
            )
        )
        return tuple(tools)
    index = next((number for number, tool in enumerate(tools) if tool.name == target), None)
    if index is None:
        raise ValueError(f"drift target is absent from baseline catalog: {target}")
    if operation == "remove":
        tools.pop(index)
        return tuple(tools)
    document = tools[index].model_dump(mode="json", by_alias=True, exclude_none=True)
    if operation == "description":
        document["description"] = "Deterministic changed benchmark description."
    elif operation == "title":
        document["title"] = "Changed benchmark title"
    elif operation == "input_schema":
        raw_schema = document.get("inputSchema")
        if not isinstance(raw_schema, dict):
            raise TypeError("benchmark tool inputSchema must be an object")
        schema = cast(dict[str, object], json.loads(json.dumps(raw_schema)))
        raw_properties = schema.setdefault("properties", {})
        if not isinstance(raw_properties, dict):
            raise TypeError("benchmark tool inputSchema properties must be an object")
        properties = cast(dict[str, object], raw_properties)
        properties["benchmark_added"] = {"type": "string"}
        document["inputSchema"] = schema
    else:
        raise ValueError(f"unknown drift operation: {operation}")
    tools[index] = types.Tool.model_validate(document)
    return tuple(tools)


async def run_overuse_cases(
    manifest: JsonObject,
    work_root: Path,
) -> tuple[JsonObject, ...]:
    expected = {
        "task_budget": await _task_budget_case(work_root / "task-budget.sqlite3"),
        "rate_window": await _rate_window_case(work_root / "rate-window.sqlite3"),
        "concurrency": await _concurrency_case(work_root / "concurrency.sqlite3"),
        "permit_replay": await _permit_replay_case(work_root / "permit-replay.sqlite3"),
        "permit_argument_mismatch": await _permit_mismatch_case(
            work_root / "permit-mismatch.sqlite3"
        ),
    }
    results: list[JsonObject] = []
    for item in _required_object_list(manifest, "overuse_cases"):
        case_id = _required_str(item, "case_id")
        kind = _required_str(item, "kind")
        try:
            passed, observed = expected[kind]
        except KeyError as exc:
            raise ValueError(f"unknown overuse kind: {kind}") from exc
        results.append(
            {
                "case_id": case_id,
                "category": "overuse",
                "passed": passed,
                "observed": observed,
            }
        )
    return tuple(results)


async def _coordinator(path: Path) -> LimitCoordinator:
    coordinator = LimitCoordinator(SqliteEnforcementRepository(path))
    await coordinator.initialize()
    return coordinator


async def _task_budget_case(path: Path) -> tuple[bool, str]:
    coordinator = await _coordinator(path)
    limits = ToolLimits(10, 1, 2)
    first = await coordinator.reserve(
        task_id="benchmark-task-budget",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    if first.lease is None:
        return False, "first_reservation_denied"
    await coordinator.finish(first.lease, forwarded=True)
    denied = await coordinator.reserve(
        task_id="benchmark-task-budget",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW + timedelta(seconds=1),
    )
    return denied.limit_type is LimitType.CALLS_PER_TASK, denied.limit_type.value


async def _rate_window_case(path: Path) -> tuple[bool, str]:
    coordinator = await _coordinator(path)
    limits = ToolLimits(1, 10, 2)
    first = await coordinator.reserve(
        task_id="benchmark-rate",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    if first.lease is None:
        return False, "first_reservation_denied"
    await coordinator.finish(first.lease, forwarded=True)
    denied = await coordinator.reserve(
        task_id="benchmark-rate",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW + timedelta(seconds=1),
    )
    return denied.limit_type is LimitType.CALLS_PER_MINUTE, denied.limit_type.value


async def _concurrency_case(path: Path) -> tuple[bool, str]:
    coordinator = await _coordinator(path)
    limits = ToolLimits(10, 10, 1)
    first = await coordinator.reserve(
        task_id="benchmark-concurrency",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    if first.lease is None:
        return False, "first_reservation_denied"
    denied = await coordinator.reserve(
        task_id="benchmark-concurrency",
        policy_id="benchmark-policy",
        tool_name="read_fixture",
        limits=limits,
        now=NOW,
    )
    await coordinator.finish(first.lease, forwarded=False)
    return denied.limit_type is LimitType.CONCURRENT_CALLS, denied.limit_type.value


async def _permit_service(path: Path) -> PermitService:
    service = PermitService(
        SqlitePermitRepository(path),
        secret=PERMIT_SECRET,
        ttl=timedelta(minutes=5),
    )
    await service.initialize()
    return service


async def _approved_permit(
    service: PermitService,
    arguments: dict[str, object],
) -> tuple[ApprovalPermit, str]:
    requested = await service.authorize_or_request(
        task_id="benchmark-permit-task",
        policy_id="benchmark-policy",
        server_id="benchmark-lab",
        tool_name="simulated_command_run",
        arguments=arguments,
        now=NOW,
    )
    if requested.pending is None:
        raise AssertionError("permit benchmark produced no pending request")
    permit = await service.approve(
        requested.pending.request_id,
        now=NOW + timedelta(seconds=1),
    )
    return permit, requested.pending.argument_digest


async def _permit_replay_case(path: Path) -> tuple[bool, str]:
    service = await _permit_service(path)
    permit, digest = await _approved_permit(service, {"command": "PUBLIC_FIXTURE"})
    first = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=NOW + timedelta(seconds=2),
    )
    replay = await service.consume_exact(
        permit,
        argument_digest=digest,
        now=NOW + timedelta(seconds=3),
    )
    passed = first.allowed and replay.reason_code == "MCP_PRIVPROF_PERMIT_REPLAY"
    return passed, replay.reason_code


async def _permit_mismatch_case(path: Path) -> tuple[bool, str]:
    service = await _permit_service(path)
    permit, _ = await _approved_permit(service, {"command": "PUBLIC_FIXTURE"})
    mismatch = await service.consume_exact(
        permit,
        argument_digest=f"sha256:{'f' * 64}",
        now=NOW + timedelta(seconds=2),
    )
    return (
        mismatch.reason_code == "MCP_PRIVPROF_PERMIT_ARGUMENT_MISMATCH",
        mismatch.reason_code,
    )


def _validate_wazuh_fixtures() -> JsonObject:
    pack = load_detection_pack()
    validate_static_pack(pack)
    positive = sum(1 for item in pack.cases if item.kind == "positive")
    near_miss = sum(1 for item in pack.cases if item.kind == "near_miss")
    return {
        "validation_mode": "static_contract",
        "fixture_cases": len(pack.cases),
        "positive_cases": positive,
        "near_miss_cases": near_miss,
        "static_fixture_precision": 1.0,
        "live_engine_revalidation_performed": False,
    }


def render_report(result: Mapping[str, object]) -> str:
    """Render a concise evidence report without broad product claims."""
    security = _mapping(result, "security")
    performance = _mapping(result, "performance")
    counts = _mapping(result, "scenario_counts")
    wazuh = _mapping(result, "wazuh")
    source = _mapping(result, "source_revision")
    lines = [
        "# Deterministic benchmark report",
        "",
        f"- Generated: `{result['generated_at']}`",
        f"- Runner: `{result['runner_version']}`",
        f"- Suite: `{result['suite_id']}`",
        f"- Source commit: `{source['commit']}`",
        f"- Working tree dirty at start: `{str(source['dirty']).lower()}`",
        "",
        "## Result",
        "",
        "All labeled deterministic cases passed.",
        "",
        "| Category | Cases |",
        "|---|---:|",
        f"| Legitimate calls | {counts['legitimate']} |",
        f"| Forbidden calls | {counts['malicious']} |",
        f"| Catalog drift | {counts['drift']} |",
        f"| Overuse and approval abuse | {counts['overuse']} |",
        "",
        "## Security behavior",
        "",
        f"- Catalog exposed {security['exposed_tools']} of {security['available_tools']} tools "
        f"({cast(float, security['catalog_reduction_rate']) * 100:.2f}% reduction).",
        f"- Forbidden-call true-positive rate: "
        f"{cast(float, security['true_positive_rate']) * 100:.2f}%.",
        f"- Legitimate-call false-positive rate: "
        f"{cast(float, security['false_positive_rate']) * 100:.2f}%.",
        f"- Drift detection rate: {cast(float, security['drift_detection_rate']) * 100:.2f}%.",
        f"- Overuse/approval-abuse rejection rate: "
        f"{cast(float, security['overuse_rejection_rate']) * 100:.2f}%.",
        "",
        "These are measurements for the published deterministic lab labels, not a claim "
        "that the proxy prevents every prompt injection or guarantees least privilege.",
        "",
        "## Performance",
        "",
        "| Measurement | Samples | p50 ms | p95 ms | p99 ms |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, key in (
        ("Policy decision and constraints", "policy_decision"),
        ("Direct MCP tool call", "direct_tool_call"),
        ("Enforced MCP tool call", "enforced_tool_call"),
        ("Measured proxy delta", "proxy_overhead"),
        ("Mandatory JSONL append plus fsync", "audit_append"),
    ):
        timing = _mapping(performance, key)
        lines.append(
            f"| {label} | {timing['samples']} | {timing['p50_ms']} | "
            f"{timing['p95_ms']} | {timing['p99_ms']} |"
        )
    lines.extend(
        [
            "",
            f"Startup plus complete live inventory: `{performance['startup_inventory_ms']} ms`.",
            "",
            "The proxy delta pairs the same 30 harmless direct and enforced calls. "
            "Small negative samples can occur from operating-system scheduling noise.",
            "",
            "## Wazuh evidence",
            "",
            f"The runner statically revalidated {wazuh['fixture_cases']} contract-valid "
            f"fixtures ({wazuh['positive_cases']} positive and "
            f"{wazuh['near_miss_cases']} near-miss cases). It did not start Docker or rerun "
            "the live Wazuh engine. The Stage 9 record separately documents the pinned "
            "Wazuh 4.14.6 logtest and live proxy-to-alert proof.",
            "",
            "## Reproduce",
            "",
            "From a frozen development environment:",
            "",
            "```powershell",
            "uv run python -m benchmarks.runner "
            "--json-output benchmarks/results/reference-windows.json "
            "--markdown-output benchmarks/results/reference-windows.md",
            "```",
            "",
            "## Limitations",
            "",
        ]
    )
    raw_limitations = result.get("limitations")
    if not isinstance(raw_limitations, list):
        raise TypeError("result limitations must be a list")
    for limitation in cast(list[object], raw_limitations):
        if not isinstance(limitation, str):
            raise TypeError("result limitations must contain strings")
        lines.append(f"- {limitation}")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Run the suite and atomically publish JSON plus Markdown evidence."""
    logging.getLogger("mcp").setLevel(logging.ERROR)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args()
    json_output = cast(Path, args.json_output)
    markdown_output = cast(Path, args.markdown_output)
    if json_output.resolve(strict=False) == markdown_output.resolve(strict=False):
        parser.error("JSON and Markdown outputs must be different files")
    try:
        manifest = load_manifest(cast(Path, args.manifest))
        with tempfile.TemporaryDirectory(prefix="mcp-privprof-benchmark-") as temporary:
            result = anyio.run(run_benchmark, manifest, Path(temporary))
        _atomic_write(
            json_output,
            (json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
        )
        _atomic_write(markdown_output, render_report(result).encode())
    except Exception as exc:
        print(f"Benchmark failed safely ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    raw_cases = result["cases"]
    if not isinstance(raw_cases, list):
        raise TypeError("benchmark cases must be a list")
    print(f"Benchmark passed ({len(cast(list[object], raw_cases))} cases).")
    print(f"JSON: {json_output}")
    print(f"Markdown: {markdown_output}")
    return 0


def _expand_call_groups(
    document: JsonObject,
    key: str,
    category: str,
) -> tuple[CallScenario, ...]:
    scenarios: list[CallScenario] = []
    for group in _required_object_list(document, key):
        group_id = _required_str(group, "group_id")
        repeat = _required_int(group, "repeat")
        if not 1 <= repeat <= 10_000:
            raise ValueError(f"{group_id} repeat must be from 1 to 10000")
        tool_name = _required_str(group, "tool_name")
        expected = _required_str(group, "expected_decision")
        if expected not in {"allowed", "denied"}:
            raise ValueError(f"{group_id} has invalid expected_decision")
        raw_arguments = group.get("arguments")
        if not isinstance(raw_arguments, dict):
            raise TypeError(f"{group_id} arguments must be an object")
        untyped_arguments = cast(dict[object, object], raw_arguments)
        if not all(isinstance(name, str) for name in untyped_arguments):
            raise TypeError(f"{group_id} arguments must be an object")
        arguments = cast(dict[str, object], untyped_arguments)
        for number in range(1, repeat + 1):
            scenarios.append(
                CallScenario(
                    case_id=f"{group_id}-{number:02d}",
                    category=category,
                    tool_name=tool_name,
                    arguments=dict(arguments),
                    expected_decision=expected,
                )
            )
    return tuple(scenarios)


def _required_object_list(document: JsonObject, key: str) -> tuple[JsonObject, ...]:
    raw = document.get(key)
    if not isinstance(raw, list):
        raise TypeError(f"{key} must be a list")
    items: list[JsonObject] = []
    for value in cast(list[object], raw):
        if not isinstance(value, dict):
            raise TypeError(f"{key} must contain objects")
        untyped_value = cast(dict[object, object], value)
        if not all(isinstance(name, str) for name in untyped_value):
            raise TypeError(f"{key} must contain objects")
        items.append(cast(JsonObject, untyped_value))
    return tuple(items)


def _required_str(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"{key} must be a non-empty string")
    return value


def _required_int(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{key} must be an integer")
    return value


def _mapping(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"{key} must be an object")
    untyped = cast(dict[object, object], value)
    if not all(isinstance(name, str) for name in untyped):
        raise TypeError(f"{key} must be an object")
    return cast(dict[str, object], untyped)


def _load_json_object(path: Path) -> JsonObject:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain one JSON object")
    untyped = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in untyped):
        raise TypeError(f"{path} must contain one JSON object")
    return cast(JsonObject, untyped)


def validate_result(result: JsonObject) -> None:
    schema = _load_json_object(RESULT_SCHEMA)
    validator = cast(
        JsonValidator,
        Draft202012Validator(schema, format_checker=FormatChecker()),
    )
    validator.validate(result)


def _source_revision() -> tuple[str, bool]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout
    return commit, bool(status.strip())


def _risk_category(tool_name: str) -> str:
    if tool_name == "simulated_credential_read":
        return "credential_access"
    if tool_name == "simulated_command_run":
        return "command_execution"
    if tool_name == "simulated_external_post":
        return "network_egress"
    if tool_name == "write_sandbox_patch":
        return "file_write"
    return "read_only"


def _quiet_subprocess_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["FASTMCP_LOG_LEVEL"] = "ERROR"
    return environment


def _stderr_tail(stream: TextIO, maximum: int = 4_000) -> str:
    stream.seek(0)
    content = stream.read()
    return content[-maximum:] if content else "(no stderr output)"


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        temporary.write(content)
        temporary.flush()
    try:
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
